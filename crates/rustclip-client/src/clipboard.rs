//! Dedicated clipboard thread. arboard instances are not `Send` on all
//! platforms, so we keep one pinned to a single OS thread and drive it via
//! channels from the async runtime.

use std::{
    borrow::Cow,
    path::PathBuf,
    sync::mpsc as stdmpsc,
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use arboard::{Clipboard, ImageData};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::{clipboard_files, config::ClientConfig, files};

const POLL_INTERVAL: Duration = Duration::from_millis(500);
/// Time window after writing an image during which we ignore image reads.
/// Platforms can roundtrip RGBA with slight differences (premultiplied
/// alpha, row-stride alignment) so content-hash echo suppression alone is
/// unreliable for images. A small quiet window catches the echo reliably.
const IMAGE_WRITE_QUIET: Duration = Duration::from_secs(3);
/// Time window after writing a file list during which we ignore file-list
/// reads. Longer than the image window because the receive path does a
/// tar unpack + NSURL / HDROP allocation before the pasteboard write; a
/// large bundle can burn past 3 s.
const FILES_WRITE_QUIET: Duration = Duration::from_secs(5);

/// Events emitted by the clipboard watcher when the user copies something.
#[derive(Debug)]
pub enum ClipEvent {
    Text(String),
    Image(ImageBytes),
    Files(Vec<PathBuf>),
}

/// Decoded PNG image bytes plus dimensions for a round-trip write.
#[derive(Debug, Clone)]
pub struct ImageBytes {
    pub width: usize,
    pub height: usize,
    /// Raw RGBA pixels from arboard. PNG-encoding happens at send time.
    pub rgba: Vec<u8>,
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum ClipboardCmd {
    WriteText(String),
    WriteImage(ImageBytes),
    WriteFileList(Vec<PathBuf>),
    Shutdown,
}

/// Sender half of the clipboard worker channel. Cheap to clone —
/// wraps `std::sync::mpsc::Sender` which is itself `Clone`. Cloning
/// lets multiple call sites (the sync loop, the Tauri history-recopy
/// command, the tray recent-clips menu) all drive the single
/// `arboard::Clipboard` that lives on the worker thread.
#[derive(Clone)]
pub struct ClipboardHandle {
    cmd_tx: stdmpsc::Sender<ClipboardCmd>,
}

impl ClipboardHandle {
    pub fn write_text(&self, text: String) -> Result<()> {
        self.cmd_tx
            .send(ClipboardCmd::WriteText(text))
            .context("clipboard worker shut down")
    }

    pub fn write_image(&self, image: ImageBytes) -> Result<()> {
        self.cmd_tx
            .send(ClipboardCmd::WriteImage(image))
            .context("clipboard worker shut down")
    }

    pub fn write_file_list(&self, paths: Vec<PathBuf>) -> Result<()> {
        self.cmd_tx
            .send(ClipboardCmd::WriteFileList(paths))
            .context("clipboard worker shut down")
    }

    #[allow(dead_code)]
    pub fn shutdown(&self) {
        let _ = self.cmd_tx.send(ClipboardCmd::Shutdown);
    }
}

pub fn spawn_watcher(event_tx: mpsc::Sender<ClipEvent>) -> Result<ClipboardHandle> {
    let (cmd_tx, cmd_rx) = stdmpsc::channel::<ClipboardCmd>();

    // Probe once up-front on the main thread so we can surface a clean error
    // before we've sunk the clipboard into the worker.
    let _probe = Clipboard::new().context("opening system clipboard")?;

    thread::Builder::new()
        .name("rustclip-clipboard".into())
        .spawn(move || worker_loop(event_tx, cmd_rx))
        .context("spawning clipboard worker thread")?;

    Ok(ClipboardHandle { cmd_tx })
}

fn worker_loop(event_tx: mpsc::Sender<ClipEvent>, cmd_rx: stdmpsc::Receiver<ClipboardCmd>) {
    let mut cb = match Clipboard::new() {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "clipboard worker cannot open clipboard");
            return;
        }
    };

    let config = ClientConfig::load().unwrap_or_default();

    let mut last_read: Option<[u8; 32]> = None;
    let mut last_set: Option<[u8; 32]> = None;
    let mut last_image_write_at: Option<Instant> = None;
    let mut last_read_files: Option<[u8; 32]> = None;
    let mut last_set_files: Option<[u8; 32]> = None;
    let mut last_files_write_at: Option<Instant> = None;

    loop {
        // Drain pending commands first.
        loop {
            match cmd_rx.try_recv() {
                Ok(ClipboardCmd::WriteText(text)) => {
                    let hash = sha256(text.as_bytes());
                    if let Err(e) = cb.set_text(text) {
                        warn!(error = %e, "clipboard write failed");
                    } else {
                        last_set = Some(hash);
                        last_read = Some(hash);
                    }
                }
                Ok(ClipboardCmd::WriteImage(image)) => {
                    let hash = hash_image(&image);
                    let img = ImageData {
                        width: image.width,
                        height: image.height,
                        bytes: Cow::Owned(image.rgba),
                    };
                    if let Err(e) = cb.set_image(img) {
                        warn!(error = %e, "clipboard image write failed");
                    } else {
                        last_set = Some(hash);
                        last_read = Some(hash);
                        last_image_write_at = Some(Instant::now());
                    }
                }
                Ok(ClipboardCmd::WriteFileList(paths)) => {
                    // Bump the echo-suppression hash BEFORE the actual
                    // pasteboard write so the next poll can't sneak in a
                    // read between the write and the hash update.
                    let hash = files::hash_path_list(&paths);
                    last_set_files = Some(hash);
                    last_read_files = Some(hash);
                    last_files_write_at = Some(Instant::now());
                    if let Err(e) = clipboard_files::write_file_list(&paths) {
                        warn!(error = %e, "clipboard file-list write failed");
                    }
                }
                Ok(ClipboardCmd::Shutdown) | Err(stdmpsc::TryRecvError::Disconnected) => {
                    debug!("clipboard worker exiting");
                    return;
                }
                Err(stdmpsc::TryRecvError::Empty) => break,
            }
        }

        // Poll file list FIRST. Finder / Explorer also push the filename
        // onto the pasteboard as a text fallback; if we polled text first
        // we'd spuriously send the filename as a text clip.
        //
        // `files_on_clipboard` records whether ANY file URL is present
        // this tick (regardless of whether we send it, suppress it as an
        // echo, or ignore it because the list is under our own inbox).
        // The text and image polls below use that flag to skip Finder's
        // auto-derived text/icon fallbacks — those are never a real
        // user-intended clip when files are what was copied.
        let mut files_on_clipboard = false;
        if config.auto_sync_files {
            let in_files_quiet = last_files_write_at
                .map(|t| t.elapsed() < FILES_WRITE_QUIET)
                .unwrap_or(false);
            if !in_files_quiet {
                match clipboard_files::read_file_list() {
                    Ok(Some(paths)) if !paths.is_empty() => {
                        files_on_clipboard = true;
                        if files::all_under_inbox(&paths) {
                            // We just wrote these ourselves (receive-side
                            // unpack). Skip silently; don't even update
                            // last_read_files so the user's own later
                            // manual re-copy still syncs.
                        } else {
                            let hash = files::hash_path_list(&paths);
                            let already_read = last_read_files == Some(hash);
                            let matches_echo = last_set_files == Some(hash);
                            if !already_read && !matches_echo {
                                last_read_files = Some(hash);
                                if event_tx.blocking_send(ClipEvent::Files(paths)).is_err() {
                                    debug!("event receiver dropped, clipboard worker exiting");
                                    return;
                                }
                                thread::sleep(POLL_INTERVAL);
                                continue;
                            } else if !already_read {
                                last_read_files = Some(hash);
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        debug!(error = %e, "clipboard file-list read error");
                    }
                }
            } else {
                // Inside the quiet window we don't call read_file_list
                // (we just wrote it ourselves on the receive path), but
                // file URLs ARE still sitting on the pasteboard — they
                // stay there until the user copies something else. The
                // auto-derived text/icon representations are therefore
                // also still there, so treat this tick as "files
                // present" to gate the text / image polls.
                files_on_clipboard = true;
            }
        }

        if files_on_clipboard {
            // Skip the text and image polls entirely: any text/icon the
            // OS derived from the file URLs is a fallback, not a real
            // clip. Note we DON'T stamp last_read for them either, so a
            // genuine text copy later still registers.
            thread::sleep(POLL_INTERVAL);
            continue;
        }

        // Poll text second.
        match cb.get_text() {
            Ok(text) if !text.is_empty() => {
                let hash = sha256(text.as_bytes());
                let already_read = last_read == Some(hash);
                let matches_echo = last_set == Some(hash);
                if !already_read && !matches_echo {
                    last_read = Some(hash);
                    if event_tx.blocking_send(ClipEvent::Text(text)).is_err() {
                        debug!("event receiver dropped, clipboard worker exiting");
                        return;
                    }
                } else if !already_read {
                    last_read = Some(hash);
                }
                thread::sleep(POLL_INTERVAL);
                continue;
            }
            Ok(_) => {}
            Err(arboard::Error::ContentNotAvailable) => {}
            Err(e) => {
                debug!(error = %e, "clipboard read error");
            }
        }

        // Poll image third.
        let in_quiet_window = last_image_write_at
            .map(|t| t.elapsed() < IMAGE_WRITE_QUIET)
            .unwrap_or(false);
        match cb.get_image() {
            Ok(img) if !in_quiet_window => {
                let image = ImageBytes {
                    width: img.width,
                    height: img.height,
                    rgba: img.bytes.into_owned(),
                };
                let hash = hash_image(&image);
                let already_read = last_read == Some(hash);
                let matches_echo = last_set == Some(hash);
                if !already_read && !matches_echo {
                    last_read = Some(hash);
                    if event_tx.blocking_send(ClipEvent::Image(image)).is_err() {
                        debug!("event receiver dropped, clipboard worker exiting");
                        return;
                    }
                } else if !already_read {
                    last_read = Some(hash);
                }
            }
            Ok(_) => {
                // Inside the post-write quiet window; skip this image read.
            }
            Err(arboard::Error::ContentNotAvailable) => {}
            Err(e) => {
                debug!(error = %e, "clipboard image read error");
            }
        }

        thread::sleep(POLL_INTERVAL);
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn hash_image(image: &ImageBytes) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update((image.width as u64).to_le_bytes());
    hasher.update((image.height as u64).to_le_bytes());
    hasher.update(&image.rgba);
    hasher.finalize().into()
}
