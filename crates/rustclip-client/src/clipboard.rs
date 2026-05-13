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

/// Which kind of clipboard write hit the OS error path. Used by the
/// GUI to render a more specific toast.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum WriteKind {
    Text,
    Image,
    Files,
}

impl WriteKind {
    pub fn as_str(self) -> &'static str {
        match self {
            WriteKind::Text => "text",
            WriteKind::Image => "image",
            WriteKind::Files => "files",
        }
    }
}

/// Failure to apply an incoming clip to the OS clipboard. The remote
/// device already has the content; the local user just won't see it on
/// paste. The GUI listens for these and surfaces a toast so the user
/// knows their next paste won't have what they expect.
#[derive(Debug, Clone)]
pub struct WriteFailure {
    pub kind: WriteKind,
    pub error: String,
}

/// Decoded PNG image bytes plus dimensions for a round-trip write.
#[derive(Debug, Clone)]
pub struct ImageBytes {
    pub width: usize,
    pub height: usize,
    /// Raw RGBA pixels from arboard. PNG-encoding happens at send time.
    pub rgba: Vec<u8>,
}

/// Caller-supplied request to "guard" a text write — re-assert it onto
/// the OS clipboard for `seconds` if the clipboard goes empty before
/// the user pastes. Specifically scoped to the receive path for
/// nested-VDI scenarios; the manual recopy paths (tray menu, hotkey)
/// pass `None`.
#[derive(Debug, Clone, Copy)]
pub struct GuardSpec {
    pub seconds: u32,
    pub max_attempts: u8,
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum ClipboardCmd {
    WriteText {
        text: String,
        guard: Option<GuardSpec>,
    },
    WriteImage(ImageBytes),
    WriteFileList(Vec<PathBuf>),
    Shutdown,
}

/// Active guard state on the worker thread. We re-write `content` if a
/// poll tick within the window finds the OS clipboard empty.
#[derive(Clone)]
struct GuardEntry {
    content: String,
    content_hash: [u8; 32],
    expires_at: Instant,
    attempts_left: u8,
}

/// What the worker should do with the active guard on the current poll
/// tick. Pure decision so it can be unit-tested without touching the
/// real OS clipboard.
#[derive(Debug, PartialEq, Eq)]
enum GuardDecision {
    /// No-op — guard stays armed.
    Keep,
    /// Drop the guard (expired, attempts exhausted, or user copied
    /// something else).
    Drop,
    /// Re-write `content` to the clipboard and decrement
    /// `attempts_left`. The caller also restamps echo-suppression
    /// hashes and skips the rest of the poll tick.
    Reassert,
}

fn evaluate_guard(
    g: &GuardEntry,
    read_result: &std::result::Result<String, arboard::Error>,
    now: Instant,
) -> GuardDecision {
    if now >= g.expires_at {
        return GuardDecision::Drop;
    }
    let cb_empty = match read_result {
        Ok(s) => s.is_empty(),
        Err(arboard::Error::ContentNotAvailable) => true,
        Err(_) => false,
    };
    if cb_empty {
        return if g.attempts_left > 0 {
            GuardDecision::Reassert
        } else {
            GuardDecision::Drop
        };
    }
    if let Ok(text) = read_result {
        if !text.is_empty() {
            let hash = sha256(text.as_bytes());
            if hash != g.content_hash {
                return GuardDecision::Drop;
            }
        }
    }
    GuardDecision::Keep
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
            .send(ClipboardCmd::WriteText { text, guard: None })
            .context("clipboard worker shut down")
    }

    /// Like `write_text` but arms the empty-clipboard guard so the
    /// worker re-asserts the same content for `guard.seconds` if a
    /// third party (VDI clipboard channel etc.) clears the clipboard
    /// before the user pastes.
    pub fn write_text_guarded(&self, text: String, guard: GuardSpec) -> Result<()> {
        self.cmd_tx
            .send(ClipboardCmd::WriteText {
                text,
                guard: Some(guard),
            })
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
    spawn_watcher_inner(event_tx, None)
}

/// Like [`spawn_watcher`] but also feeds each clipboard write failure
/// onto `failure_tx`. The GUI uses this to surface a toast + tray
/// flicker; the CLI never needs to know (warn! is enough), so it stays
/// on the plain entry point.
pub fn spawn_watcher_with_failures(
    event_tx: mpsc::Sender<ClipEvent>,
    failure_tx: mpsc::Sender<WriteFailure>,
) -> Result<ClipboardHandle> {
    spawn_watcher_inner(event_tx, Some(failure_tx))
}

fn spawn_watcher_inner(
    event_tx: mpsc::Sender<ClipEvent>,
    failure_tx: Option<mpsc::Sender<WriteFailure>>,
) -> Result<ClipboardHandle> {
    let (cmd_tx, cmd_rx) = stdmpsc::channel::<ClipboardCmd>();

    // Probe once up-front on the main thread so we can surface a clean error
    // before we've sunk the clipboard into the worker.
    let _probe = Clipboard::new().context("opening system clipboard")?;

    thread::Builder::new()
        .name("rustclip-clipboard".into())
        .spawn(move || worker_loop(event_tx, cmd_rx, failure_tx))
        .context("spawning clipboard worker thread")?;

    Ok(ClipboardHandle { cmd_tx })
}

fn report_failure(failure_tx: &Option<mpsc::Sender<WriteFailure>>, kind: WriteKind, error: &str) {
    if let Some(tx) = failure_tx {
        // blocking_send is fine — we're on the dedicated clipboard
        // thread (no tokio executor running here). A full channel
        // shouldn't happen in practice; if it does, drop silently
        // rather than block forever.
        let _ = tx.try_send(WriteFailure {
            kind,
            error: error.to_string(),
        });
    }
}

/// Total attempts (1 initial + up to N-1 retries) when the OS-level
/// clipboard write hits a transient error. arboard wraps NSPasteboard
/// / CF_HDROP / X11 / Wayland and all of them have occasional
/// glitches — AV scanners, focus changes, a clipboard manager briefly
/// holding the handle — that resolve on the second or third attempt.
const WRITE_MAX_ATTEMPTS: u32 = 3;
/// Sleep between retries. Short enough that even a worst-case retry
/// budget (~100 ms) stays well inside the 500 ms poll interval.
const WRITE_RETRY_DELAY: Duration = Duration::from_millis(50);

fn set_text_with_retry(cb: &mut Clipboard, text: &str) -> std::result::Result<(), arboard::Error> {
    let mut last_err: Option<arboard::Error> = None;
    for attempt in 1..=WRITE_MAX_ATTEMPTS {
        match cb.set_text(text) {
            Ok(()) => return Ok(()),
            Err(e) => {
                debug!(attempt, max = WRITE_MAX_ATTEMPTS, error = %e, "set_text failed, will retry");
                last_err = Some(e);
                if attempt < WRITE_MAX_ATTEMPTS {
                    thread::sleep(WRITE_RETRY_DELAY);
                }
            }
        }
    }
    Err(last_err.expect("attempted at least once"))
}

fn set_image_with_retry(
    cb: &mut Clipboard,
    image: &ImageBytes,
) -> std::result::Result<(), arboard::Error> {
    let mut last_err: Option<arboard::Error> = None;
    for attempt in 1..=WRITE_MAX_ATTEMPTS {
        let img = ImageData {
            width: image.width,
            height: image.height,
            bytes: Cow::Borrowed(&image.rgba),
        };
        match cb.set_image(img) {
            Ok(()) => return Ok(()),
            Err(e) => {
                debug!(attempt, max = WRITE_MAX_ATTEMPTS, error = %e, "set_image failed, will retry");
                last_err = Some(e);
                if attempt < WRITE_MAX_ATTEMPTS {
                    thread::sleep(WRITE_RETRY_DELAY);
                }
            }
        }
    }
    Err(last_err.expect("attempted at least once"))
}

fn write_file_list_with_retry(paths: &[PathBuf]) -> anyhow::Result<()> {
    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 1..=WRITE_MAX_ATTEMPTS {
        match clipboard_files::write_file_list(paths) {
            Ok(()) => return Ok(()),
            Err(e) => {
                debug!(
                    attempt,
                    max = WRITE_MAX_ATTEMPTS,
                    error = %e,
                    "file-list write failed, will retry"
                );
                last_err = Some(e);
                if attempt < WRITE_MAX_ATTEMPTS {
                    thread::sleep(WRITE_RETRY_DELAY);
                }
            }
        }
    }
    Err(last_err.expect("attempted at least once"))
}

fn worker_loop(
    event_tx: mpsc::Sender<ClipEvent>,
    cmd_rx: stdmpsc::Receiver<ClipboardCmd>,
    failure_tx: Option<mpsc::Sender<WriteFailure>>,
) {
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
    let mut guard_text: Option<GuardEntry> = None;

    loop {
        // Drain pending commands first.
        loop {
            match cmd_rx.try_recv() {
                Ok(ClipboardCmd::WriteText { text, guard }) => {
                    // Pre-stamp echo-suppression hashes BEFORE the OS
                    // write so a third-party reader/writer racing the
                    // very next poll can't trip a spurious echo. Roll
                    // back atomically if the OS write actually fails —
                    // otherwise stale hashes would suppress legitimate
                    // user copies of the prior clipboard content.
                    let hash = sha256(text.as_bytes());
                    let prev_last_set = last_set;
                    let prev_last_read = last_read;
                    let prev_guard = guard_text.clone();
                    last_set = Some(hash);
                    last_read = Some(hash);
                    if let Some(spec) = guard {
                        guard_text = Some(GuardEntry {
                            content: text.clone(),
                            content_hash: hash,
                            expires_at: Instant::now() + Duration::from_secs(spec.seconds as u64),
                            attempts_left: spec.max_attempts,
                        });
                    } else {
                        // A non-guarded write (manual recopy etc.)
                        // implicitly cancels any prior guard — the
                        // user is moving on.
                        guard_text = None;
                    }
                    if let Err(e) = set_text_with_retry(&mut cb, &text) {
                        warn!(error = %e, "clipboard write failed after retries");
                        last_set = prev_last_set;
                        last_read = prev_last_read;
                        guard_text = prev_guard;
                        report_failure(&failure_tx, WriteKind::Text, &e.to_string());
                    }
                }
                Ok(ClipboardCmd::WriteImage(image)) => {
                    let hash = hash_image(&image);
                    let prev_last_set = last_set;
                    let prev_last_read = last_read;
                    let prev_image_write_at = last_image_write_at;
                    last_set = Some(hash);
                    last_read = Some(hash);
                    last_image_write_at = Some(Instant::now());
                    if let Err(e) = set_image_with_retry(&mut cb, &image) {
                        warn!(error = %e, "clipboard image write failed after retries");
                        last_set = prev_last_set;
                        last_read = prev_last_read;
                        last_image_write_at = prev_image_write_at;
                        report_failure(&failure_tx, WriteKind::Image, &e.to_string());
                    }
                }
                Ok(ClipboardCmd::WriteFileList(paths)) => {
                    // Bump the echo-suppression hash BEFORE the actual
                    // pasteboard write so the next poll can't sneak in a
                    // read between the write and the hash update. Roll
                    // back the same trio on failure so a stale file-list
                    // hash doesn't outlive the failed attempt — the
                    // previous fix pre-stamped but never restored.
                    let hash = files::hash_path_list(&paths);
                    let prev_last_set_files = last_set_files;
                    let prev_last_read_files = last_read_files;
                    let prev_files_write_at = last_files_write_at;
                    last_set_files = Some(hash);
                    last_read_files = Some(hash);
                    last_files_write_at = Some(Instant::now());
                    if let Err(e) = write_file_list_with_retry(&paths) {
                        warn!(error = %e, "clipboard file-list write failed after retries");
                        last_set_files = prev_last_set_files;
                        last_read_files = prev_last_read_files;
                        last_files_write_at = prev_files_write_at;
                        report_failure(&failure_tx, WriteKind::Files, &e.to_string());
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

        // Poll text second. Read once and reuse the result for guard
        // handling so a transient third-party clipboard clear can't
        // race between the guard's empty-check and the normal poll.
        let read_result = cb.get_text();

        // Guard pass: re-assert our last write if the clipboard has
        // gone empty within the window. Runs BEFORE the normal poll so
        // a re-assert never emits a watcher event (the next tick sees
        // last_set match the re-asserted hash and stays quiet).
        if let Some(g) = guard_text.as_mut() {
            match evaluate_guard(g, &read_result, Instant::now()) {
                GuardDecision::Keep => {}
                GuardDecision::Drop => {
                    guard_text = None;
                }
                GuardDecision::Reassert => {
                    g.attempts_left -= 1;
                    let attempts_left = g.attempts_left;
                    let hash = g.content_hash;
                    let content = g.content.clone();
                    match set_text_with_retry(&mut cb, &content) {
                        Ok(()) => {
                            last_set = Some(hash);
                            last_read = Some(hash);
                            debug!(
                                attempts_left,
                                "clipboard guard re-asserted after empty-clipboard tick"
                            );
                        }
                        Err(e) => {
                            warn!(error = %e, "clipboard guard re-assert failed");
                            guard_text = None;
                            report_failure(&failure_tx, WriteKind::Text, &e.to_string());
                        }
                    }
                    // Don't fall through to the normal text / image
                    // poll for this tick — we just wrote, the next
                    // read would see our own content.
                    thread::sleep(POLL_INTERVAL);
                    continue;
                }
            }
        }

        match read_result {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn guard_with(content: &str, expires_in: Duration, attempts_left: u8) -> GuardEntry {
        GuardEntry {
            content: content.to_string(),
            content_hash: sha256(content.as_bytes()),
            expires_at: Instant::now() + expires_in,
            attempts_left,
        }
    }

    /// Within the window, attempts left, clipboard reads as empty
    /// (`Ok("")`): caller should re-assert. The clearer-as-error case
    /// (`ContentNotAvailable`) is treated as empty too.
    #[test]
    fn guard_re_asserts_when_cleared_to_empty() {
        let g = guard_with("hello", Duration::from_secs(5), 3);
        let now = Instant::now();
        assert_eq!(
            evaluate_guard(&g, &Ok(String::new()), now),
            GuardDecision::Reassert
        );
        assert_eq!(
            evaluate_guard(&g, &Err(arboard::Error::ContentNotAvailable), now),
            GuardDecision::Reassert
        );
    }

    /// User copies something else within the window: drop the guard so
    /// we never fight a real copy. Guard kept alive when the same
    /// content is still on the clipboard (our own write echoing back).
    #[test]
    fn guard_clears_on_user_overwrite() {
        let g = guard_with("hello", Duration::from_secs(5), 3);
        let now = Instant::now();
        assert_eq!(
            evaluate_guard(&g, &Ok("a different copy".into()), now),
            GuardDecision::Drop
        );
        // Same content still present → keep the guard alive.
        assert_eq!(
            evaluate_guard(&g, &Ok("hello".into()), now),
            GuardDecision::Keep
        );
    }

    /// Past the expiry the guard is dropped regardless of clipboard
    /// state — including the empty-with-attempts-left case where it
    /// would otherwise re-assert.
    #[test]
    fn guard_clears_on_window_expiry() {
        let g = guard_with("hello", Duration::from_millis(0), 3);
        let now = Instant::now() + Duration::from_millis(1);
        assert_eq!(
            evaluate_guard(&g, &Ok(String::new()), now),
            GuardDecision::Drop
        );
        assert_eq!(
            evaluate_guard(&g, &Ok("hello".into()), now),
            GuardDecision::Drop
        );
    }

    /// With zero attempts remaining, an empty clipboard tick drops the
    /// guard rather than re-asserting indefinitely.
    #[test]
    fn guard_caps_re_assertions() {
        let g = guard_with("hello", Duration::from_secs(5), 0);
        let now = Instant::now();
        assert_eq!(
            evaluate_guard(&g, &Ok(String::new()), now),
            GuardDecision::Drop
        );
    }

    /// Non-Empty / non-ContentNotAvailable read errors are treated as
    /// "unknown state": don't re-assert and don't drop. We wait for
    /// the next tick rather than fighting a transient read failure.
    #[test]
    fn guard_keeps_on_transient_read_error() {
        let g = guard_with("hello", Duration::from_secs(5), 3);
        let err: std::result::Result<String, arboard::Error> = Err(arboard::Error::Unknown {
            description: "transient".into(),
        });
        assert_eq!(
            evaluate_guard(&g, &err, Instant::now()),
            GuardDecision::Keep
        );
    }
}
