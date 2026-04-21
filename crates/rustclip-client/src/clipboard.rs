//! Dedicated clipboard thread. arboard instances are not `Send` on all
//! platforms, so we keep one pinned to a single OS thread and drive it via
//! channels from the async runtime.

use std::{sync::mpsc as stdmpsc, thread, time::Duration};

use anyhow::{Context, Result};
use arboard::Clipboard;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tracing::{debug, warn};

const POLL_INTERVAL: Duration = Duration::from_millis(500);

#[allow(dead_code)]
#[derive(Debug)]
pub enum ClipboardCmd {
    Write(String),
    Shutdown,
}

pub struct ClipboardHandle {
    cmd_tx: stdmpsc::Sender<ClipboardCmd>,
}

impl ClipboardHandle {
    pub fn write_text(&self, text: String) -> Result<()> {
        self.cmd_tx
            .send(ClipboardCmd::Write(text))
            .context("clipboard worker shut down")
    }

    #[allow(dead_code)]
    pub fn shutdown(&self) {
        let _ = self.cmd_tx.send(ClipboardCmd::Shutdown);
    }
}

pub fn spawn_watcher(event_tx: mpsc::Sender<String>) -> Result<ClipboardHandle> {
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

fn worker_loop(event_tx: mpsc::Sender<String>, cmd_rx: stdmpsc::Receiver<ClipboardCmd>) {
    let mut cb = match Clipboard::new() {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "clipboard worker cannot open clipboard");
            return;
        }
    };

    let mut last_read: Option<[u8; 32]> = None;
    let mut last_set: Option<[u8; 32]> = None;

    loop {
        // Drain pending commands first.
        loop {
            match cmd_rx.try_recv() {
                Ok(ClipboardCmd::Write(text)) => {
                    let hash = sha256(text.as_bytes());
                    if let Err(e) = cb.set_text(text) {
                        warn!(error = %e, "clipboard write failed");
                    } else {
                        last_set = Some(hash);
                        last_read = Some(hash);
                    }
                }
                Ok(ClipboardCmd::Shutdown) | Err(stdmpsc::TryRecvError::Disconnected) => {
                    debug!("clipboard worker exiting");
                    return;
                }
                Err(stdmpsc::TryRecvError::Empty) => break,
            }
        }

        // Poll current text and emit events on change.
        match cb.get_text() {
            Ok(text) if !text.is_empty() => {
                let hash = sha256(text.as_bytes());
                let already_read = last_read == Some(hash);
                let matches_echo = last_set == Some(hash);
                if !already_read && !matches_echo {
                    last_read = Some(hash);
                    if event_tx.blocking_send(text).is_err() {
                        debug!("event receiver dropped, clipboard worker exiting");
                        return;
                    }
                } else if !already_read {
                    last_read = Some(hash);
                }
            }
            Ok(_) => {}
            Err(arboard::Error::ContentNotAvailable) => {}
            Err(e) => {
                debug!(error = %e, "clipboard read error");
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
