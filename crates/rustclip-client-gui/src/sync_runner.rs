//! Owns the background tokio task that runs `rustclip_client::sync::run`.
//!
//! Start/stop is idempotent and tracked by a JoinHandle behind a mutex.
//! Status changes are emitted as `sync-status` Tauri events so the tray
//! menu and the account window can reflect the current state.

use std::sync::Arc;

use anyhow::{Context, Result};
use rustclip_client::clipboard::{self, ClipboardHandle};
use tauri::{AppHandle, Emitter};
use tokio::{sync::Mutex, task::JoinHandle};
use tracing::{info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum SyncStatus {
    Stopped,
    Running,
    Failed,
}

pub struct SyncRunner {
    handle: Mutex<Option<JoinHandle<()>>>,
    watcher: Mutex<Option<JoinHandle<()>>>,
    status: Mutex<SyncStatus>,
    /// Handle to the clipboard worker thread. Populated in `start()`,
    /// cleared in `stop()`. Tauri commands and the tray menu clone the
    /// handle to push `WriteText` / `WriteImage` / `WriteFileList`
    /// through the same worker that the sync loop uses, so the worker's
    /// echo-suppression hashes update in lockstep — history recopies
    /// don't get re-broadcast as fresh outgoing clips.
    clipboard: std::sync::Mutex<Option<ClipboardHandle>>,
}

impl Default for SyncRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl SyncRunner {
    pub fn new() -> Self {
        Self {
            handle: Mutex::new(None),
            watcher: Mutex::new(None),
            status: Mutex::new(SyncStatus::Stopped),
            clipboard: std::sync::Mutex::new(None),
        }
    }

    pub async fn status(&self) -> SyncStatus {
        *self.status.lock().await
    }

    pub async fn is_running(&self) -> bool {
        matches!(self.status().await, SyncStatus::Running)
    }

    /// Returns a clone of the active clipboard handle, or `None` if sync
    /// isn't currently running. Call sites that want to push to the OS
    /// clipboard (history-recopy command, tray recent-clips menu) use
    /// this to route through the one running `arboard::Clipboard`
    /// instead of spinning up a throwaway instance per call.
    pub fn clipboard(&self) -> Option<ClipboardHandle> {
        self.clipboard.lock().ok()?.as_ref().cloned()
    }

    pub async fn start(self: &Arc<Self>, app: AppHandle) -> Result<()> {
        let mut guard = self.handle.lock().await;
        if guard.is_some() {
            return Ok(());
        }
        let ctx = rustclip_client::gui_api::load_sync_context()
            .context("loading sync context; enroll or login first")?;

        // Spawn the clipboard worker here — once — and keep a clone of
        // the handle on `self` so command handlers can reach it. The
        // original is moved into `run_sync` and dies with the sync task.
        let (event_tx, event_rx) = tokio::sync::mpsc::channel(64);
        let handle = clipboard::spawn_watcher(event_tx).context("spawning clipboard watcher")?;
        info!("clipboard watcher started");
        if let Ok(mut slot) = self.clipboard.lock() {
            *slot = Some(handle.clone());
        }

        let status_cell = Arc::clone(self);
        let emit_app = app.clone();
        let task = tokio::spawn(async move {
            info!("sync task starting");
            status_cell.set_status(&emit_app, SyncStatus::Running).await;
            match rustclip_client::gui_api::run_sync(ctx, handle, event_rx).await {
                Ok(()) => {
                    info!("sync exited cleanly");
                    status_cell.set_status(&emit_app, SyncStatus::Stopped).await;
                }
                Err(e) => {
                    warn!(error = %e, "sync task errored");
                    status_cell.set_status(&emit_app, SyncStatus::Failed).await;
                }
            }
            // Drop the clipboard handle stored on self when sync exits,
            // so `clipboard()` correctly reports "no handle available"
            // and history recopy falls back to its throwaway path.
            if let Ok(mut slot) = status_cell.clipboard.lock() {
                *slot = None;
            }
        });
        *guard = Some(task);
        drop(guard);

        // Side-car that tails the local history DB and fires OS
        // notifications + `history-updated` Tauri events for each new
        // incoming clip. Starts with sync, dies with it.
        let mut watcher = self.watcher.lock().await;
        if watcher.is_none() {
            *watcher = Some(crate::history_watcher::spawn(app.clone()));
        }
        Ok(())
    }

    pub async fn stop(&self, app: &AppHandle) -> Result<()> {
        let mut guard = self.handle.lock().await;
        if let Some(task) = guard.take() {
            task.abort();
        }
        drop(guard);
        let mut watcher = self.watcher.lock().await;
        if let Some(task) = watcher.take() {
            task.abort();
        }
        drop(watcher);
        if let Ok(mut slot) = self.clipboard.lock() {
            *slot = None;
        }
        self.set_status(app, SyncStatus::Stopped).await;
        Ok(())
    }

    async fn set_status(&self, app: &AppHandle, status: SyncStatus) {
        {
            let mut s = self.status.lock().await;
            *s = status;
        }
        let _ = app.emit("sync-status", status);
    }
}
