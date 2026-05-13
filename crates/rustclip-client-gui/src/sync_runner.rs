//! Owns the background tokio task that runs `rustclip_client::sync::run`.
//!
//! Start/stop is idempotent and tracked by a JoinHandle behind a mutex.
//! Status changes are emitted as `sync-status` Tauri events so the tray
//! menu and the account window can reflect the current state.

use std::sync::Arc;

use anyhow::{Context, Result};
use rustclip_client::clipboard::{
    self, ClipboardHandle, OutgoingSkip, OutgoingSkipReason, WriteFailure,
};
use tauri::{AppHandle, Emitter};
use tauri_plugin_notification::NotificationExt;
use tokio::{sync::Mutex, task::JoinHandle};
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum SyncStatus {
    Stopped,
    Running,
    Failed,
}

pub struct SyncRunner {
    handle: Mutex<Option<JoinHandle<()>>>,
    watcher: Mutex<Option<JoinHandle<()>>>,
    /// Consumes WriteFailure events emitted by the clipboard worker
    /// when an incoming clip can't be applied (the remote got it, but
    /// the local paste won't have what the user expects). Fires a
    /// toast and a transient tray status flicker.
    failure_consumer: Mutex<Option<JoinHandle<()>>>,
    /// Consumes OutgoingSkip notices from the sync loop — events the
    /// watcher detected but sync refused to send (file bundle exceeds
    /// the size cap, unpackable pasteboard junk). Surfaces a toast so
    /// the user understands why their copy didn't appear on the
    /// other device.
    skip_consumer: Mutex<Option<JoinHandle<()>>>,
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
            failure_consumer: Mutex::new(None),
            skip_consumer: Mutex::new(None),
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
        let (failure_tx, failure_rx) = tokio::sync::mpsc::channel::<WriteFailure>(8);
        let handle = clipboard::spawn_watcher_with_failures(event_tx, failure_tx)
            .context("spawning clipboard watcher")?;
        info!("clipboard watcher started");
        if let Ok(mut slot) = self.clipboard.lock() {
            *slot = Some(handle.clone());
        }

        // Side-car that turns each clipboard apply-failure into a
        // user-visible toast + a transient tray status flicker. The
        // remote device already has the content; the local paste
        // won't, so we owe the user an explicit signal.
        let failure_app = app.clone();
        let failure_task = tokio::spawn(consume_write_failures(failure_app, failure_rx));
        let mut fc = self.failure_consumer.lock().await;
        *fc = Some(failure_task);
        drop(fc);

        // Side-car for outgoing skip notices (size-cap rejections,
        // unpackable bundles). Same pattern as the failure consumer
        // above but distinct semantics — these are local-side decisions
        // the user should know about, not remote apply errors.
        let (skip_tx, skip_rx) = tokio::sync::mpsc::channel::<OutgoingSkip>(8);
        let skip_app = app.clone();
        let skip_task = tokio::spawn(consume_outgoing_skips(skip_app, skip_rx));
        let mut sc = self.skip_consumer.lock().await;
        *sc = Some(skip_task);
        drop(sc);

        let status_cell = Arc::clone(self);
        let emit_app = app.clone();
        let task = tokio::spawn(async move {
            info!("sync task starting");
            status_cell.set_status(&emit_app, SyncStatus::Running).await;
            match rustclip_client::gui_api::run_sync_with_skip_tx(ctx, handle, event_rx, skip_tx)
                .await
            {
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
        let mut fc = self.failure_consumer.lock().await;
        if let Some(task) = fc.take() {
            task.abort();
        }
        drop(fc);
        let mut sc = self.skip_consumer.lock().await;
        if let Some(task) = sc.take() {
            task.abort();
        }
        drop(sc);
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

/// Drains [`WriteFailure`] events from the clipboard worker. For each
/// one: emits a `clip-write-failed` Tauri event the frontend can react
/// to, fires an OS toast (gated by the user's `notifications_enabled`
/// preference), and flashes the tray status row. Lives for as long as
/// the watcher; aborted in [`SyncRunner::stop`].
async fn consume_write_failures(app: AppHandle, mut rx: tokio::sync::mpsc::Receiver<WriteFailure>) {
    while let Some(failure) = rx.recv().await {
        let kind_str = failure.kind.as_str();
        debug!(kind = kind_str, error = %failure.error, "clipboard write failure surfacing");

        // Frontend listener (currently unwired; safe to ignore until UI
        // wants to surface it inline somewhere).
        let _ = app.emit(
            "clip-write-failed",
            serde_json::json!({ "kind": kind_str, "error": failure.error }),
        );

        crate::tray::flash_transient_status(&app, format!("Error applying {kind_str} clip"));

        if notifications_enabled() {
            let body = format!(
                "An incoming {kind_str} clip couldn't be placed on the clipboard. \
                See Settings → Diagnostics for logs."
            );
            if let Err(e) = app
                .notification()
                .builder()
                .title("RustClip couldn't paste")
                .body(body)
                .show()
            {
                warn!(error = %e, "showing write-failure notification failed");
            }
        }
    }
    debug!("write-failure consumer exiting (channel closed)");
}

/// Drains [`OutgoingSkip`] notices from the sync loop. Today only
/// `OutgoingSkipReason::TooLarge` and `OutgoingSkipReason::Unpackable`
/// fire, both for file bundles. Surfaces a tray-status flicker plus a
/// dedicated toast so the user understands why their copy didn't
/// appear on the other device.
async fn consume_outgoing_skips(app: AppHandle, mut rx: tokio::sync::mpsc::Receiver<OutgoingSkip>) {
    while let Some(skip) = rx.recv().await {
        let kind_str = skip.kind.as_str();
        debug!(kind = kind_str, reason = ?skip.reason, "outgoing skip surfacing");

        let _ = app.emit(
            "clip-outgoing-skipped",
            serde_json::json!({ "kind": kind_str, "reason": skip_reason_to_json(&skip.reason) }),
        );

        let (transient, title, body) = match &skip.reason {
            OutgoingSkipReason::TooLarge { total_bytes, cap } => {
                let total_mb = (*total_bytes as f64) / (1024.0 * 1024.0);
                let cap_mb = (*cap as f64) / (1024.0 * 1024.0);
                (
                    format!("{kind_str} bundle too large to auto-sync"),
                    "RustClip skipped a copy".to_string(),
                    format!(
                        "Bundle is {total_mb:.0} MB which exceeds the {cap_mb:.0} MB auto-sync cap. \
                        Raise the cap in Settings → Auto-sync, or use the `send-files` CLI."
                    ),
                )
            }
            OutgoingSkipReason::Unpackable { error } => (
                format!("couldn't pack {kind_str} bundle"),
                "RustClip skipped a copy".to_string(),
                format!(
                    "The clipboard reference couldn't be packed (often a stale path). \
                    Try the copy again. Detail: {error}"
                ),
            ),
        };

        crate::tray::flash_transient_status(&app, transient);

        if notifications_enabled() {
            if let Err(e) = app.notification().builder().title(title).body(body).show() {
                warn!(error = %e, "showing outgoing-skip notification failed");
            }
        }
    }
    debug!("outgoing-skip consumer exiting (channel closed)");
}

fn skip_reason_to_json(r: &OutgoingSkipReason) -> serde_json::Value {
    match r {
        OutgoingSkipReason::TooLarge { total_bytes, cap } => {
            serde_json::json!({ "kind": "too_large", "total_bytes": total_bytes, "cap": cap })
        }
        OutgoingSkipReason::Unpackable { error } => {
            serde_json::json!({ "kind": "unpackable", "error": error })
        }
    }
}

/// Reads the per-device config. Fails open (returns true) so a
/// transient disk issue doesn't silently eat the user's signal that
/// something went wrong with paste.
fn notifications_enabled() -> bool {
    match rustclip_client::gui_api::get_client_config() {
        Ok(cfg) => cfg.notifications_enabled,
        Err(e) => {
            debug!(error = %e, "reading client config failed; defaulting to notifications enabled");
            true
        }
    }
}
