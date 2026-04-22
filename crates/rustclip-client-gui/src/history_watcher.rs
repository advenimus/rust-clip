//! Polls the local history DB and fires Tauri events + OS toasts when a
//! new incoming clip lands.
//!
//! Polling is the pragmatic choice here over hooking inside the sync
//! loop: the history DB is written from the sync task on every
//! successful incoming decrypt, so tailing it in a side task keeps the
//! sync path unchanged and also catches writes that happen through a
//! parallel CLI run. A 2-second cadence is plenty for notifications and
//! costs microseconds per tick.

use std::time::Duration;

use tauri::{AppHandle, Emitter};
use tauri_plugin_notification::NotificationExt;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use rustclip_client::gui_api::HistoryEntryView;

const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Spawns the watcher and returns its handle. Drop/abort to stop it.
pub fn spawn(app: AppHandle) -> JoinHandle<()> {
    tokio::spawn(run(app))
}

async fn run(app: AppHandle) {
    // Seed last-seen with whatever is already in the DB so we don't
    // double-notify every historical item on first tick.
    let mut last_seen_id = latest_incoming_id();
    let mut ticker = tokio::time::interval(POLL_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await; // burn first immediate tick

    loop {
        ticker.tick().await;
        match latest_incoming() {
            Ok(Some(item)) if Some(item.id.clone()) != last_seen_id => {
                last_seen_id = Some(item.id.clone());
                notify_and_emit(&app, &item);
            }
            Ok(_) => {}
            Err(e) => debug!(error = %e, "history watcher: list failed"),
        }
    }
}

fn latest_incoming() -> anyhow::Result<Option<HistoryEntryView>> {
    let items = rustclip_client::gui_api::list_history(5)?;
    Ok(items.into_iter().find(|it| it.direction == "incoming"))
}

fn latest_incoming_id() -> Option<String> {
    latest_incoming().ok().flatten().map(|i| i.id)
}

fn notify_and_emit(app: &AppHandle, item: &HistoryEntryView) {
    let _ = app.emit("history-updated", ());
    if !notifications_enabled() {
        return;
    }
    let (title, body) = match item.kind.as_str() {
        "text" => ("New clipboard item".to_string(), trim(&item.preview, 80)),
        "image" => ("New clipboard image".to_string(), item.preview.clone()),
        "bundle" => ("New files synced".to_string(), item.preview.clone()),
        other => (format!("New clip ({other})"), item.preview.clone()),
    };
    if let Err(e) = app.notification().builder().title(title).body(body).show() {
        warn!(error = %e, "showing incoming-clip notification failed");
    }
}

/// Reads the per-device config. Fails open (returns true) on error so a
/// transient disk issue doesn't silently eat notifications.
fn notifications_enabled() -> bool {
    match rustclip_client::gui_api::get_client_config() {
        Ok(cfg) => cfg.notifications_enabled,
        Err(e) => {
            debug!(error = %e, "reading client config failed; defaulting to notifications enabled");
            true
        }
    }
}

fn trim(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.replace(['\n', '\r', '\t'], " ")
    } else {
        let cut: String = s.chars().take(max).collect();
        format!("{}…", cut.replace(['\n', '\r', '\t'], " "))
    }
}
