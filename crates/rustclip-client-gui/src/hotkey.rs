//! Global "re-copy last clip" shortcut.
//!
//! Registered at startup from `recopy_hotkey` in the user config and
//! re-registered whenever the setting changes. Empty string disables the
//! shortcut. The handler reads the most recent history row and routes
//! it through the existing recopy command so the action is identical
//! to clicking the row in the History window or the tray submenu.

use anyhow::{Result, anyhow};
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_global_shortcut::GlobalShortcutExt;
use tauri_plugin_notification::NotificationExt;
use tracing::{info, warn};

use crate::AppState;
use crate::commands::copy_history_item;

/// Pull the configured shortcut and register it. Called once during
/// `setup()`. A missing config or empty shortcut means do nothing —
/// the user can set one later in Settings.
pub fn register_from_config(app: &AppHandle) {
    let shortcut = match rustclip_client::gui_api::get_client_config() {
        Ok(cfg) if cfg.recopy_hotkey_enabled => cfg.recopy_hotkey,
        Ok(_) => String::new(),
        Err(e) => {
            warn!(error = %e, "reading client config failed; skipping hotkey registration");
            return;
        }
    };
    re_register(app, &shortcut);
}

/// Replace whatever shortcut is currently registered. Empty `next`
/// just unregisters the previous one. Errors surface as a
/// `recopy-hotkey-error` Tauri event for the UI to display, and the
/// caller's config save still goes through so the user has a chance to
/// correct it.
pub fn re_register(app: &AppHandle, next: &str) {
    let plugin = app.global_shortcut();
    if let Err(e) = plugin.unregister_all() {
        warn!(error = %e, "unregistering old global shortcut failed");
    }
    if next.is_empty() {
        info!("recopy hotkey cleared");
        return;
    }
    match plugin.register(next) {
        Ok(()) => info!(shortcut = next, "registered global recopy shortcut"),
        Err(e) => {
            warn!(error = %e, shortcut = next, "registering global recopy shortcut failed");
            let _ = app.emit("recopy-hotkey-error", e.to_string());
        }
    }
}

/// Handler invoked when ANY registered shortcut fires. Since we only
/// ever register the one recopy shortcut at a time, this always means
/// "re-copy the latest history item."
pub async fn on_press(app: AppHandle) {
    if let Err(e) = run_recopy(&app).await {
        warn!(error = %e, "recopy hotkey handler failed");
    }
}

async fn run_recopy(app: &AppHandle) -> Result<()> {
    let items =
        rustclip_client::gui_api::list_history(1).map_err(|e| anyhow!("reading history: {e}"))?;
    let Some(item) = items.into_iter().next() else {
        let _ = app
            .notification()
            .builder()
            .title("RustClip")
            .body("History is empty — nothing to re-copy.")
            .show();
        return Ok(());
    };

    let state: tauri::State<'_, AppState> = app.state();
    copy_history_item(state, item.id.clone())
        .await
        .map_err(|e| anyhow!("re-copy: {e}"))?;

    let _ = app
        .notification()
        .builder()
        .title("Re-copied last clip")
        .body(preview(&item))
        .show();
    Ok(())
}

fn preview(item: &rustclip_client::gui_api::HistoryEntryView) -> String {
    let raw = match item.kind.as_str() {
        "text" => item.preview.clone(),
        "image" => format!("(image · {})", item.preview),
        "bundle" => format!("(files · {})", item.preview),
        other => format!("({other})"),
    };
    let cleaned = raw.replace(['\n', '\r', '\t'], " ");
    if cleaned.chars().count() <= 80 {
        cleaned
    } else {
        let cut: String = cleaned.chars().take(80).collect();
        format!("{cut}…")
    }
}
