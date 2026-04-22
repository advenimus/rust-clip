//! Tauri IPC handlers. Keep the surface thin — each one wraps a
//! `rustclip_client::gui_api` helper and returns a `Result<T, String>`
//! (Tauri serializes the `String` back to the frontend).

use arboard::Clipboard;
use rustclip_client::gui_api::{
    AccountStatus, ClientConfigView, EnrollInput, HistoryEntryView, LoginInput, clear_history,
    enroll, get_client_config, list_history, local_account, login, logout, reset,
    set_client_config,
};
use serde::Serialize;
use tauri::{AppHandle, Manager, WebviewUrl, WebviewWindowBuilder};
use tauri_plugin_autostart::ManagerExt;
use tauri_plugin_opener::OpenerExt;

use crate::{AppState, tray, updater};

fn map_err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

#[tauri::command]
pub async fn cmd_status() -> Result<Option<AccountStatus>, String> {
    local_account().map_err(map_err)
}

#[tauri::command]
pub async fn cmd_enroll(
    app: AppHandle,
    state: tauri::State<'_, AppState>,
    input: EnrollInput,
) -> Result<AccountStatus, String> {
    let status = enroll(input).await.map_err(map_err)?;
    kick_off_sync(&app, &state).await;
    Ok(status)
}

#[tauri::command]
pub async fn cmd_login(
    app: AppHandle,
    state: tauri::State<'_, AppState>,
    input: LoginInput,
) -> Result<AccountStatus, String> {
    let status = login(input).await.map_err(map_err)?;
    kick_off_sync(&app, &state).await;
    Ok(status)
}

async fn kick_off_sync(app: &AppHandle, state: &tauri::State<'_, AppState>) {
    {
        let inner = state.lock().await;
        if let Err(e) = inner.sync.start(app.clone()).await {
            tracing::warn!(error = %e, "auto-start of sync after enroll/login failed");
        }
    }
    tray::refresh_menu(app).await;
}

#[tauri::command]
pub async fn cmd_logout(app: AppHandle, state: tauri::State<'_, AppState>) -> Result<(), String> {
    {
        let inner = state.lock().await;
        let _ = inner.sync.stop(&app).await;
    }
    logout().await.map_err(map_err)?;
    tray::refresh_menu(&app).await;
    Ok(())
}

#[tauri::command]
pub async fn cmd_reset(app: AppHandle, state: tauri::State<'_, AppState>) -> Result<(), String> {
    {
        let inner = state.lock().await;
        let _ = inner.sync.stop(&app).await;
    }
    reset().map_err(map_err)?;
    tray::refresh_menu(&app).await;
    Ok(())
}

#[tauri::command]
pub async fn cmd_list_history(limit: i64) -> Result<Vec<HistoryEntryView>, String> {
    list_history(limit.max(1)).map_err(map_err)
}

#[tauri::command]
pub async fn cmd_clear_history() -> Result<(), String> {
    clear_history().map_err(map_err)
}

/// Copy a past text history item back to the OS clipboard without
/// re-broadcasting. The sync watcher's post-write quiet window
/// suppresses the echo.
///
/// The actual arboard write runs inside `spawn_blocking` so it lands
/// on a dedicated OS thread that survives the tokio-worker rescheduling
/// (`arboard::Clipboard` holds per-instance OS handles and can race
/// with the sync daemon's own clipboard-owning thread if two live on
/// the same tokio runtime).
#[tauri::command]
pub async fn cmd_copy_history_text(entry_id: String) -> Result<(), String> {
    tracing::debug!(entry_id = %entry_id, "cmd_copy_history_text invoked");
    let text = match rustclip_client::gui_api::history_item_text(&entry_id) {
        Ok(Some(t)) => t,
        Ok(None) => {
            tracing::warn!(
                entry_id = %entry_id,
                "history entry not found or not a text row — nothing to copy"
            );
            return Err("history entry not found or not text".to_string());
        }
        Err(e) => {
            tracing::error!(entry_id = %entry_id, error = %e, "history_item_text failed");
            return Err(map_err(e));
        }
    };
    let bytes = text.len();
    tokio::task::spawn_blocking(move || -> Result<(), String> {
        let mut cb = Clipboard::new().map_err(|e| format!("clipboard open: {e}"))?;
        cb.set_text(text).map_err(|e| format!("clipboard write: {e}"))
    })
    .await
    .map_err(|e| format!("clipboard task join: {e}"))??;
    tracing::info!(entry_id = %entry_id, bytes, "copy-from-history wrote clipboard");
    Ok(())
}

#[tauri::command]
pub async fn cmd_start_sync(
    app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let inner = state.lock().await;
    inner.sync.start(app.clone()).await.map_err(map_err)
}

#[tauri::command]
pub async fn cmd_stop_sync(
    app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let inner = state.lock().await;
    inner.sync.stop(&app).await.map_err(map_err)
}

#[tauri::command]
pub async fn cmd_sync_running(state: tauri::State<'_, AppState>) -> Result<bool, String> {
    let inner = state.lock().await;
    Ok(inner.sync.is_running().await)
}

#[tauri::command]
pub async fn cmd_set_autostart(app: AppHandle, enable: bool) -> Result<(), String> {
    let manager = app.autolaunch();
    if enable {
        manager.enable().map_err(|e| e.to_string())
    } else {
        manager.disable().map_err(|e| e.to_string())
    }
}

#[tauri::command]
pub async fn cmd_get_autostart(app: AppHandle) -> Result<bool, String> {
    app.autolaunch().is_enabled().map_err(|e| e.to_string())
}

/// Opens (or focuses) one of the known windows. The webview URL uses
/// `#account` / `#history` / `#about` hashes so a single `index.html`
/// renders the right panel.
#[tauri::command]
pub async fn cmd_show_window(app: AppHandle, name: String) -> Result<(), String> {
    open_or_focus(&app, &name).map_err(map_err)
}

pub fn open_or_focus(app: &AppHandle, name: &str) -> anyhow::Result<()> {
    let label = match name {
        "account" => "account",
        "history" => "history",
        "about" => "about",
        other => anyhow::bail!("unknown window: {other}"),
    };
    if let Some(win) = app.get_webview_window(label) {
        let _ = win.show();
        let _ = win.set_focus();
        return Ok(());
    }
    let url = format!("index.html#{label}");
    let title = match label {
        "account" => "RustClip · Account",
        "history" => "RustClip · History",
        "about" => "RustClip · About",
        _ => "RustClip",
    };
    WebviewWindowBuilder::new(app, label, WebviewUrl::App(url.into()))
        .title(title)
        .inner_size(760.0, 560.0)
        .min_inner_size(520.0, 360.0)
        .resizable(true)
        .visible(true)
        .build()?;
    Ok(())
}

#[derive(Serialize)]
pub struct AboutInfo {
    pub version: &'static str,
    pub repo_url: &'static str,
    pub author_name: &'static str,
    pub author_handle: &'static str,
    pub author_url: &'static str,
    pub license: &'static str,
}

#[tauri::command]
pub async fn cmd_about() -> Result<AboutInfo, String> {
    Ok(AboutInfo {
        version: env!("CARGO_PKG_VERSION"),
        repo_url: "https://github.com/advenimus/rust-clip",
        author_name: "Chris Vautour",
        author_handle: "advenimus",
        author_url: "https://github.com/advenimus",
        license: "PolyForm Noncommercial 1.0.0",
    })
}

/// Open an external URL in the user's default browser via the opener plugin.
/// Used by About-panel links so webview navigation doesn't try to load them
/// in-app.
#[tauri::command]
pub async fn cmd_open_external(app: AppHandle, url: String) -> Result<(), String> {
    app.opener()
        .open_url(url, None::<&str>)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn cmd_check_update(app: AppHandle) -> Result<Option<updater::UpdateInfo>, String> {
    updater::check_for_update(&app).await.map_err(map_err)
}

#[tauri::command]
pub async fn cmd_install_update(app: AppHandle) -> Result<(), String> {
    updater::install_update(&app).await.map_err(map_err)
}

#[tauri::command]
pub async fn cmd_update_install_kind() -> Result<updater::InstallKind, String> {
    Ok(updater::install_kind())
}

#[tauri::command]
pub async fn cmd_get_client_config() -> Result<ClientConfigView, String> {
    get_client_config().map_err(map_err)
}

#[tauri::command]
pub async fn cmd_set_client_config(config: ClientConfigView) -> Result<ClientConfigView, String> {
    set_client_config(config).map_err(map_err)
}
