//! Tauri IPC handlers. Keep the surface thin — each one wraps a
//! `rustclip_client::gui_api` helper and returns a `Result<T, String>`
//! (Tauri serializes the `String` back to the frontend).

use arboard::Clipboard;
use rustclip_client::gui_api::{
    AccountStatus, ClientConfigView, EnrollInput, HistoryEntryView, LoginInput, clear_history,
    enroll, get_client_config, history_item_bundle_paths, history_item_image, list_history,
    local_account, login, logout, reset, set_client_config,
};
use rustclip_client::history::HistoryKind;
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

/// Copy any kind of history row back onto the OS clipboard without
/// re-broadcasting to other devices.
///
/// Dispatches by row kind:
///   - **text** — pull the decrypted preview, write via the worker.
///   - **image** — decrypt the `<event_id>.enc` blob, PNG-decode, write
///     as an ImageData via the worker.
///   - **bundle** — resolve the inbox folder's top-level entries and
///     push them onto the OS file clipboard via the worker.
///
/// Routing through the clipboard worker (owned by `SyncRunner`) is
/// what prevents the recopy from triggering a fresh "outgoing" clip
/// event 500ms later: the worker stamps its own echo-suppression
/// hashes as it writes, so the next poll sees a match and stays quiet.
///
/// If sync isn't currently running, there is no worker — the tray can
/// offer a text fallback (fresh arboard instance), but images and
/// bundles need the worker thread's `arboard::Clipboard` for their
/// OS-specific calls, so they fail clean with an explanatory error.
#[tauri::command]
pub async fn cmd_copy_history_item(
    state: tauri::State<'_, AppState>,
    entry_id: String,
) -> Result<(), String> {
    tracing::debug!(entry_id = %entry_id, "cmd_copy_history_item invoked");

    let kind = rustclip_client::gui_api::history_item_kind(&entry_id)
        .map_err(map_err)?
        .ok_or_else(|| "history entry not found".to_string())?;

    // Pull a clone of the clipboard handle out from under the async
    // Mutex before doing any blocking work — we hold the runner lock
    // for only a moment.
    let handle_opt = {
        let inner = state.lock().await;
        inner.sync.clipboard()
    };

    match kind {
        HistoryKind::Text => {
            let text = rustclip_client::gui_api::history_item_text(&entry_id)
                .map_err(map_err)?
                .ok_or_else(|| "history entry not found or not text".to_string())?;
            let bytes = text.len();
            if let Some(handle) = handle_opt {
                handle.write_text(text).map_err(map_err)?;
                tracing::info!(entry_id = %entry_id, bytes, "text recopy via worker");
            } else {
                // Fallback: sync isn't running, so there's no worker to
                // route through. Re-broadcast isn't a concern here
                // (nothing is polling the clipboard). Use a throwaway
                // arboard on a dedicated blocking thread so we don't
                // starve the tokio worker pool.
                tokio::task::spawn_blocking(move || -> Result<(), String> {
                    let mut cb = Clipboard::new().map_err(|e| format!("clipboard open: {e}"))?;
                    cb.set_text(text)
                        .map_err(|e| format!("clipboard write: {e}"))
                })
                .await
                .map_err(|e| format!("clipboard task join: {e}"))??;
                tracing::info!(entry_id = %entry_id, bytes, "text recopy via fallback");
            }
        }
        HistoryKind::Image => {
            let Some(handle) = handle_opt else {
                return Err("sync must be running to copy an image from history".to_string());
            };
            let image = history_item_image(&entry_id)
                .map_err(map_err)?
                .ok_or_else(|| "image no longer available in history".to_string())?;
            let (width, height) = (image.width, image.height);
            handle.write_image(image).map_err(map_err)?;
            tracing::info!(entry_id = %entry_id, width, height, "image recopy via worker");
        }
        HistoryKind::Bundle => {
            let Some(handle) = handle_opt else {
                return Err("sync must be running to copy files from history".to_string());
            };
            let paths = history_item_bundle_paths(&entry_id)
                .map_err(map_err)?
                .ok_or_else(|| "bundle files no longer available".to_string())?;
            let count = paths.len();
            handle.write_file_list(paths).map_err(map_err)?;
            tracing::info!(entry_id = %entry_id, count, "bundle recopy via worker");
        }
    }

    Ok(())
}

/// Deprecated alias for `cmd_copy_history_item`. Older frontend caches
/// that still call `cmd_copy_history_text` keep working for one release
/// while the new UI rolls out.
#[tauri::command]
pub async fn cmd_copy_history_text(
    state: tauri::State<'_, AppState>,
    entry_id: String,
) -> Result<(), String> {
    // Kept as a thin alias while the frontend cache updates; delegates
    // directly to the kind-agnostic command.
    cmd_copy_history_item(state, entry_id).await
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
