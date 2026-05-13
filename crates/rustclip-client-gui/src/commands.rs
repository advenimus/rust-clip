//! Tauri IPC handlers. Keep the surface thin — each one wraps a
//! `rustclip_client::gui_api` helper and returns a `Result<T, String>`
//! (Tauri serializes the `String` back to the frontend).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use arboard::Clipboard;
use rustclip_client::gui_api::{
    AccountStatus, ClientConfigView, EnrollInput, HistoryEntryView, LoginInput, clear_history,
    enroll, get_client_config, history_item_bundle_paths, history_item_image, list_history,
    local_account, login, logout, reset, set_client_config,
};
use rustclip_client::history::HistoryKind;
use rustclip_client::log_setup;
use serde::Serialize;
use tauri::async_runtime::spawn_blocking;
use tauri::{AppHandle, Manager, WebviewUrl, WebviewWindowBuilder};
use tauri_plugin_autostart::ManagerExt;
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_opener::OpenerExt;
use time::OffsetDateTime;
use time::macros::format_description;

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
    copy_history_item(state, entry_id).await
}

/// Non-command implementation of `cmd_copy_history_item`. Exposed so
/// other call sites (the global recopy hotkey, the tray submenu) can
/// reuse the same dispatch without round-tripping through the IPC layer.
pub async fn copy_history_item(
    state: tauri::State<'_, AppState>,
    entry_id: String,
) -> Result<(), String> {
    tracing::debug!(entry_id = %entry_id, "copy_history_item invoked");

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
pub async fn cmd_set_client_config(
    app: AppHandle,
    config: ClientConfigView,
) -> Result<ClientConfigView, String> {
    let updated = set_client_config(config).map_err(map_err)?;
    // Re-register the hotkey from the saved-and-normalized value so
    // an empty string clears the registration and an invalid combo
    // surfaces a `recopy-hotkey-error` event for the UI.
    crate::hotkey::re_register(&app, &updated.recopy_hotkey);
    Ok(updated)
}

/// Return the absolute path to the on-disk log directory. UI displays
/// it under the Diagnostics buttons so users know where to look even
/// without clicking through.
#[tauri::command]
pub async fn cmd_log_dir() -> Result<String, String> {
    Ok(log_setup::log_dir().to_string_lossy().to_string())
}

/// Reveal the log directory in the user's file manager. Creates it
/// first if it doesn't exist yet — a fresh install with sync never
/// enabled may not have rotated a log file yet, and we'd rather show
/// an empty folder than fail with "no such file."
#[tauri::command]
pub async fn cmd_open_log_dir(app: AppHandle) -> Result<(), String> {
    let dir = log_setup::log_dir();
    if let Err(e) = fs::create_dir_all(&dir) {
        return Err(format!("create log dir: {e}"));
    }
    app.opener()
        .open_path(dir.to_string_lossy().to_string(), None::<&str>)
        .map_err(|e| e.to_string())
}

/// Pack the recent daily log files into a zip the user picks a
/// location for. Returns the chosen path, or `None` if they cancelled
/// the save dialog. Files matching the daily-rolling pattern
/// `<prefix>.YYYY-MM-DD.<suffix>` are included; nothing else in the
/// log directory is touched.
#[tauri::command]
pub async fn cmd_export_logs_zip(app: AppHandle) -> Result<Option<String>, String> {
    let stamp = OffsetDateTime::now_utc()
        .format(format_description!(
            "[year][month][day]-[hour][minute][second]"
        ))
        .unwrap_or_else(|_| "now".into());
    let default_name = format!("rustclip-logs-{stamp}.zip");

    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .set_file_name(&default_name)
        .add_filter("Zip archive", &["zip"])
        .save_file(move |path| {
            let _ = tx.send(path);
        });
    let chosen = rx.await.map_err(|e| format!("save-file channel: {e}"))?;
    let Some(file_path) = chosen else {
        return Ok(None);
    };
    let target: PathBuf = file_path
        .as_path()
        .ok_or_else(|| "save-file dialog returned a non-path URL".to_string())?
        .to_path_buf();

    let log_dir = log_setup::log_dir();
    let prefix = log_setup::log_file_prefix().to_string();
    let suffix = log_setup::log_file_suffix().to_string();
    let target_for_task = target.clone();

    let written =
        spawn_blocking(move || write_logs_zip(&log_dir, &prefix, &suffix, &target_for_task))
            .await
            .map_err(|e| format!("zip task join: {e}"))??;

    tracing::info!(
        target = %target.display(),
        files = written,
        "exported logs to zip"
    );

    Ok(Some(target.to_string_lossy().to_string()))
}

/// Walk the log directory and write any daily-rolling log file into
/// `dst` as a deflate-compressed zip. Returns the number of files
/// packed. Runs on a blocking thread because zip writes can be large
/// and `std::io::copy` is sync. If the log directory is missing or
/// empty, the zip is still produced — with a single placeholder text
/// entry — so the user always gets a file they can hand back.
fn write_logs_zip(log_dir: &Path, prefix: &str, suffix: &str, dst: &Path) -> Result<usize, String> {
    let f = fs::File::create(dst).map_err(|e| format!("create zip: {e}"))?;
    let mut zw = zip::ZipWriter::new(f);
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    let mut names: Vec<(String, PathBuf)> = Vec::new();
    if log_dir.exists() {
        let entries = fs::read_dir(log_dir).map_err(|e| format!("read log dir: {e}"))?;
        for entry in entries {
            let Ok(entry) = entry else { continue };
            let Ok(ft) = entry.file_type() else { continue };
            if !ft.is_file() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            if is_daily_log(&name, prefix, suffix) {
                names.push((name, entry.path()));
            }
        }
        names.sort_by(|a, b| a.0.cmp(&b.0));
    }

    if names.is_empty() {
        zw.start_file("README.txt", opts)
            .map_err(|e| format!("zip placeholder: {e}"))?;
        let msg = format!(
            "No RustClip log files were found in {}.\n\
             If you expected logs here, the GUI may not have been launched\n\
             since the logging feature shipped — try copying or pasting\n\
             something and exporting again.\n",
            log_dir.display()
        );
        zw.write_all(msg.as_bytes())
            .map_err(|e| format!("zip placeholder write: {e}"))?;
        zw.finish().map_err(|e| format!("finish zip: {e}"))?;
        return Ok(0);
    }

    let mut count: usize = 0;
    for (name, path) in names {
        zw.start_file(&name, opts)
            .map_err(|e| format!("zip start_file {name}: {e}"))?;
        let mut src = fs::File::open(&path).map_err(|e| format!("open {}: {e}", path.display()))?;
        std::io::copy(&mut src, &mut zw).map_err(|e| format!("copy {}: {e}", path.display()))?;
        count += 1;
    }
    zw.finish().map_err(|e| format!("finish zip: {e}"))?;
    Ok(count)
}

fn is_daily_log(name: &str, prefix: &str, suffix: &str) -> bool {
    // tracing-appender daily rolling: <prefix>.YYYY-MM-DD.<suffix>
    // Require a non-empty stamp between the dots; otherwise an
    // unrelated `<prefix>.<suffix>` file would slip through.
    let head = format!("{prefix}.");
    let tail = format!(".{suffix}");
    name.starts_with(&head) && name.ends_with(&tail) && name.len() > head.len() + tail.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn is_daily_log_matches_appender_output() {
        assert!(is_daily_log("rustclip.2026-05-13.log", "rustclip", "log"));
        assert!(!is_daily_log("rustclip", "rustclip", "log"));
        assert!(!is_daily_log("rustclip.log", "rustclip", "log"));
        assert!(!is_daily_log("other.2026-05-13.log", "rustclip", "log"));
        assert!(!is_daily_log("rustclip.2026-05-13.txt", "rustclip", "log"));
    }

    #[test]
    fn write_logs_zip_packs_matching_files() {
        let src = TempDir::new().unwrap();
        let dst = TempDir::new().unwrap();
        fs::write(src.path().join("rustclip.2026-05-13.log"), b"day-one").unwrap();
        fs::write(src.path().join("rustclip.2026-05-12.log"), b"day-zero").unwrap();
        fs::write(src.path().join("not-a-log.txt"), b"ignore me").unwrap();

        let zip_path = dst.path().join("logs.zip");
        let n = write_logs_zip(src.path(), "rustclip", "log", &zip_path).unwrap();
        assert_eq!(n, 2);

        // Re-open the produced zip and confirm exactly the two log files.
        let zf = fs::File::open(&zip_path).unwrap();
        let mut zr = zip::ZipArchive::new(zf).unwrap();
        assert_eq!(zr.len(), 2);
        let mut names: Vec<String> = (0..zr.len())
            .map(|i| zr.by_index(i).unwrap().name().to_string())
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec!["rustclip.2026-05-12.log", "rustclip.2026-05-13.log"]
        );
    }

    #[test]
    fn write_logs_zip_writes_placeholder_when_empty() {
        let src = TempDir::new().unwrap();
        let dst = TempDir::new().unwrap();
        let zip_path = dst.path().join("logs.zip");
        let n = write_logs_zip(src.path(), "rustclip", "log", &zip_path).unwrap();
        assert_eq!(n, 0);

        let zf = fs::File::open(&zip_path).unwrap();
        let mut zr = zip::ZipArchive::new(zf).unwrap();
        assert_eq!(zr.len(), 1);
        assert_eq!(zr.by_index(0).unwrap().name(), "README.txt");
    }
}
