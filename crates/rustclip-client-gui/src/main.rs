//! Tauri v2 desktop client for RustClip.
//!
//! Runs the clipboard sync daemon in the Tauri backend, exposes the
//! account + history UIs as webview windows, and presents a tray icon
//! with recent-items submenu so the user can paste back any past clip
//! with one click.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod history_watcher;
mod sync_runner;
mod tray;

use std::sync::Arc;

use tauri::async_runtime::Mutex;
use tauri_plugin_autostart::MacosLauncher;
use tracing_subscriber::{EnvFilter, fmt};

use crate::sync_runner::SyncRunner;

pub struct AppStateInner {
    pub sync: Arc<SyncRunner>,
}

pub type AppState = Arc<Mutex<AppStateInner>>;

fn main() {
    init_tracing();

    let sync = Arc::new(SyncRunner::new());
    let app_state: AppState = Arc::new(Mutex::new(AppStateInner { sync: sync.clone() }));

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            None,
        ))
        .manage(app_state.clone())
        .setup(move |app| {
            // Menu-bar-only on macOS: no dock tile, no application menu,
            // tray icon is the entire visible surface. Windows open as
            // floating panels and don't register dock presence.
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            tray::install(app.handle())?;

            // If already enrolled, spin sync up on launch.
            let handle = app.handle().clone();
            let runner = sync.clone();
            tauri::async_runtime::spawn(async move {
                if rustclip_client::gui_api::local_account()
                    .ok()
                    .flatten()
                    .is_some()
                {
                    if let Err(e) = runner.start(handle.clone()).await {
                        tracing::warn!(error = %e, "auto-start sync failed");
                    }
                }
                tray::refresh_menu(&handle).await;
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::cmd_status,
            commands::cmd_enroll,
            commands::cmd_login,
            commands::cmd_logout,
            commands::cmd_reset,
            commands::cmd_list_history,
            commands::cmd_clear_history,
            commands::cmd_copy_history_text,
            commands::cmd_start_sync,
            commands::cmd_stop_sync,
            commands::cmd_sync_running,
            commands::cmd_set_autostart,
            commands::cmd_get_autostart,
            commands::cmd_show_window,
        ])
        .on_window_event(|window, event| {
            // Closing a UI window should hide it rather than quit the app;
            // the tray icon keeps the daemon alive.
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let _ = window.hide();
                api.prevent_close();
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

fn init_tracing() {
    let filter = EnvFilter::try_from_env("RUSTCLIP_LOG_LEVEL")
        .or_else(|_| EnvFilter::try_new("warn,rustclip_client=info,rustclip_client_gui=info"))
        .expect("static filter");
    let _ = fmt().with_env_filter(filter).try_init();
}
