//! System tray icon + menu. Rebuilt on status or history change.

use anyhow::Result;
use tauri::{
    AppHandle, Manager,
    image::Image,
    menu::{Menu, MenuItem, PredefinedMenuItem, Submenu},
    tray::{TrayIcon, TrayIconBuilder},
};
use tracing::warn;

use crate::AppState;
use crate::commands::open_or_focus;

const TRAY_ID: &str = "rustclip-tray";

pub fn install(app: &AppHandle) -> Result<()> {
    let icon_bytes = include_bytes!("../icons/icon.png");
    let icon = Image::from_bytes(icon_bytes)?;
    let menu = build_initial_menu(app)?;
    let _tray: TrayIcon = TrayIconBuilder::with_id(TRAY_ID)
        .icon(icon)
        .tooltip("RustClip")
        .menu(&menu)
        .show_menu_on_left_click(true)
        .on_menu_event(handle_menu_event)
        .build(app)?;
    Ok(())
}

fn build_initial_menu(app: &AppHandle) -> Result<Menu<tauri::Wry>> {
    Menu::with_items(
        app,
        &[
            &MenuItem::with_id(app, "status", "RustClip — starting…", false, None::<&str>)?,
            &PredefinedMenuItem::separator(app)?,
            &MenuItem::with_id(app, "open-account", "Account", true, None::<&str>)?,
            &MenuItem::with_id(app, "open-history", "History", true, None::<&str>)?,
            &PredefinedMenuItem::separator(app)?,
            &MenuItem::with_id(app, "start-sync", "Start sync", true, None::<&str>)?,
            &MenuItem::with_id(app, "stop-sync", "Stop sync", true, None::<&str>)?,
            &PredefinedMenuItem::separator(app)?,
            &MenuItem::with_id(app, "quit", "Quit RustClip", true, None::<&str>)?,
        ],
    )
    .map_err(|e| anyhow::anyhow!(e))
}

pub async fn refresh_menu(app: &AppHandle) {
    if let Err(e) = refresh_menu_inner(app).await {
        warn!(error = %e, "refreshing tray menu failed");
    }
}

async fn refresh_menu_inner(app: &AppHandle) -> Result<()> {
    let state: tauri::State<'_, AppState> = app.state();
    let inner = state.lock().await;
    let sync_status = inner.sync.status().await;
    drop(inner);

    let account = rustclip_client::gui_api::local_account().ok().flatten();
    let status_label = match (&account, sync_status) {
        (None, _) => "Not enrolled".to_string(),
        (Some(a), crate::sync_runner::SyncStatus::Running) => {
            format!("Connected · {}", a.username)
        }
        (Some(a), crate::sync_runner::SyncStatus::Stopped) => {
            format!("Offline · {}", a.username)
        }
        (Some(a), crate::sync_runner::SyncStatus::Failed) => {
            format!("Error · {}", a.username)
        }
    };

    let history = rustclip_client::gui_api::list_history(10).unwrap_or_default();
    let mut history_items: Vec<MenuItem<tauri::Wry>> = Vec::new();
    for item in &history {
        if item.kind != "text" {
            continue;
        }
        let preview = snippet(&item.preview, 48);
        let label = format!("[{}] {}", item.direction_short(), preview);
        let id = format!("history-copy::{}", item.id);
        history_items.push(MenuItem::with_id(app, id, label, true, None::<&str>)?);
    }

    let history_submenu = if history_items.is_empty() {
        Submenu::with_id_and_items(
            app,
            "history-menu",
            "Recent clips",
            true,
            &[&MenuItem::with_id(
                app,
                "history-empty",
                "(nothing yet)",
                false,
                None::<&str>,
            )?],
        )?
    } else {
        let refs: Vec<&dyn tauri::menu::IsMenuItem<tauri::Wry>> = history_items
            .iter()
            .map(|m| m as &dyn tauri::menu::IsMenuItem<tauri::Wry>)
            .collect();
        Submenu::with_id_and_items(app, "history-menu", "Recent clips", true, &refs)?
    };

    let menu = Menu::with_items(
        app,
        &[
            &MenuItem::with_id(app, "status", status_label, false, None::<&str>)?,
            &PredefinedMenuItem::separator(app)?,
            &history_submenu,
            &PredefinedMenuItem::separator(app)?,
            &MenuItem::with_id(app, "open-account", "Account…", true, None::<&str>)?,
            &MenuItem::with_id(app, "open-history", "History…", true, None::<&str>)?,
            &PredefinedMenuItem::separator(app)?,
            &MenuItem::with_id(
                app,
                "start-sync",
                "Start sync",
                !matches!(sync_status, crate::sync_runner::SyncStatus::Running)
                    && account.is_some(),
                None::<&str>,
            )?,
            &MenuItem::with_id(
                app,
                "stop-sync",
                "Stop sync",
                matches!(sync_status, crate::sync_runner::SyncStatus::Running),
                None::<&str>,
            )?,
            &PredefinedMenuItem::separator(app)?,
            &MenuItem::with_id(app, "quit", "Quit RustClip", true, None::<&str>)?,
        ],
    )?;

    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        tray.set_menu(Some(menu))?;
        let tooltip = match sync_status {
            crate::sync_runner::SyncStatus::Running => "RustClip — connected",
            crate::sync_runner::SyncStatus::Stopped => "RustClip — offline",
            crate::sync_runner::SyncStatus::Failed => "RustClip — error",
        };
        tray.set_tooltip(Some(tooltip))?;
    }
    Ok(())
}

fn handle_menu_event(app: &AppHandle, event: tauri::menu::MenuEvent) {
    let id = event.id().as_ref().to_string();
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        if let Err(e) = dispatch(&app, &id).await {
            warn!(error = %e, menu_id = %id, "tray menu handler failed");
        }
        refresh_menu(&app).await;
    });
}

async fn dispatch(app: &AppHandle, id: &str) -> Result<()> {
    match id {
        "open-account" => open_or_focus(app, "account")?,
        "open-history" => open_or_focus(app, "history")?,
        "start-sync" => {
            let state: tauri::State<'_, AppState> = app.state();
            let inner = state.lock().await;
            inner.sync.start(app.clone()).await?;
        }
        "stop-sync" => {
            let state: tauri::State<'_, AppState> = app.state();
            let inner = state.lock().await;
            inner.sync.stop(app).await?;
        }
        "quit" => {
            let state: tauri::State<'_, AppState> = app.state();
            let inner = state.lock().await;
            let _ = inner.sync.stop(app).await;
            drop(inner);
            app.exit(0);
        }
        other if other.starts_with("history-copy::") => {
            let id = other.trim_start_matches("history-copy::");
            if let Some(text) = rustclip_client::gui_api::history_item_text(id)? {
                let mut cb = arboard::Clipboard::new()?;
                cb.set_text(text)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn snippet(s: &str, max: usize) -> String {
    let s = s.replace(['\n', '\r', '\t'], " ");
    if s.chars().count() <= max {
        s
    } else {
        let cut: String = s.chars().take(max).collect();
        format!("{cut}…")
    }
}

trait DirShort {
    fn direction_short(&self) -> &'static str;
}
impl DirShort for rustclip_client::gui_api::HistoryEntryView {
    fn direction_short(&self) -> &'static str {
        match self.direction.as_str() {
            "outgoing" => "out",
            "incoming" => "in",
            _ => "·",
        }
    }
}
