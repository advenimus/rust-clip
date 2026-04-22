//! Thin wrapper around `tauri-plugin-updater` for check + install + install-kind detection.
//!
//! The tray app boots, waits a few seconds, then calls [`check_and_notify`] —
//! on a hit we emit `update-available` with an [`UpdateInfo`] payload so the
//! frontend banner can reveal itself. Actual install is user-triggered via
//! the `cmd_install_update` Tauri command so the sync daemon doesn't restart
//! mid-paste.

use serde::Serialize;
use tauri::{AppHandle, Emitter};
use tauri_plugin_updater::UpdaterExt;

/// What kind of package the app was installed from. Drives whether the
/// frontend can offer an in-app install button or has to defer to the system
/// package manager.
#[derive(Serialize, Clone, Copy, Debug)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)] // variants are cfg-gated; unused per-platform compilations still need them.
pub enum InstallKind {
    Dmg,
    Msi,
    Nsis,
    AppImage,
    Deb,
    Rpm,
    Unknown,
}

impl InstallKind {
    pub fn is_self_updatable(self) -> bool {
        matches!(self, Self::Dmg | Self::Msi | Self::Nsis | Self::AppImage)
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct UpdateInfo {
    pub current_version: String,
    pub latest_version: String,
    pub release_notes: Option<String>,
    pub install_kind: InstallKind,
    pub release_url: String,
}

/// Best-effort detection of how the running binary was installed.
pub fn install_kind() -> InstallKind {
    #[cfg(target_os = "macos")]
    {
        InstallKind::Dmg
    }
    #[cfg(target_os = "windows")]
    {
        // Both .msi and NSIS .exe land in the same end state; the updater
        // plugin picks the right replacement asset by target triple. We can't
        // reliably tell which one was used, so return Nsis as the cover-all.
        InstallKind::Nsis
    }
    #[cfg(target_os = "linux")]
    {
        if std::env::var_os("APPIMAGE").is_some() {
            return InstallKind::AppImage;
        }
        if std::path::Path::new("/etc/debian_version").exists() {
            return InstallKind::Deb;
        }
        if std::path::Path::new("/etc/redhat-release").exists()
            || std::path::Path::new("/etc/fedora-release").exists()
        {
            return InstallKind::Rpm;
        }
        InstallKind::Unknown
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        InstallKind::Unknown
    }
}

const RELEASES_PAGE: &str = "https://github.com/advenimus/rust-clip/releases/latest";

/// Returns `Some(info)` when the updater manifest reports a newer version,
/// `None` when up-to-date, and an error if the check itself failed.
pub async fn check_for_update(app: &AppHandle) -> anyhow::Result<Option<UpdateInfo>> {
    let updater = app
        .updater()
        .map_err(|e| anyhow::anyhow!("updater plugin not initialized: {e}"))?;
    match updater.check().await {
        Ok(Some(update)) => Ok(Some(UpdateInfo {
            current_version: env!("CARGO_PKG_VERSION").to_string(),
            latest_version: update.version.clone(),
            release_notes: update.body.clone(),
            install_kind: install_kind(),
            release_url: RELEASES_PAGE.to_string(),
        })),
        Ok(None) => Ok(None),
        Err(e) => Err(anyhow::anyhow!("update check failed: {e}")),
    }
}

/// Download + apply the latest update, then restart the app.
pub async fn install_update(app: &AppHandle) -> anyhow::Result<()> {
    let kind = install_kind();
    if !kind.is_self_updatable() {
        anyhow::bail!(
            "in-app update not supported for {kind:?} installs — upgrade via your package manager"
        );
    }
    let updater = app
        .updater()
        .map_err(|e| anyhow::anyhow!("updater plugin not initialized: {e}"))?;
    let Some(update) = updater
        .check()
        .await
        .map_err(|e| anyhow::anyhow!("update check failed: {e}"))?
    else {
        anyhow::bail!("no update available");
    };
    update
        .download_and_install(|_, _| {}, || {})
        .await
        .map_err(|e| anyhow::anyhow!("download/install failed: {e}"))?;
    app.restart();
}

/// Fire-and-forget boot-time check. Emits `update-available` on success,
/// logs and swallows errors so a flaky network doesn't surface a scary
/// toast on every launch.
pub async fn check_and_notify(app: &AppHandle) {
    match check_for_update(app).await {
        Ok(Some(info)) => {
            tracing::info!(
                latest = %info.latest_version,
                current = %info.current_version,
                "update available"
            );
            if let Err(e) = app.emit("update-available", info) {
                tracing::warn!(error = %e, "emit update-available failed");
            }
        }
        Ok(None) => {
            tracing::debug!("no update available");
        }
        Err(e) => {
            tracing::warn!(error = %e, "background update check failed");
        }
    }
}
