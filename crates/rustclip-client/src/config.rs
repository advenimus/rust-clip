//! Per-device client configuration.
//!
//! Stored as TOML at `$DATA_LOCAL_DIR/rustclip/config.toml`. Fields here
//! are preferences a user sets once and that should persist across
//! sessions but not across devices — e.g. "auto-sync files from my
//! clipboard" is something you might disable on a work laptop even if
//! it's on for your home machine.
//!
//! A missing file loads cleanly as defaults. Field-level missing values
//! also fall back to defaults via `#[serde(default)]`, so adding a new
//! option in the future will never break an older config.

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::files::DEFAULT_AUTO_BUNDLE_CAP_BYTES;

pub const GUARD_SECONDS_MIN: u32 = 1;
pub const GUARD_SECONDS_MAX: u32 = 30;
pub const DEFAULT_RECOPY_HOTKEY: &str = "CmdOrCtrl+Shift+R";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// If true, the sync watcher picks up file copies from Finder /
    /// Explorer and sends them as encrypted bundles automatically.
    #[serde(default = "default_auto_sync_files")]
    pub auto_sync_files: bool,
    /// Cap, in bytes, on an auto-detected file bundle. Over-cap copies
    /// log a warning and are skipped; the user can still send them via
    /// the explicit `send-files` CLI.
    #[serde(default = "default_auto_sync_max_bytes")]
    pub auto_sync_max_bytes: u64,
    /// If true, the GUI shows an OS toast when a new clipboard item
    /// arrives from another device. The History window refreshes
    /// regardless.
    #[serde(default = "default_notifications_enabled")]
    pub notifications_enabled: bool,
    /// If true, the receive side will re-assert its last write to the
    /// OS clipboard whenever the clipboard goes empty within
    /// `clipboard_guard_seconds`. Workaround for nested
    /// remote-desktop / VDI scenarios where a third-party clipboard
    /// channel clears the clipboard right after our write.
    #[serde(default = "default_clipboard_guard_enabled")]
    pub clipboard_guard_enabled: bool,
    /// How long, in seconds, to keep watching for an empty clipboard
    /// after a remote clip lands. Clamped to `[GUARD_SECONDS_MIN,
    /// GUARD_SECONDS_MAX]` on load and save so a hand-edited config
    /// can't disable the cap.
    #[serde(default = "default_clipboard_guard_seconds")]
    pub clipboard_guard_seconds: u32,
    /// Global shortcut string (tauri-plugin-global-shortcut accelerator
    /// format) that re-copies the most recent history item to the OS
    /// clipboard. Empty string disables the shortcut.
    #[serde(default = "default_recopy_hotkey")]
    pub recopy_hotkey: String,
}

fn default_auto_sync_files() -> bool {
    true
}
fn default_auto_sync_max_bytes() -> u64 {
    DEFAULT_AUTO_BUNDLE_CAP_BYTES
}
fn default_notifications_enabled() -> bool {
    true
}
fn default_clipboard_guard_enabled() -> bool {
    false
}
fn default_clipboard_guard_seconds() -> u32 {
    5
}
fn default_recopy_hotkey() -> String {
    DEFAULT_RECOPY_HOTKEY.to_string()
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            auto_sync_files: default_auto_sync_files(),
            auto_sync_max_bytes: default_auto_sync_max_bytes(),
            notifications_enabled: default_notifications_enabled(),
            clipboard_guard_enabled: default_clipboard_guard_enabled(),
            clipboard_guard_seconds: default_clipboard_guard_seconds(),
            recopy_hotkey: default_recopy_hotkey(),
        }
    }
}

impl ClientConfig {
    /// Coerce out-of-range numeric fields back into supported bounds.
    /// Called on every load and every save so a hand-edited TOML file
    /// can't push the guard window outside `[1, 30]`.
    fn normalize(&mut self) {
        self.clipboard_guard_seconds = self
            .clipboard_guard_seconds
            .clamp(GUARD_SECONDS_MIN, GUARD_SECONDS_MAX);
    }
}

impl ClientConfig {
    pub fn load() -> Result<Self> {
        Self::load_from(&config_path())
    }

    pub fn save(&self) -> Result<()> {
        self.save_to(&config_path())
    }

    fn load_from(path: &Path) -> Result<Self> {
        let mut cfg = match fs::read_to_string(path) {
            Ok(text) => toml::from_str::<ClientConfig>(&text)
                .with_context(|| format!("parsing {}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        cfg.normalize();
        Ok(cfg)
    }

    fn save_to(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        let mut to_write = self.clone();
        to_write.normalize();
        let text = toml::to_string_pretty(&to_write).context("serializing config")?;
        fs::write(path, text).with_context(|| format!("writing {}", path.display()))
    }
}

fn config_path() -> PathBuf {
    let base = dirs::data_local_dir()
        .or_else(dirs::data_dir)
        .unwrap_or_else(std::env::temp_dir);
    base.join("rustclip").join("config.toml")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn load_from_missing_returns_defaults() {
        let dir = TempDir::new().unwrap();
        let cfg = ClientConfig::load_from(&dir.path().join("nope.toml")).unwrap();
        assert!(cfg.auto_sync_files);
        assert_eq!(cfg.auto_sync_max_bytes, DEFAULT_AUTO_BUNDLE_CAP_BYTES);
        assert!(cfg.notifications_enabled);
        assert!(!cfg.clipboard_guard_enabled);
        assert_eq!(cfg.clipboard_guard_seconds, 5);
        assert_eq!(cfg.recopy_hotkey, DEFAULT_RECOPY_HOTKEY);
    }

    #[test]
    fn round_trip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("cfg.toml");
        let cfg = ClientConfig {
            auto_sync_files: false,
            auto_sync_max_bytes: 42,
            notifications_enabled: false,
            clipboard_guard_enabled: true,
            clipboard_guard_seconds: 10,
            recopy_hotkey: "Ctrl+Shift+P".into(),
        };
        cfg.save_to(&path).unwrap();
        let loaded = ClientConfig::load_from(&path).unwrap();
        assert!(!loaded.auto_sync_files);
        assert_eq!(loaded.auto_sync_max_bytes, 42);
        assert!(!loaded.notifications_enabled);
        assert!(loaded.clipboard_guard_enabled);
        assert_eq!(loaded.clipboard_guard_seconds, 10);
        assert_eq!(loaded.recopy_hotkey, "Ctrl+Shift+P");
    }

    #[test]
    fn partial_config_falls_back_to_defaults() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("partial.toml");
        fs::write(&path, "auto_sync_files = false\n").unwrap();
        let loaded = ClientConfig::load_from(&path).unwrap();
        assert!(!loaded.auto_sync_files);
        assert_eq!(loaded.auto_sync_max_bytes, DEFAULT_AUTO_BUNDLE_CAP_BYTES);
        assert!(loaded.notifications_enabled);
        assert!(!loaded.clipboard_guard_enabled);
        assert_eq!(loaded.clipboard_guard_seconds, 5);
        assert_eq!(loaded.recopy_hotkey, DEFAULT_RECOPY_HOTKEY);
    }

    #[test]
    fn guard_seconds_clamped_high_on_load() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("over.toml");
        fs::write(&path, "clipboard_guard_seconds = 9999\n").unwrap();
        let loaded = ClientConfig::load_from(&path).unwrap();
        assert_eq!(loaded.clipboard_guard_seconds, GUARD_SECONDS_MAX);
    }

    #[test]
    fn guard_seconds_clamped_low_on_load() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("under.toml");
        fs::write(&path, "clipboard_guard_seconds = 0\n").unwrap();
        let loaded = ClientConfig::load_from(&path).unwrap();
        assert_eq!(loaded.clipboard_guard_seconds, GUARD_SECONDS_MIN);
    }
}
