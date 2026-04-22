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

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            auto_sync_files: default_auto_sync_files(),
            auto_sync_max_bytes: default_auto_sync_max_bytes(),
            notifications_enabled: default_notifications_enabled(),
        }
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
        match fs::read_to_string(path) {
            Ok(text) => toml::from_str::<ClientConfig>(&text)
                .with_context(|| format!("parsing {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    fn save_to(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        let text = toml::to_string_pretty(self).context("serializing config")?;
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
    }

    #[test]
    fn round_trip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("cfg.toml");
        let cfg = ClientConfig {
            auto_sync_files: false,
            auto_sync_max_bytes: 42,
            notifications_enabled: false,
        };
        cfg.save_to(&path).unwrap();
        let loaded = ClientConfig::load_from(&path).unwrap();
        assert!(!loaded.auto_sync_files);
        assert_eq!(loaded.auto_sync_max_bytes, 42);
        assert!(!loaded.notifications_enabled);
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
    }
}
