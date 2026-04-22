//! Runtime-tunable settings persisted in the `settings` table.
//!
//! The boot-time [`Config`] supplies defaults from env. Admins can override
//! individual knobs at runtime through the settings page; overrides are
//! written to the DB and held in an in-memory snapshot so hot paths don't
//! hit SQLite on every request.

use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::RwLock;

use crate::{
    config::Config,
    db::{DbPool, now_millis},
};

pub const KEY_MAX_PAYLOAD_BYTES: &str = "max_payload_bytes";
pub const KEY_OFFLINE_TTL_HOURS: &str = "offline_ttl_hours";
pub const KEY_AUDIT_RETENTION_DAYS: &str = "audit_retention_days";
pub const KEY_UPDATE_CHECK_ENABLED: &str = "update_check_enabled";

pub const DEFAULT_AUDIT_RETENTION_DAYS: u32 = 90;
pub const DEFAULT_UPDATE_CHECK_ENABLED: bool = true;

pub const MIN_OFFLINE_TTL_HOURS: u32 = 1;
pub const MAX_OFFLINE_TTL_HOURS: u32 = 24 * 365;
pub const MIN_PAYLOAD_BYTES: u64 = 64 * 1024;
pub const MAX_PAYLOAD_BYTES: u64 = 1024 * 1024 * 1024;
pub const MIN_AUDIT_RETENTION_DAYS: u32 = 1;
pub const MAX_AUDIT_RETENTION_DAYS: u32 = 3650;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeSettings {
    pub max_payload_bytes: u64,
    pub offline_ttl_hours: u32,
    pub audit_retention_days: u32,
    pub update_check_enabled: bool,
}

impl RuntimeSettings {
    fn from_config(config: &Config) -> Self {
        Self {
            max_payload_bytes: config.max_payload_bytes,
            offline_ttl_hours: config.offline_ttl_hours,
            audit_retention_days: DEFAULT_AUDIT_RETENTION_DAYS,
            update_check_enabled: DEFAULT_UPDATE_CHECK_ENABLED,
        }
    }
}

#[derive(Clone)]
pub struct SettingsStore {
    inner: Arc<RwLock<RuntimeSettings>>,
}

impl SettingsStore {
    pub async fn load(pool: &DbPool, config: &Config) -> Result<Self> {
        let mut s = RuntimeSettings::from_config(config);
        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT key, value FROM settings WHERE key IN (?, ?, ?, ?)")
                .bind(KEY_MAX_PAYLOAD_BYTES)
                .bind(KEY_OFFLINE_TTL_HOURS)
                .bind(KEY_AUDIT_RETENTION_DAYS)
                .bind(KEY_UPDATE_CHECK_ENABLED)
                .fetch_all(pool)
                .await
                .context("loading runtime settings")?;
        for (k, v) in rows {
            match k.as_str() {
                KEY_MAX_PAYLOAD_BYTES => {
                    if let Ok(n) = v.parse::<u64>() {
                        s.max_payload_bytes = n;
                    }
                }
                KEY_OFFLINE_TTL_HOURS => {
                    if let Ok(n) = v.parse::<u32>() {
                        s.offline_ttl_hours = n;
                    }
                }
                KEY_AUDIT_RETENTION_DAYS => {
                    if let Ok(n) = v.parse::<u32>() {
                        s.audit_retention_days = n;
                    }
                }
                KEY_UPDATE_CHECK_ENABLED => {
                    if let Ok(b) = v.parse::<bool>() {
                        s.update_check_enabled = b;
                    }
                }
                _ => {}
            }
        }
        Ok(Self {
            inner: Arc::new(RwLock::new(s)),
        })
    }

    #[cfg(test)]
    pub fn from_values(s: RuntimeSettings) -> Self {
        Self {
            inner: Arc::new(RwLock::new(s)),
        }
    }

    pub async fn snapshot(&self) -> RuntimeSettings {
        *self.inner.read().await
    }

    pub async fn update(&self, pool: &DbPool, new: RuntimeSettings) -> Result<()> {
        let now = now_millis();
        let pairs = [
            (KEY_MAX_PAYLOAD_BYTES, new.max_payload_bytes.to_string()),
            (KEY_OFFLINE_TTL_HOURS, new.offline_ttl_hours.to_string()),
            (
                KEY_AUDIT_RETENTION_DAYS,
                new.audit_retention_days.to_string(),
            ),
            (
                KEY_UPDATE_CHECK_ENABLED,
                new.update_check_enabled.to_string(),
            ),
        ];
        let mut tx = pool.begin().await?;
        for (k, v) in &pairs {
            sqlx::query(
                "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) \
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            )
            .bind(k)
            .bind(v)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        *self.inner.write().await = new;
        Ok(())
    }
}

pub fn validate(values: &RuntimeSettings) -> Result<(), String> {
    if !(MIN_PAYLOAD_BYTES..=MAX_PAYLOAD_BYTES).contains(&values.max_payload_bytes) {
        return Err(format!(
            "max payload bytes must be between {MIN_PAYLOAD_BYTES} and {MAX_PAYLOAD_BYTES}"
        ));
    }
    if !(MIN_OFFLINE_TTL_HOURS..=MAX_OFFLINE_TTL_HOURS).contains(&values.offline_ttl_hours) {
        return Err(format!(
            "offline TTL hours must be between {MIN_OFFLINE_TTL_HOURS} and {MAX_OFFLINE_TTL_HOURS}"
        ));
    }
    if !(MIN_AUDIT_RETENTION_DAYS..=MAX_AUDIT_RETENTION_DAYS).contains(&values.audit_retention_days)
    {
        return Err(format!(
            "audit retention days must be between {MIN_AUDIT_RETENTION_DAYS} and {MAX_AUDIT_RETENTION_DAYS}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::test_pool;
    use std::{net::SocketAddr, path::PathBuf};

    fn test_config() -> Config {
        Config {
            bind_addr: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            data_dir: PathBuf::from("/tmp"),
            public_url: "http://localhost".into(),
            admin_username: None,
            admin_password: None,
            max_payload_bytes: 10 * 1024 * 1024,
            offline_ttl_hours: 24,
        }
    }

    #[tokio::test]
    async fn load_uses_config_defaults_when_empty() {
        let pool = test_pool().await;
        let config = test_config();
        let store = SettingsStore::load(&pool, &config).await.unwrap();
        let snap = store.snapshot().await;
        assert_eq!(snap.max_payload_bytes, 10 * 1024 * 1024);
        assert_eq!(snap.offline_ttl_hours, 24);
        assert_eq!(snap.audit_retention_days, DEFAULT_AUDIT_RETENTION_DAYS);
        assert_eq!(snap.update_check_enabled, DEFAULT_UPDATE_CHECK_ENABLED);
    }

    #[tokio::test]
    async fn update_persists_and_reloads() {
        let pool = test_pool().await;
        let config = test_config();
        let store = SettingsStore::load(&pool, &config).await.unwrap();

        let new = RuntimeSettings {
            max_payload_bytes: 50 * 1024 * 1024,
            offline_ttl_hours: 48,
            audit_retention_days: 30,
            update_check_enabled: false,
        };
        store.update(&pool, new).await.unwrap();

        let snap = store.snapshot().await;
        assert_eq!(snap, new);

        let store2 = SettingsStore::load(&pool, &config).await.unwrap();
        assert_eq!(store2.snapshot().await, new);
    }

    #[test]
    fn validate_rejects_out_of_range() {
        assert!(
            validate(&RuntimeSettings {
                max_payload_bytes: 0,
                offline_ttl_hours: 24,
                audit_retention_days: 30,
                update_check_enabled: true,
            })
            .is_err()
        );
        assert!(
            validate(&RuntimeSettings {
                max_payload_bytes: 10 * 1024 * 1024,
                offline_ttl_hours: 0,
                audit_retention_days: 30,
                update_check_enabled: true,
            })
            .is_err()
        );
        assert!(
            validate(&RuntimeSettings {
                max_payload_bytes: 10 * 1024 * 1024,
                offline_ttl_hours: 24,
                audit_retention_days: 0,
                update_check_enabled: true,
            })
            .is_err()
        );
        assert!(
            validate(&RuntimeSettings {
                max_payload_bytes: 10 * 1024 * 1024,
                offline_ttl_hours: 24,
                audit_retention_days: 30,
                update_check_enabled: true,
            })
            .is_ok()
        );
    }
}
