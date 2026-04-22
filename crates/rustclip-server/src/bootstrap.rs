use anyhow::{Context, Result};
use tracing::{info, warn};
use uuid::Uuid;

use crate::{
    config::Config,
    db::{DbPool, now_millis},
    password::hash_password,
};

/// Creates the bootstrap admin user from env vars if, and only if, the users
/// table is empty. Existing installations ignore the env vars to prevent
/// surprise overwrites on restart.
pub async fn maybe_bootstrap_admin(db: &DbPool, config: &Config) -> Result<()> {
    let user_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(db)
        .await
        .context("counting users")?;

    let (Some(username), Some(password)) = (&config.admin_username, &config.admin_password) else {
        if user_count == 0 {
            warn!(
                "no users in the database and RUSTCLIP_ADMIN_USERNAME/RUSTCLIP_ADMIN_PASSWORD not set. \
                 set them and restart to create the first admin."
            );
        }
        return Ok(());
    };

    if user_count > 0 {
        info!("users table already populated; ignoring RUSTCLIP_ADMIN_USERNAME/PASSWORD env vars");
        return Ok(());
    }

    let id = Uuid::new_v4();
    let password_hash = hash_password(password).context("hashing admin password")?;
    let now = now_millis();

    sqlx::query(
        "INSERT INTO users \
         (id, username, display_name, password_hash, content_salt, is_admin, created_at) \
         VALUES (?, ?, ?, ?, NULL, 1, ?)",
    )
    .bind(id)
    .bind(username)
    .bind(username)
    .bind(password_hash)
    .bind(now)
    .execute(db)
    .await
    .context("creating bootstrap admin user")?;

    info!(%username, "bootstrap admin user created");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::test_pool;
    use std::{net::SocketAddr, path::PathBuf};

    fn test_config(admin_user: Option<&str>, admin_pw: Option<&str>) -> Config {
        Config {
            bind_addr: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            data_dir: PathBuf::from("/tmp"),
            public_url: "http://localhost".into(),
            admin_username: admin_user.map(String::from),
            admin_password: admin_pw.map(String::from),
            max_payload_bytes: 0,
            offline_ttl_hours: 0,
            trusted_proxies: Vec::new(),
            metrics_token: None,
        }
    }

    #[tokio::test]
    async fn creates_admin_on_empty_db() {
        let pool = test_pool().await;
        maybe_bootstrap_admin(&pool, &test_config(Some("root"), Some("pw")))
            .await
            .unwrap();
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE is_admin = 1")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn skips_when_users_already_exist() {
        let pool = test_pool().await;
        // Preload a non-admin user so the table is non-empty.
        let id = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users (id, username, display_name, password_hash, is_admin, created_at) \
             VALUES (?, 'bob', 'Bob', '', 0, 0)",
        )
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();

        maybe_bootstrap_admin(&pool, &test_config(Some("root"), Some("pw")))
            .await
            .unwrap();
        let admin_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM users WHERE is_admin = 1 AND username = 'root'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(admin_count, 0, "admin env vars should be ignored");
    }

    #[tokio::test]
    async fn no_op_without_env_vars() {
        let pool = test_pool().await;
        maybe_bootstrap_admin(&pool, &test_config(None, None))
            .await
            .unwrap();
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }
}
