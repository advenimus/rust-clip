use std::time::Duration;

use sqlx::FromRow;
use tokio::fs;
use tracing::{debug, warn};

use crate::{
    db::{DbPool, now_millis},
    settings::SettingsStore,
};

pub const SWEEP_INTERVAL: Duration = Duration::from_secs(5 * 60);

pub fn spawn(pool: DbPool, settings: SettingsStore) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(SWEEP_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let snap = settings.snapshot().await;
            if let Err(e) = sweep_once(&pool, snap.audit_retention_days).await {
                warn!(error = %e, "sweeper tick failed");
            }
        }
    });
}

pub async fn sweep_once(pool: &DbPool, audit_retention_days: u32) -> sqlx::Result<SweepReport> {
    let now = now_millis();

    let enrollments = sqlx::query(
        "DELETE FROM enrollment_tokens \
         WHERE consumed_at IS NOT NULL OR expires_at < ?",
    )
    .bind(now)
    .execute(pool)
    .await?
    .rows_affected();

    let clip_events = sqlx::query("DELETE FROM clip_events WHERE expires_at < ?")
        .bind(now)
        .execute(pool)
        .await?
        .rows_affected();

    // Remove the on-disk ciphertext before deleting the metadata row so a
    // crash between the two leaves orphaned files rather than orphaned rows.
    let expired_blobs: Vec<ExpiredBlob> =
        sqlx::query_as::<_, ExpiredBlob>("SELECT storage_path FROM blobs WHERE expires_at < ?")
            .bind(now)
            .fetch_all(pool)
            .await?;
    for blob in &expired_blobs {
        if let Err(e) = fs::remove_file(&blob.storage_path).await {
            if e.kind() != std::io::ErrorKind::NotFound {
                warn!(error = ?e, path = %blob.storage_path, "removing expired blob file");
            }
        }
    }
    let blobs = sqlx::query("DELETE FROM blobs WHERE expires_at < ?")
        .bind(now)
        .execute(pool)
        .await?
        .rows_affected();

    let audit_cutoff = now - (audit_retention_days as i64) * 24 * 60 * 60 * 1000;
    let audit_rows = sqlx::query("DELETE FROM audit_log WHERE created_at < ?")
        .bind(audit_cutoff)
        .execute(pool)
        .await?
        .rows_affected();

    let report = SweepReport {
        enrollments,
        clip_events,
        blobs,
        audit_rows,
    };
    debug!(?report, "sweeper completed");
    Ok(report)
}

#[derive(FromRow)]
struct ExpiredBlob {
    storage_path: String,
}

#[allow(dead_code)]
#[derive(Debug, Default)]
pub struct SweepReport {
    pub enrollments: u64,
    pub clip_events: u64,
    pub blobs: u64,
    pub audit_rows: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::test_pool;
    use uuid::Uuid;

    const FAR_FUTURE_RETENTION: u32 = 3650;

    #[tokio::test]
    async fn deletes_expired_enrollments() {
        let pool = test_pool().await;
        let user_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users (id, username, display_name, password_hash, is_admin, created_at) \
             VALUES (?, 'u', 'U', '', 0, 0)",
        )
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();

        // One expired (expires_at = 1), one still valid (expires_at = far future).
        let expired_id = Uuid::new_v4();
        let valid_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO enrollment_tokens (id, user_id, token_hash, expires_at, created_at) \
             VALUES (?, ?, '', 1, 0)",
        )
        .bind(expired_id)
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO enrollment_tokens (id, user_id, token_hash, expires_at, created_at) \
             VALUES (?, ?, '', ?, 0)",
        )
        .bind(valid_id)
        .bind(user_id)
        .bind(i64::MAX)
        .execute(&pool)
        .await
        .unwrap();

        let report = sweep_once(&pool, FAR_FUTURE_RETENTION).await.unwrap();
        assert_eq!(report.enrollments, 1);

        let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM enrollment_tokens")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(remaining, 1);
    }

    #[tokio::test]
    async fn sweeper_removes_expired_blob_file() {
        use tempfile::TempDir;

        let pool = test_pool().await;
        let tmp = TempDir::new().unwrap();
        let expired_path = tmp.path().join("expired.bin");
        tokio::fs::write(&expired_path, b"old").await.unwrap();
        let alive_path = tmp.path().join("alive.bin");
        tokio::fs::write(&alive_path, b"new").await.unwrap();

        sqlx::query(
            "INSERT INTO blobs (id, sha256, byte_length, storage_path, created_at, expires_at) \
             VALUES (?, '', 3, ?, 0, 1)",
        )
        .bind(Uuid::new_v4())
        .bind(expired_path.to_string_lossy().to_string())
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO blobs (id, sha256, byte_length, storage_path, created_at, expires_at) \
             VALUES (?, '', 3, ?, 0, ?)",
        )
        .bind(Uuid::new_v4())
        .bind(alive_path.to_string_lossy().to_string())
        .bind(i64::MAX)
        .execute(&pool)
        .await
        .unwrap();

        let report = sweep_once(&pool, FAR_FUTURE_RETENTION).await.unwrap();
        assert_eq!(report.blobs, 1);
        assert!(!expired_path.exists(), "expired blob file should be gone");
        assert!(alive_path.exists(), "live blob file should remain");
    }

    #[tokio::test]
    async fn deletes_consumed_enrollments() {
        let pool = test_pool().await;
        let user_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users (id, username, display_name, password_hash, is_admin, created_at) \
             VALUES (?, 'u', 'U', '', 0, 0)",
        )
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO enrollment_tokens (id, user_id, token_hash, expires_at, consumed_at, created_at) \
             VALUES (?, ?, '', ?, 1, 0)",
        )
        .bind(Uuid::new_v4())
        .bind(user_id)
        .bind(i64::MAX)
        .execute(&pool)
        .await
        .unwrap();

        let report = sweep_once(&pool, FAR_FUTURE_RETENTION).await.unwrap();
        assert_eq!(report.enrollments, 1);
    }

    #[tokio::test]
    async fn deletes_old_audit_rows() {
        let pool = test_pool().await;
        let now = now_millis();
        let one_day_ms: i64 = 24 * 60 * 60 * 1000;
        // Old row: created 10 days ago.
        sqlx::query(
            "INSERT INTO audit_log (event_type, details_json, created_at) \
             VALUES ('old_event', '{}', ?)",
        )
        .bind(now - 10 * one_day_ms)
        .execute(&pool)
        .await
        .unwrap();
        // Recent row: created 1 day ago.
        sqlx::query(
            "INSERT INTO audit_log (event_type, details_json, created_at) \
             VALUES ('recent_event', '{}', ?)",
        )
        .bind(now - one_day_ms)
        .execute(&pool)
        .await
        .unwrap();

        // Retention 5 days -> old_event drops, recent_event stays.
        let report = sweep_once(&pool, 5).await.unwrap();
        assert_eq!(report.audit_rows, 1);
        let kept: Vec<(String,)> =
            sqlx::query_as("SELECT event_type FROM audit_log ORDER BY created_at")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].0, "recent_event");
    }
}
