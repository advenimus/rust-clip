use std::time::Duration;

use tracing::{debug, warn};

use crate::db::{DbPool, now_millis};

pub const SWEEP_INTERVAL: Duration = Duration::from_secs(5 * 60);

pub fn spawn(pool: DbPool) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(SWEEP_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            if let Err(e) = sweep_once(&pool).await {
                warn!(error = %e, "sweeper tick failed");
            }
        }
    });
}

pub async fn sweep_once(pool: &DbPool) -> sqlx::Result<SweepReport> {
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

    let blobs = sqlx::query("DELETE FROM blobs WHERE expires_at < ?")
        .bind(now)
        .execute(pool)
        .await?
        .rows_affected();

    let report = SweepReport {
        enrollments,
        clip_events,
        blobs,
    };
    debug!(?report, "sweeper completed");
    Ok(report)
}

#[allow(dead_code)]
#[derive(Debug, Default)]
pub struct SweepReport {
    pub enrollments: u64,
    pub clip_events: u64,
    pub blobs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::test_pool;
    use uuid::Uuid;

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

        let report = sweep_once(&pool).await.unwrap();
        assert_eq!(report.enrollments, 1);

        let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM enrollment_tokens")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(remaining, 1);
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

        let report = sweep_once(&pool).await.unwrap();
        assert_eq!(report.enrollments, 1);
    }
}
