use serde::Serialize;
use sqlx::Executor;
use uuid::Uuid;

use crate::db::{DbPool, now_millis};

pub const EVENT_ADMIN_LOGIN: &str = "admin_login";
pub const EVENT_ADMIN_LOGIN_FAILED: &str = "admin_login_failed";
pub const EVENT_ADMIN_LOGOUT: &str = "admin_logout";
pub const EVENT_USER_CREATED: &str = "user_created";
pub const EVENT_USER_DELETED: &str = "user_deleted";
pub const EVENT_ENROLLMENT_TOKEN_ISSUED: &str = "enrollment_token_issued";
pub const EVENT_DEVICE_REVOKED: &str = "device_revoked";
pub const EVENT_DEVICE_REGISTERED: &str = "device_registered";
pub const EVENT_DEVICE_LOGOUT: &str = "device_logout";
pub const EVENT_USER_PASSWORD_RESET: &str = "user_password_reset";

pub struct AuditEntry<'a> {
    pub actor_user_id: Option<Uuid>,
    pub actor_device_id: Option<Uuid>,
    pub event_type: &'a str,
    pub ip_addr: Option<&'a str>,
    pub user_agent: Option<&'a str>,
}

pub async fn record<E: Serialize>(
    pool: &DbPool,
    entry: AuditEntry<'_>,
    details: &E,
) -> sqlx::Result<()> {
    let details_json = serde_json::to_string(details).unwrap_or_else(|_| "{}".into());
    let created_at = now_millis();
    pool.execute(
        sqlx::query(
            "INSERT INTO audit_log \
             (actor_user_id, actor_device_id, event_type, details_json, ip_addr, user_agent, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(entry.actor_user_id)
        .bind(entry.actor_device_id)
        .bind(entry.event_type)
        .bind(details_json)
        .bind(entry.ip_addr)
        .bind(entry.user_agent)
        .bind(created_at),
    )
    .await?;
    Ok(())
}
