#![allow(dead_code)]
// Row structs mirror the full schema so downstream modules and future phases
// can deserialize without reshaping. Some fields are unused in Phase 1.

use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct UserRow {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub password_hash: String,
    pub content_salt: Option<Vec<u8>>,
    pub is_admin: i64,
    pub created_at: i64,
    pub disabled_at: Option<i64>,
}

impl UserRow {
    pub fn is_admin(&self) -> bool {
        self.is_admin != 0
    }
    pub fn is_active(&self) -> bool {
        self.disabled_at.is_none()
    }
}

#[derive(Debug, Clone, FromRow)]
pub struct DeviceRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub device_name: String,
    pub platform: String,
    pub last_seen_at: Option<i64>,
    pub created_at: i64,
    pub revoked_at: Option<i64>,
}

#[derive(Debug, Clone, FromRow)]
pub struct EnrollmentTokenRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub expires_at: i64,
    pub consumed_at: Option<i64>,
    pub created_at: i64,
}

#[derive(Debug, Clone, FromRow)]
pub struct AuditLogRow {
    pub id: i64,
    pub actor_user_id: Option<Uuid>,
    pub actor_device_id: Option<Uuid>,
    pub event_type: String,
    pub details_json: String,
    pub ip_addr: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: i64,
}
