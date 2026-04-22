use axum::{
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
};
use sqlx::FromRow;
use uuid::Uuid;

use crate::{api::ApiError, db::now_millis, state::AppState, tokens::hash_token};

pub struct DeviceAuth {
    pub device_id: Uuid,
    pub user_id: Uuid,
    pub username: String,
    pub display_name: String,
    pub device_name: String,
    pub platform: String,
    pub created_at: i64,
    pub last_seen_at: Option<i64>,
}

#[derive(FromRow)]
struct DeviceAuthRow {
    device_id: Uuid,
    user_id: Uuid,
    username: String,
    display_name: String,
    device_name: String,
    platform: String,
    created_at: i64,
    last_seen_at: Option<i64>,
}

impl FromRequestParts<AppState> for DeviceAuth {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| ApiError::unauthorized("missing authorization header"))?;
        let token = header
            .strip_prefix("Bearer ")
            .ok_or_else(|| ApiError::unauthorized("expected 'Bearer <token>' authorization"))?;
        if token.is_empty() {
            return Err(ApiError::unauthorized("empty bearer token"));
        }
        let token_hash = hash_token(token);

        let now = now_millis();
        // M5: reject expired tokens. `expires_at` is NULL for devices
        // enrolled before migration 0003; those still work until the
        // next refresh rotates them onto a TTL.
        let row = sqlx::query_as::<_, DeviceAuthRow>(
            "SELECT d.id AS device_id, d.user_id, u.username, u.display_name, \
                    d.device_name, d.platform, d.created_at, d.last_seen_at \
             FROM devices d JOIN users u ON u.id = d.user_id \
             WHERE d.device_token_hash = ? \
               AND d.revoked_at IS NULL \
               AND u.disabled_at IS NULL \
               AND (d.expires_at IS NULL OR d.expires_at > ?)",
        )
        .bind(&token_hash)
        .bind(now)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "token is invalid, revoked, or expired",
            )
        })?;
        // Update last_seen best-effort; don't fail the request on a transient write error.
        if let Err(e) = sqlx::query("UPDATE devices SET last_seen_at = ? WHERE id = ?")
            .bind(now)
            .bind(row.device_id)
            .execute(&state.db)
            .await
        {
            tracing::warn!(error = ?e, device_id = %row.device_id, "failed to update last_seen_at");
        }

        Ok(DeviceAuth {
            device_id: row.device_id,
            user_id: row.user_id,
            username: row.username,
            display_name: row.display_name,
            device_name: row.device_name,
            platform: row.platform,
            created_at: row.created_at,
            last_seen_at: row.last_seen_at,
        })
    }
}
