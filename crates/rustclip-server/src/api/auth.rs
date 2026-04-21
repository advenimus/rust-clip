use axum::{Json, extract::State, http::HeaderMap};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use rustclip_shared::rest::{EnrollRequest, EnrollResponse, LoginRequest, LoginResponse};
use sqlx::FromRow;
use uuid::Uuid;

use crate::{
    api::{ApiError, device_auth::DeviceAuth},
    audit,
    db::now_millis,
    middleware::client_meta,
    password::{hash_password, verify_password},
    state::AppState,
    tokens,
};

const CONTENT_SALT_BYTES: usize = 32;
const VALID_PLATFORMS: &[&str] = &["windows", "macos", "linux"];

fn validate_platform(platform: &str) -> Result<(), ApiError> {
    if VALID_PLATFORMS.contains(&platform) {
        Ok(())
    } else {
        Err(ApiError::validation(format!(
            "platform must be one of {VALID_PLATFORMS:?}"
        )))
    }
}

#[derive(FromRow)]
struct EnrollRow {
    enrollment_id: Uuid,
    expires_at: i64,
    consumed_at: Option<i64>,
    user_id: Uuid,
    username: String,
    display_name: String,
    existing_password_hash: String,
}

pub async fn enroll(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<EnrollRequest>,
) -> Result<Json<EnrollResponse>, ApiError> {
    validate_platform(&req.platform)?;
    if req.password.len() < 8 {
        return Err(ApiError::validation(
            "password must be at least 8 characters",
        ));
    }
    if req.device_name.trim().is_empty() {
        return Err(ApiError::validation("device_name is required"));
    }
    let content_salt = BASE64
        .decode(req.content_salt_b64.as_bytes())
        .map_err(|_| ApiError::validation("content_salt_b64 is not valid base64"))?;
    if content_salt.len() != CONTENT_SALT_BYTES {
        return Err(ApiError::validation(format!(
            "content_salt must be {CONTENT_SALT_BYTES} bytes"
        )));
    }

    let token_hash = tokens::hash_token(&req.enrollment_token);
    let now = now_millis();

    let row = sqlx::query_as::<_, EnrollRow>(
        "SELECT e.id AS enrollment_id, \
                e.expires_at, e.consumed_at, \
                u.id AS user_id, u.username, u.display_name, \
                u.password_hash AS existing_password_hash \
         FROM enrollment_tokens e JOIN users u ON u.id = e.user_id \
         WHERE e.token_hash = ?",
    )
    .bind(&token_hash)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::unauthorized("enrollment token not recognized"))?;

    if row.consumed_at.is_some() {
        return Err(ApiError::unauthorized(
            "enrollment token has already been used",
        ));
    }
    if row.expires_at < now {
        return Err(ApiError::unauthorized("enrollment token has expired"));
    }
    if !row.existing_password_hash.is_empty() {
        return Err(ApiError::validation(
            "user already enrolled; use /auth/login for additional devices",
        ));
    }

    let password_hash =
        hash_password(&req.password).map_err(|_| ApiError::internal("failed to hash password"))?;
    let device_token =
        tokens::generate_token().map_err(|_| ApiError::internal("failed to generate token"))?;
    let device_id = Uuid::new_v4();

    let mut tx = state.db.begin().await?;

    sqlx::query(
        "UPDATE users SET password_hash = ?, content_salt = ? \
         WHERE id = ? AND password_hash = ''",
    )
    .bind(&password_hash)
    .bind(&content_salt)
    .bind(row.user_id)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        "INSERT INTO devices \
         (id, user_id, device_name, platform, device_token_hash, created_at) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(device_id)
    .bind(row.user_id)
    .bind(req.device_name.trim())
    .bind(&req.platform)
    .bind(&device_token.hash)
    .bind(now)
    .execute(&mut *tx)
    .await?;

    sqlx::query("UPDATE enrollment_tokens SET consumed_at = ? WHERE id = ?")
        .bind(now)
        .bind(row.enrollment_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    let (ip, ua) = client_meta(&headers);
    let _ = audit::record(
        &state.db,
        audit::AuditEntry {
            actor_user_id: Some(row.user_id),
            actor_device_id: Some(device_id),
            event_type: audit::EVENT_DEVICE_REGISTERED,
            ip_addr: ip.as_deref(),
            user_agent: ua.as_deref(),
        },
        &serde_json::json!({
            "device_name": req.device_name,
            "platform": req.platform,
            "via": "enrollment",
        }),
    )
    .await;

    Ok(Json(EnrollResponse {
        device_token: device_token.plaintext,
        user_id: row.user_id,
        device_id,
        username: row.username,
        display_name: row.display_name,
    }))
}

#[derive(FromRow)]
struct LoginRow {
    id: Uuid,
    username: String,
    display_name: String,
    password_hash: String,
    content_salt: Option<Vec<u8>>,
    disabled_at: Option<i64>,
}

pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    validate_platform(&req.platform)?;
    if req.device_name.trim().is_empty() {
        return Err(ApiError::validation("device_name is required"));
    }

    let row = sqlx::query_as::<_, LoginRow>(
        "SELECT id, username, display_name, password_hash, content_salt, disabled_at \
         FROM users WHERE username = ?",
    )
    .bind(&req.username)
    .fetch_optional(&state.db)
    .await?;

    let row = row.ok_or_else(|| ApiError::unauthorized("invalid username or password"))?;
    if row.disabled_at.is_some() {
        return Err(ApiError::unauthorized("account is disabled"));
    }
    if row.password_hash.is_empty() {
        return Err(ApiError::unauthorized(
            "account has not been enrolled yet; use the enrollment token",
        ));
    }
    let ok = verify_password(&req.password, &row.password_hash).unwrap_or(false);
    if !ok {
        return Err(ApiError::unauthorized("invalid username or password"));
    }
    let content_salt = row
        .content_salt
        .ok_or_else(|| ApiError::internal("user missing content salt"))?;

    let device_token =
        tokens::generate_token().map_err(|_| ApiError::internal("failed to generate token"))?;
    let device_id = Uuid::new_v4();
    let now = now_millis();

    sqlx::query(
        "INSERT INTO devices \
         (id, user_id, device_name, platform, device_token_hash, created_at) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(device_id)
    .bind(row.id)
    .bind(req.device_name.trim())
    .bind(&req.platform)
    .bind(&device_token.hash)
    .bind(now)
    .execute(&state.db)
    .await?;

    let (ip, ua) = client_meta(&headers);
    let _ = audit::record(
        &state.db,
        audit::AuditEntry {
            actor_user_id: Some(row.id),
            actor_device_id: Some(device_id),
            event_type: audit::EVENT_DEVICE_REGISTERED,
            ip_addr: ip.as_deref(),
            user_agent: ua.as_deref(),
        },
        &serde_json::json!({
            "device_name": req.device_name,
            "platform": req.platform,
            "via": "login",
        }),
    )
    .await;

    Ok(Json(LoginResponse {
        device_token: device_token.plaintext,
        user_id: row.id,
        device_id,
        username: row.username,
        display_name: row.display_name,
        content_salt_b64: BASE64.encode(&content_salt),
    }))
}

pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    auth: DeviceAuth,
) -> Result<(), ApiError> {
    let now = now_millis();
    sqlx::query("UPDATE devices SET revoked_at = ? WHERE id = ?")
        .bind(now)
        .bind(auth.device_id)
        .execute(&state.db)
        .await?;

    let (ip, ua) = client_meta(&headers);
    let _ = audit::record(
        &state.db,
        audit::AuditEntry {
            actor_user_id: Some(auth.user_id),
            actor_device_id: Some(auth.device_id),
            event_type: audit::EVENT_DEVICE_LOGOUT,
            ip_addr: ip.as_deref(),
            user_agent: ua.as_deref(),
        },
        &serde_json::json!({}),
    )
    .await;

    Ok(())
}
