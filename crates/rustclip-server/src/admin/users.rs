use askama::Template;
use axum::{
    Form,
    extract::{Path, State},
    http::HeaderMap,
    response::{Html, IntoResponse, Redirect, Response},
};
use serde::Deserialize;
use sqlx::FromRow;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{
    admin::dashboard::format_millis,
    audit,
    db::now_millis,
    error::{AppError, AppResult},
    middleware::{AdminUser, client_meta},
    state::AppState,
    tokens,
};

const ENROLLMENT_TTL_DAYS: i64 = 30;

#[derive(FromRow)]
struct UserListRow {
    id: Uuid,
    username: String,
    display_name: String,
    is_admin: i64,
    created_at: i64,
    disabled_at: Option<i64>,
    device_count: i64,
}

pub struct UserRowView {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub is_admin: bool,
    pub is_active: bool,
    pub created_at: String,
    pub device_count: i64,
}

#[derive(Template)]
#[template(path = "users.html")]
struct UsersTemplate<'a> {
    admin_display_name: &'a str,
    users: Vec<UserRowView>,
}

pub async fn list(State(state): State<AppState>, admin: AdminUser) -> AppResult<Response> {
    let rows = sqlx::query_as::<_, UserListRow>(
        "SELECT u.id, u.username, u.display_name, u.is_admin, u.created_at, u.disabled_at, \
         (SELECT COUNT(*) FROM devices d WHERE d.user_id = u.id AND d.revoked_at IS NULL) AS device_count \
         FROM users u \
         ORDER BY u.created_at DESC",
    )
    .fetch_all(&state.db)
    .await?;

    let users = rows
        .into_iter()
        .map(|r| UserRowView {
            id: r.id,
            username: r.username,
            display_name: r.display_name,
            is_admin: r.is_admin != 0,
            is_active: r.disabled_at.is_none(),
            created_at: format_millis(r.created_at),
            device_count: r.device_count,
        })
        .collect();

    let tmpl = UsersTemplate {
        admin_display_name: &admin.display_name,
        users,
    };
    Ok(Html(tmpl.render()?).into_response())
}

#[derive(Deserialize)]
pub struct CreateUserForm {
    pub username: String,
    pub display_name: String,
}

#[derive(Template)]
#[template(path = "user_created.html")]
struct UserCreatedTemplate<'a> {
    admin_display_name: &'a str,
    username: &'a str,
    display_name: &'a str,
    enrollment_token: &'a str,
    expires_at: &'a str,
    public_url: &'a str,
}

pub async fn create(
    State(state): State<AppState>,
    admin: AdminUser,
    headers: HeaderMap,
    Form(form): Form<CreateUserForm>,
) -> AppResult<Response> {
    let username = form.username.trim();
    let display_name = form.display_name.trim();
    if username.is_empty() {
        return Err(AppError::Validation("username is required".into()));
    }
    if display_name.is_empty() {
        return Err(AppError::Validation("display name is required".into()));
    }

    let mut tx = state.db.begin().await?;

    let user_id = Uuid::new_v4();
    let now = now_millis();
    let res = sqlx::query(
        "INSERT INTO users \
         (id, username, display_name, password_hash, content_salt, is_admin, created_at) \
         VALUES (?, ?, ?, '', NULL, 0, ?)",
    )
    .bind(user_id)
    .bind(username)
    .bind(display_name)
    .bind(now)
    .execute(&mut *tx)
    .await;

    match res {
        Ok(_) => {}
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return Err(AppError::Validation(format!(
                "username '{username}' already exists"
            )));
        }
        Err(e) => return Err(e.into()),
    }

    let generated = tokens::generate_token().map_err(AppError::internal)?;
    let enrollment_id = Uuid::new_v4();
    let expires_at =
        (OffsetDateTime::now_utc() + Duration::days(ENROLLMENT_TTL_DAYS)).unix_timestamp() * 1000;

    sqlx::query(
        "INSERT INTO enrollment_tokens \
         (id, user_id, token_hash, expires_at, created_at) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(enrollment_id)
    .bind(user_id)
    .bind(&generated.hash)
    .bind(expires_at)
    .bind(now)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    let (ip, ua) = client_meta(&headers);
    audit::record(
        &state.db,
        audit::AuditEntry {
            actor_user_id: Some(admin.id),
            actor_device_id: None,
            event_type: audit::EVENT_USER_CREATED,
            ip_addr: ip.as_deref(),
            user_agent: ua.as_deref(),
        },
        &serde_json::json!({ "user_id": user_id, "username": username }),
    )
    .await?;
    audit::record(
        &state.db,
        audit::AuditEntry {
            actor_user_id: Some(admin.id),
            actor_device_id: None,
            event_type: audit::EVENT_ENROLLMENT_TOKEN_ISSUED,
            ip_addr: ip.as_deref(),
            user_agent: ua.as_deref(),
        },
        &serde_json::json!({ "user_id": user_id, "expires_at": expires_at }),
    )
    .await?;

    let tmpl = UserCreatedTemplate {
        admin_display_name: &admin.display_name,
        username,
        display_name,
        enrollment_token: &generated.plaintext,
        expires_at: &format_millis(expires_at),
        public_url: &state.config.public_url,
    };
    Ok(Html(tmpl.render()?).into_response())
}

pub async fn delete(
    State(state): State<AppState>,
    admin: AdminUser,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> AppResult<Redirect> {
    if id == admin.id {
        return Err(AppError::Validation(
            "you cannot delete the currently logged in admin".into(),
        ));
    }
    let result = sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(id)
        .execute(&state.db)
        .await?;
    if result.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    let (ip, ua) = client_meta(&headers);
    audit::record(
        &state.db,
        audit::AuditEntry {
            actor_user_id: Some(admin.id),
            actor_device_id: None,
            event_type: audit::EVENT_USER_DELETED,
            ip_addr: ip.as_deref(),
            user_agent: ua.as_deref(),
        },
        &serde_json::json!({ "user_id": id }),
    )
    .await?;
    Ok(Redirect::to("/admin/users"))
}

pub async fn reset_enrollment(
    State(state): State<AppState>,
    admin: AdminUser,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> AppResult<Response> {
    let user = sqlx::query_as::<_, (String, String)>(
        "SELECT username, display_name FROM users WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::NotFound)?;

    let mut tx = state.db.begin().await?;
    sqlx::query("DELETE FROM enrollment_tokens WHERE user_id = ? AND consumed_at IS NULL")
        .bind(id)
        .execute(&mut *tx)
        .await?;

    let generated = tokens::generate_token().map_err(AppError::internal)?;
    let enrollment_id = Uuid::new_v4();
    let now = now_millis();
    let expires_at =
        (OffsetDateTime::now_utc() + Duration::days(ENROLLMENT_TTL_DAYS)).unix_timestamp() * 1000;

    sqlx::query(
        "INSERT INTO enrollment_tokens \
         (id, user_id, token_hash, expires_at, created_at) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(enrollment_id)
    .bind(id)
    .bind(&generated.hash)
    .bind(expires_at)
    .bind(now)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    let (ip, ua) = client_meta(&headers);
    audit::record(
        &state.db,
        audit::AuditEntry {
            actor_user_id: Some(admin.id),
            actor_device_id: None,
            event_type: audit::EVENT_ENROLLMENT_TOKEN_ISSUED,
            ip_addr: ip.as_deref(),
            user_agent: ua.as_deref(),
        },
        &serde_json::json!({ "user_id": id, "expires_at": expires_at, "reissued": true }),
    )
    .await?;

    let tmpl = UserCreatedTemplate {
        admin_display_name: &admin.display_name,
        username: &user.0,
        display_name: &user.1,
        enrollment_token: &generated.plaintext,
        expires_at: &format_millis(expires_at),
        public_url: &state.config.public_url,
    };
    Ok(Html(tmpl.render()?).into_response())
}
