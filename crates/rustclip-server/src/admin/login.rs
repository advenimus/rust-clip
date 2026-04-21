use askama::Template;
use axum::{
    Form,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
};
use serde::Deserialize;
use sqlx::FromRow;
use tower_sessions::Session;
use uuid::Uuid;

use crate::{
    audit,
    error::{AppError, AppResult},
    middleware::{ADMIN_USER_KEY, AdminUser, client_meta},
    password::verify_password,
    state::AppState,
};

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate<'a> {
    error: Option<&'a str>,
}

pub async fn show() -> AppResult<Response> {
    let tmpl = LoginTemplate { error: None };
    Ok(Html(tmpl.render()?).into_response())
}

#[derive(Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
}

#[derive(FromRow)]
struct LoginRow {
    id: Uuid,
    password_hash: String,
    is_admin: i64,
    disabled_at: Option<i64>,
}

pub async fn submit(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> AppResult<Response> {
    let (ip, ua) = client_meta(&headers);

    let row = sqlx::query_as::<_, LoginRow>(
        "SELECT id, password_hash, is_admin, disabled_at FROM users WHERE username = ?",
    )
    .bind(&form.username)
    .fetch_optional(&state.db)
    .await?;

    let matched = row.as_ref().and_then(|r| {
        (r.is_admin == 1 && r.disabled_at.is_none())
            .then(|| verify_password(&form.password, &r.password_hash).unwrap_or(false))
            .filter(|ok| *ok)
            .map(|_| r.id)
    });

    let Some(user_id) = matched else {
        let _ = audit::record(
            &state.db,
            audit::AuditEntry {
                actor_user_id: None,
                actor_device_id: None,
                event_type: audit::EVENT_ADMIN_LOGIN_FAILED,
                ip_addr: ip.as_deref(),
                user_agent: ua.as_deref(),
            },
            &serde_json::json!({ "username": form.username }),
        )
        .await;
        let tmpl = LoginTemplate {
            error: Some("Invalid username or password."),
        };
        return Ok((StatusCode::UNAUTHORIZED, Html(tmpl.render()?)).into_response());
    };

    session
        .insert(ADMIN_USER_KEY, user_id)
        .await
        .map_err(|e| AppError::Session(e.to_string()))?;

    audit::record(
        &state.db,
        audit::AuditEntry {
            actor_user_id: Some(user_id),
            actor_device_id: None,
            event_type: audit::EVENT_ADMIN_LOGIN,
            ip_addr: ip.as_deref(),
            user_agent: ua.as_deref(),
        },
        &serde_json::json!({}),
    )
    .await?;

    Ok(Redirect::to("/admin/").into_response())
}

pub async fn logout(
    State(state): State<AppState>,
    session: Session,
    admin: AdminUser,
    headers: HeaderMap,
) -> AppResult<Redirect> {
    let (ip, ua) = client_meta(&headers);
    audit::record(
        &state.db,
        audit::AuditEntry {
            actor_user_id: Some(admin.id),
            actor_device_id: None,
            event_type: audit::EVENT_ADMIN_LOGOUT,
            ip_addr: ip.as_deref(),
            user_agent: ua.as_deref(),
        },
        &serde_json::json!({}),
    )
    .await?;
    session
        .flush()
        .await
        .map_err(|e| AppError::Session(e.to_string()))?;
    Ok(Redirect::to("/admin/login"))
}
