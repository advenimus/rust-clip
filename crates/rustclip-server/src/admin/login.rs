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
    admin::csrf,
    audit,
    error::{AppError, AppResult},
    middleware::{ADMIN_USER_KEY, AdminUser, client_meta},
    password::verify_password,
    rate_limit::{ADMIN_USERNAME_LOCKOUT, RateLimiter},
    state::AppState,
};

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate<'a> {
    error: Option<&'a str>,
    csrf_token: String,
}

pub async fn show(session: Session) -> AppResult<Response> {
    let csrf_token = csrf::ensure_token(&session)
        .await
        .map_err(|e| AppError::Session(e.to_string()))?;
    let tmpl = LoginTemplate {
        error: None,
        csrf_token,
    };
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
    // H4: per-username lockout independent of per-IP rate limit. Keyed on
    // the lowercased submitted username so capitalization doesn't let the
    // attacker reset the counter. A successful verify does NOT reset the
    // bucket — an attacker who eventually guesses right still paid the
    // cost, and legitimate typo-retries are cheap (5-capacity).
    let username_key = format!("admin_login_user:{}", form.username.to_lowercase());
    let username_allowed =
        admin_login_username_allowed(&state.auth_limiter, &username_key).await;

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

    if !username_allowed {
        // Even if the password happens to be right, we refuse while the
        // per-username bucket is empty. The response is the same generic
        // message so the attacker can't see whether the lockout fired.
        state.metrics.incr(&state.metrics.admin_login_failed);
        let _ = audit::record(
            &state.db,
            audit::AuditEntry {
                actor_user_id: None,
                actor_device_id: None,
                event_type: audit::EVENT_ADMIN_LOGIN_FAILED,
                ip_addr: ip.as_deref(),
                user_agent: ua.as_deref(),
            },
            &serde_json::json!({ "username": form.username, "reason": "username_lockout" }),
        )
        .await;
        let csrf_token = csrf::ensure_token(&session)
            .await
            .map_err(|e| AppError::Session(e.to_string()))?;
        let tmpl = LoginTemplate {
            error: Some("Invalid username or password."),
            csrf_token,
        };
        return Ok((StatusCode::UNAUTHORIZED, Html(tmpl.render()?)).into_response());
    }

    let Some(user_id) = matched else {
        state.metrics.incr(&state.metrics.admin_login_failed);
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
        let csrf_token = csrf::ensure_token(&session)
            .await
            .map_err(|e| AppError::Session(e.to_string()))?;
        let tmpl = LoginTemplate {
            error: Some("Invalid username or password."),
            csrf_token,
        };
        return Ok((StatusCode::UNAUTHORIZED, Html(tmpl.render()?)).into_response());
    };

    session
        .cycle_id()
        .await
        .map_err(|e| AppError::Session(e.to_string()))?;
    session
        .insert(ADMIN_USER_KEY, user_id)
        .await
        .map_err(|e| AppError::Session(e.to_string()))?;

    state.metrics.incr(&state.metrics.admin_login_success);
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

/// Checks the per-username admin-login bucket. Returns `true` if there
/// is budget for another attempt. The bucket refills slowly (see
/// `ADMIN_USERNAME_LOCKOUT`) so a sustained attack pays the real cost
/// no matter which IPs it comes from.
async fn admin_login_username_allowed(limiter: &RateLimiter, key: &str) -> bool {
    limiter.check(key, ADMIN_USERNAME_LOCKOUT).await
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
