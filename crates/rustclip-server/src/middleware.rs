use axum::{
    extract::FromRequestParts,
    http::request::Parts,
    response::{IntoResponse, Redirect, Response},
};
use sqlx::FromRow;
use tower_sessions::Session;
use uuid::Uuid;

use crate::{admin::csrf, state::AppState};

pub const ADMIN_USER_KEY: &str = "admin_user_id";

#[allow(dead_code)]
pub struct AdminUser {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    /// Session-bound CSRF token. Always populate into any admin
    /// template that contains a form so the CSRF middleware can
    /// validate the resulting POST.
    pub csrf_token: String,
}

#[derive(FromRow)]
struct AdminRow {
    id: Uuid,
    username: String,
    display_name: String,
}

impl FromRequestParts<AppState> for AdminUser {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let redirect_login = || Redirect::to("/admin/login").into_response();

        let session = Session::from_request_parts(parts, state)
            .await
            .map_err(|e| {
                tracing::warn!(error = ?e, "session extraction failed");
                redirect_login()
            })?;

        let user_id: Uuid = match session.get(ADMIN_USER_KEY).await {
            Ok(Some(id)) => id,
            Ok(None) => return Err(redirect_login()),
            Err(e) => {
                tracing::warn!(error = ?e, "reading session failed");
                return Err(redirect_login());
            }
        };

        let row = sqlx::query_as::<_, AdminRow>(
            "SELECT id, username, display_name FROM users \
             WHERE id = ? AND is_admin = 1 AND disabled_at IS NULL",
        )
        .bind(user_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = ?e, "loading admin user failed");
            redirect_login()
        })?;

        let Some(r) = row else {
            return Err(redirect_login());
        };
        let csrf_token = csrf::ensure_token(&session).await.map_err(|e| {
            tracing::error!(error = %e, "csrf token init failed");
            redirect_login()
        })?;
        Ok(AdminUser {
            id: r.id,
            username: r.username,
            display_name: r.display_name,
            csrf_token,
        })
    }
}

pub fn client_meta(headers: &axum::http::HeaderMap) -> (Option<String>, Option<String>) {
    let ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string());
    let ua = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    (ip, ua)
}
