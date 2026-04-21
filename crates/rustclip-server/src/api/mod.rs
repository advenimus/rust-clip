use axum::{
    Json, Router,
    http::StatusCode,
    middleware::from_fn_with_state,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use rustclip_shared::rest::{ErrorBody, ErrorResponse};

use crate::{rate_limit, state::AppState};

pub mod auth;
pub mod blobs;
#[cfg(test)]
mod blobs_test;
pub mod device_auth;
pub mod me;

pub fn router(auth_limiter: rate_limit::RateLimiter) -> Router<AppState> {
    let auth_routes = Router::new()
        .route("/auth/enroll", post(auth::enroll))
        .route("/auth/login", post(auth::login))
        .route("/auth/logout", post(auth::logout))
        .layer(from_fn_with_state(auth_limiter, rate_limit::auth_api_layer));

    Router::new()
        .merge(auth_routes)
        .route("/me", get(me::show))
        .nest("/blobs", blobs::router())
}

pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized", msg)
    }
    pub fn validation(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::UNPROCESSABLE_ENTITY, "validation_error", msg)
    }
    pub fn internal(context: &'static str) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            context.to_string(),
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if self.status.is_server_error() {
            tracing::error!(code = self.code, message = %self.message, "api server error");
        }
        let body = ErrorResponse {
            error: ErrorBody {
                code: self.code.to_string(),
                message: self.message,
            },
        };
        (self.status, Json(body)).into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(err: sqlx::Error) -> Self {
        tracing::error!(error = ?err, "db error in api");
        ApiError::internal("database error")
    }
}
