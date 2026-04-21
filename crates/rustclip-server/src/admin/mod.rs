use axum::{
    Router,
    middleware::from_fn_with_state,
    routing::{get, post},
};

use crate::{rate_limit, state::AppState};

pub mod audit_page;
pub mod dashboard;
pub mod devices;
pub mod login;
pub mod settings;
pub mod users;

pub fn router(auth_limiter: rate_limit::RateLimiter) -> Router<AppState> {
    let login_routes = Router::new()
        .route("/login", get(login::show).post(login::submit))
        .layer(from_fn_with_state(
            auth_limiter,
            rate_limit::admin_login_layer,
        ));

    Router::new()
        .merge(login_routes)
        .route("/logout", post(login::logout))
        .route("/", get(dashboard::show))
        .route("/users", get(users::list).post(users::create))
        .route("/users/{id}/delete", post(users::delete))
        .route(
            "/users/{id}/reset-enrollment",
            post(users::reset_enrollment),
        )
        .route("/users/{id}/reset-password", post(users::reset_password))
        .route("/devices", get(devices::list))
        .route("/devices/{id}/revoke", post(devices::revoke))
        .route("/audit-log", get(audit_page::list))
        .route("/audit-log.csv", get(audit_page::export_csv))
        .route("/settings", get(settings::show).post(settings::update))
}
