use axum::{
    Router,
    routing::{get, post},
};

use crate::state::AppState;

pub mod audit_page;
pub mod dashboard;
pub mod devices;
pub mod login;
pub mod users;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/login", get(login::show).post(login::submit))
        .route("/logout", post(login::logout))
        .route("/", get(dashboard::show))
        .route("/users", get(users::list).post(users::create))
        .route("/users/{id}/delete", post(users::delete))
        .route(
            "/users/{id}/reset-enrollment",
            post(users::reset_enrollment),
        )
        .route("/devices", get(devices::list))
        .route("/devices/{id}/revoke", post(devices::revoke))
        .route("/audit-log", get(audit_page::list))
}
