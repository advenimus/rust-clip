use axum::{
    Router,
    middleware::from_fn_with_state,
    routing::{get, post},
};

use crate::{rate_limit, state::AppState};

pub mod about;
pub mod audit_page;
pub mod csrf;
pub mod dashboard;
pub mod devices;
pub mod login;
pub mod settings;
pub mod users;

pub fn router(state: AppState) -> Router<AppState> {
    let login_routes = Router::new()
        .route("/login", get(login::show).post(login::submit))
        .layer(from_fn_with_state(
            state.clone(),
            rate_limit::admin_login_layer,
        ));

    // Routes that require an authenticated admin and modify state. CSRF
    // middleware runs after AdminUser so we get a rejection response
    // (redirect to /admin/login) for unauthenticated callers, and a 403
    // for authenticated-but-CSRF-missing callers.
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
        .route("/about", get(about::show))
        .layer(from_fn_with_state(state, csrf::csrf_layer))
}
