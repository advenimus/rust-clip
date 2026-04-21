use axum::{Router, extract::State, response::Response, routing::any};

use crate::{api::device_auth::DeviceAuth, state::AppState, ws::session::run};

pub mod hub;
pub mod session;

#[cfg(test)]
mod sync_test;

pub fn router() -> Router<AppState> {
    Router::new().route("/", any(ws_upgrade))
}

async fn ws_upgrade(
    State(state): State<AppState>,
    auth: DeviceAuth,
    ws: axum::extract::WebSocketUpgrade,
) -> Response {
    ws.on_upgrade(move |socket| run(socket, state, auth))
}
