use axum::{Router, extract::State, response::Response, routing::any};
use rustclip_shared::protocol::WS_SUBPROTOCOL;

use crate::{api::device_auth::DeviceAuth, state::AppState, ws::session::run};

pub mod hub;
pub mod session;

#[cfg(test)]
mod bundle_test;
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
    // If the client asks for `rustclip.v1` we accept and echo it back;
    // clients that send no `Sec-WebSocket-Protocol` still upgrade (for
    // back-compat with the pre-negotiation client). Future major-version
    // bumps can tighten this to require a match.
    ws.protocols([WS_SUBPROTOCOL])
        .on_upgrade(move |socket| run(socket, state, auth))
}
