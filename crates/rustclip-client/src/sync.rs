//! The `rustclip-client sync` daemon: keeps a WebSocket open, mirrors the
//! local clipboard to the server and applies incoming events to the clipboard.

use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use futures_util::{SinkExt, StreamExt};
use rustclip_shared::{
    PROTOCOL_VERSION,
    protocol::{ClientMessage, ClipEventMessage, ContentRef, MIME_TEXT, ServerMessage},
};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::{
    Message, client::IntoClientRequest, http::HeaderValue, protocol::CloseFrame,
};
use tracing::{debug, info, warn};
use url::Url;
use uuid::Uuid;

use crate::{
    clipboard::{self, ClipboardHandle},
    crypto::Cipher,
};

const RECONNECT_INITIAL: Duration = Duration::from_millis(500);
const RECONNECT_MAX: Duration = Duration::from_secs(30);
const PING_INTERVAL: Duration = Duration::from_secs(30);

pub async fn run(
    server_url: String,
    device_token: String,
    device_id: Uuid,
    content_key: [u8; 32],
) -> Result<()> {
    let ws_url = http_to_ws(&server_url)?;
    let cipher = Cipher::new(&content_key);

    let (event_tx, event_rx) = mpsc::channel::<String>(64);
    let clipboard = clipboard::spawn_watcher(event_tx)?;
    info!("clipboard watcher started");

    let mut backoff = RECONNECT_INITIAL;
    let mut event_rx = event_rx;
    loop {
        match session(
            &ws_url,
            &device_token,
            &cipher,
            device_id,
            &mut event_rx,
            &clipboard,
        )
        .await
        {
            Ok(()) => {
                info!("ws closed cleanly, reconnecting");
                backoff = RECONNECT_INITIAL;
            }
            Err(e) => {
                warn!(error = %e, "ws session error, backing off {:?}", backoff);
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(RECONNECT_MAX);
    }
}

async fn session(
    ws_url: &str,
    device_token: &str,
    cipher: &Cipher,
    device_id: Uuid,
    event_rx: &mut mpsc::Receiver<String>,
    clipboard: &ClipboardHandle,
) -> Result<()> {
    let mut request = ws_url
        .into_client_request()
        .context("building ws request")?;
    let bearer = HeaderValue::from_str(&format!("Bearer {device_token}"))
        .context("invalid device token for header")?;
    request.headers_mut().insert("authorization", bearer);

    debug!(url = ws_url, "connecting ws");
    let (stream, _response) = tokio_tungstenite::connect_async(request)
        .await
        .context("ws connect")?;
    let (mut writer, mut reader) = stream.split();
    info!("connected to server, awaiting backlog");

    let mut ping_timer = tokio::time::interval(PING_INTERVAL);
    ping_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ping_timer.tick().await; // skip immediate tick

    loop {
        tokio::select! {
            maybe_text = event_rx.recv() => {
                let Some(text) = maybe_text else {
                    let _ = writer
                        .send(Message::Close(Some(CloseFrame {
                            code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Normal,
                            reason: "client shutdown".into(),
                        })))
                        .await;
                    return Ok(());
                };
                let event = build_outgoing(cipher, &text)?;
                let msg = ClientMessage::ClipEvent(event);
                let wire = serde_json::to_string(&msg)?;
                writer
                    .send(Message::Text(wire.into()))
                    .await
                    .context("sending clip_event")?;
            }

            frame = reader.next() => {
                let Some(frame) = frame else { return Ok(()); };
                let frame = frame.context("ws read")?;
                match frame {
                    Message::Text(text) => {
                        match serde_json::from_str::<ServerMessage>(&text) {
                            Ok(msg) => handle_server(msg, cipher, device_id, clipboard).await,
                            Err(e) => warn!(error = %e, "unparseable server message"),
                        }
                    }
                    Message::Ping(p) => { let _ = writer.send(Message::Pong(p)).await; }
                    Message::Close(_) => return Ok(()),
                    _ => {}
                }
            }

            _ = ping_timer.tick() => {
                let ping = ClientMessage::Ping;
                let wire = serde_json::to_string(&ping)?;
                writer
                    .send(Message::Text(wire.into()))
                    .await
                    .context("sending ping")?;
            }
        }
    }
}

fn build_outgoing(cipher: &Cipher, text: &str) -> Result<ClipEventMessage> {
    let (nonce, ciphertext) = cipher.encrypt(text.as_bytes())?;
    Ok(ClipEventMessage {
        id: Uuid::new_v4(),
        v: PROTOCOL_VERSION,
        source_device_id: None,
        content: ContentRef::Inline {
            ciphertext_b64: BASE64.encode(&ciphertext),
            nonce_b64: BASE64.encode(&nonce),
        },
        mime_hint: MIME_TEXT.into(),
        size_bytes: text.len() as i64,
        created_at: now_millis(),
    })
}

async fn handle_server(
    msg: ServerMessage,
    cipher: &Cipher,
    device_id: Uuid,
    clipboard: &ClipboardHandle,
) {
    match msg {
        ServerMessage::BacklogStart => info!("draining backlog"),
        ServerMessage::BacklogEnd => info!("backlog done, live"),
        ServerMessage::Ack { id } => debug!(event_id = %id, "server ack"),
        ServerMessage::Pong => {}
        ServerMessage::Error { code, message } => {
            warn!(%code, %message, "server error");
        }
        ServerMessage::ClipEvent(event) => {
            if event.source_device_id == Some(device_id) {
                // Shouldn't happen since the server filters, but defense in depth.
                return;
            }
            if let Err(e) = apply_incoming(event, cipher, clipboard) {
                warn!(error = %e, "failed to apply incoming clip event");
            }
        }
    }
}

fn apply_incoming(
    event: ClipEventMessage,
    cipher: &Cipher,
    clipboard: &ClipboardHandle,
) -> Result<()> {
    let (ciphertext, nonce) = match &event.content {
        ContentRef::Inline {
            ciphertext_b64,
            nonce_b64,
        } => {
            let ct = BASE64
                .decode(ciphertext_b64.as_bytes())
                .map_err(|_| anyhow!("ciphertext not base64"))?;
            let nn = BASE64
                .decode(nonce_b64.as_bytes())
                .map_err(|_| anyhow!("nonce not base64"))?;
            (ct, nn)
        }
        ContentRef::Blob { .. } => {
            warn!("blob events are not supported yet (Phase 5)");
            return Ok(());
        }
    };
    let plaintext = cipher.decrypt(&nonce, &ciphertext)?;
    let text =
        String::from_utf8(plaintext).map_err(|_| anyhow!("decrypted payload is not utf-8"))?;
    info!(
        bytes = text.len(),
        event_id = %event.id,
        "received clip"
    );
    clipboard.write_text(text)?;
    Ok(())
}

fn http_to_ws(server_url: &str) -> Result<String> {
    let mut url = Url::parse(server_url).context("parsing server url")?;
    let new_scheme = match url.scheme() {
        "http" => "ws",
        "https" => "wss",
        other => return Err(anyhow!("unsupported scheme: {other}")),
    };
    url.set_scheme(new_scheme)
        .map_err(|_| anyhow!("failed to rewrite scheme"))?;
    let trimmed = url.path().trim_end_matches('/').to_string();
    url.set_path(&trimmed);
    Ok(format!("{}/ws", url.as_str().trim_end_matches('/')))
}

fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
