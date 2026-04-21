//! The `rustclip-client sync` daemon: keeps a WebSocket open, mirrors the
//! local clipboard to the server and applies incoming events to the clipboard.

use std::{collections::VecDeque, time::Duration};

use anyhow::{Context, Result, anyhow};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use futures_util::{SinkExt, StreamExt};
use rustclip_shared::{
    MAX_INLINE_CIPHERTEXT_BYTES, PROTOCOL_VERSION,
    protocol::{
        ClientMessage, ClipEventMessage, ContentRef, MIME_BUNDLE, MIME_PNG, MIME_TEXT,
        ServerMessage,
    },
};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::{
    Message, client::IntoClientRequest, http::HeaderValue, protocol::CloseFrame,
};
use tracing::{debug, info, warn};
use url::Url;
use uuid::Uuid;

use crate::{
    clipboard::{self, ClipEvent, ClipboardHandle},
    clipboard_files,
    crypto::Cipher,
    files::{self, FileBundle},
    http::ServerClient,
    image_codec,
};

const RECONNECT_INITIAL: Duration = Duration::from_millis(500);
const RECONNECT_MAX: Duration = Duration::from_secs(30);
const PING_INTERVAL: Duration = Duration::from_secs(30);
const SEEN_EVENTS_CAPACITY: usize = 256;

pub async fn run(
    server_url: String,
    device_token: String,
    device_id: Uuid,
    content_key: [u8; 32],
) -> Result<()> {
    let ws_url = http_to_ws(&server_url)?;
    let cipher = Cipher::new(&content_key);
    let rest = ServerClient::new(&server_url)?;

    let (event_tx, event_rx) = mpsc::channel::<ClipEvent>(64);
    let clipboard = clipboard::spawn_watcher(event_tx)?;
    info!("clipboard watcher started");

    let mut backoff = RECONNECT_INITIAL;
    let mut event_rx = event_rx;
    let mut seen = SeenEvents::new(SEEN_EVENTS_CAPACITY);
    loop {
        match session(
            &ws_url,
            &device_token,
            &cipher,
            &rest,
            device_id,
            &mut event_rx,
            &clipboard,
            &mut seen,
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

#[allow(clippy::too_many_arguments)]
async fn session(
    ws_url: &str,
    device_token: &str,
    cipher: &Cipher,
    rest: &ServerClient,
    device_id: Uuid,
    event_rx: &mut mpsc::Receiver<ClipEvent>,
    clipboard: &ClipboardHandle,
    seen: &mut SeenEvents,
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
            maybe_event = event_rx.recv() => {
                let Some(event) = maybe_event else {
                    let _ = writer
                        .send(Message::Close(Some(CloseFrame {
                            code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Normal,
                            reason: "client shutdown".into(),
                        })))
                        .await;
                    return Ok(());
                };
                let outgoing = build_outgoing(cipher, rest, device_token, event).await?;
                seen.insert(outgoing.id);
                let msg = ClientMessage::ClipEvent(outgoing);
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
                            Ok(msg) => handle_server(msg, cipher, rest, device_token, device_id, clipboard, seen).await,
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

async fn build_outgoing(
    cipher: &Cipher,
    rest: &ServerClient,
    device_token: &str,
    event: ClipEvent,
) -> Result<ClipEventMessage> {
    match event {
        ClipEvent::Text(text) => {
            let (nonce, ciphertext) = cipher.encrypt(text.as_bytes())?;
            let plain_len = text.len() as i64;
            build_event(ciphertext, nonce, MIME_TEXT, plain_len, rest, device_token).await
        }
        ClipEvent::Image(image) => {
            let png_bytes = image_codec::encode_png(&image)?;
            let plain_len = png_bytes.len() as i64;
            let (nonce, ciphertext) = cipher.encrypt(&png_bytes)?;
            build_event(ciphertext, nonce, MIME_PNG, plain_len, rest, device_token).await
        }
    }
}

/// Build and send a single clip event via a short-lived WS connection.
/// Used by the `send-files` CLI command, which does not run a daemon.
///
/// The filename / summary stays inside the encrypted payload: the server
/// only sees `application/x-rustclip-bundle` and the ciphertext length. The
/// receiver recovers the original filenames from the tar headers after
/// decryption.
pub async fn send_bundle_one_shot(
    server_url: &str,
    device_token: &str,
    cipher: &Cipher,
    bundle: FileBundle,
) -> Result<()> {
    let rest = ServerClient::new(server_url)?;
    let plain_len = bundle.tar_bytes.len() as i64;
    let (nonce, ciphertext) = cipher.encrypt(&bundle.tar_bytes)?;
    let event = build_event(
        ciphertext,
        nonce,
        MIME_BUNDLE,
        plain_len,
        &rest,
        device_token,
    )
    .await?;

    let ws_url = http_to_ws(server_url)?;
    let mut request = ws_url
        .as_str()
        .into_client_request()
        .context("building ws request")?;
    let bearer = HeaderValue::from_str(&format!("Bearer {device_token}"))
        .context("invalid device token for header")?;
    request.headers_mut().insert("authorization", bearer);
    let (stream, _resp) = tokio_tungstenite::connect_async(request)
        .await
        .context("ws connect for one-shot")?;
    let (mut writer, mut reader) = stream.split();

    let wire = serde_json::to_string(&ClientMessage::ClipEvent(event.clone()))?;
    writer
        .send(Message::Text(wire.into()))
        .await
        .context("sending clip_event")?;

    // Wait up to a few seconds for the server Ack, then disconnect.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(anyhow!("timed out waiting for server ack"));
        }
        match tokio::time::timeout(remaining, reader.next()).await {
            Ok(Some(Ok(Message::Text(text)))) => {
                if let Ok(msg) = serde_json::from_str::<ServerMessage>(&text) {
                    match msg {
                        ServerMessage::Ack { id } if id == event.id => {
                            let _ = writer
                                .send(Message::Close(Some(CloseFrame {
                                    code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Normal,
                                    reason: "sent".into(),
                                })))
                                .await;
                            return Ok(());
                        }
                        ServerMessage::Error { code, message } => {
                            return Err(anyhow!("server error {code}: {message}"));
                        }
                        _ => {}
                    }
                }
            }
            Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => {}
            Ok(Some(Ok(Message::Close(_))) | None) => {
                return Err(anyhow!("server closed connection before ack"));
            }
            Ok(Some(Err(e))) => return Err(anyhow!("ws read: {e}")),
            Err(_) => return Err(anyhow!("timed out waiting for server ack")),
            _ => {}
        }
    }
}

async fn build_event(
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    mime: &str,
    size_bytes: i64,
    rest: &ServerClient,
    device_token: &str,
) -> Result<ClipEventMessage> {
    let content = if ciphertext.len() <= MAX_INLINE_CIPHERTEXT_BYTES {
        ContentRef::Inline {
            ciphertext_b64: BASE64.encode(&ciphertext),
            nonce_b64: BASE64.encode(&nonce),
        }
    } else {
        let upload = rest
            .upload_blob(device_token, ciphertext)
            .await
            .context("uploading blob ciphertext")?;
        ContentRef::Blob {
            blob_id: upload.blob_id,
            nonce_b64: BASE64.encode(&nonce),
            sha256_hex: upload.sha256_hex,
        }
    };
    Ok(ClipEventMessage {
        id: Uuid::new_v4(),
        v: PROTOCOL_VERSION,
        source_device_id: None,
        content,
        mime_hint: mime.into(),
        size_bytes,
        created_at: now_millis(),
    })
}

#[allow(clippy::too_many_arguments)]
async fn handle_server(
    msg: ServerMessage,
    cipher: &Cipher,
    rest: &ServerClient,
    device_token: &str,
    device_id: Uuid,
    clipboard: &ClipboardHandle,
    seen: &mut SeenEvents,
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
            if seen.contains(event.id) {
                debug!(event_id = %event.id, "dropping duplicate clip event");
                return;
            }
            seen.insert(event.id);
            if let Err(e) = apply_incoming(event, cipher, rest, device_token, clipboard).await {
                warn!(error = %e, "failed to apply incoming clip event");
            }
        }
    }
}

async fn apply_incoming(
    event: ClipEventMessage,
    cipher: &Cipher,
    rest: &ServerClient,
    device_token: &str,
    clipboard: &ClipboardHandle,
) -> Result<()> {
    let (ciphertext, nonce) = match event.content {
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
        ContentRef::Blob {
            blob_id,
            nonce_b64,
            sha256_hex: _,
        } => {
            let ct = rest.download_blob(device_token, blob_id).await?;
            let nn = BASE64
                .decode(nonce_b64.as_bytes())
                .map_err(|_| anyhow!("nonce not base64"))?;
            (ct, nn)
        }
    };
    let plaintext = cipher.decrypt(&nonce, &ciphertext)?;

    let mime_base = event.mime_hint.split(';').next().unwrap_or("").trim();
    match mime_base {
        m if m.starts_with("text/") => {
            let text = String::from_utf8(plaintext)
                .map_err(|_| anyhow!("decrypted payload is not utf-8"))?;
            info!(
                bytes = text.len(),
                event_id = %event.id,
                "received text clip"
            );
            clipboard.write_text(text)?;
        }
        MIME_PNG => {
            let image = image_codec::decode_png(&plaintext)?;
            info!(
                width = image.width,
                height = image.height,
                event_id = %event.id,
                "received image clip"
            );
            clipboard.write_image(image)?;
        }
        MIME_BUNDLE => {
            let dest = files::inbox_dir().join(event.id.to_string());
            let written = files::unpack(&plaintext, &dest)?;
            info!(
                count = written.len(),
                path = %dest.display(),
                event_id = %event.id,
                "received file bundle"
            );
            for p in &written {
                info!(file = %p.display(), "inbox file");
            }
            if let Err(e) = clipboard_files::write_file_list(&written) {
                // Non-fatal: files are already on disk, user can still copy
                // them manually if the pasteboard write failed.
                warn!(error = %e, "pasteboard file-list write failed");
            }
        }
        other => {
            warn!(mime = %other, "unsupported mime, dropping");
        }
    }
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

/// Bounded LRU of recently-seen event ids. Used to drop duplicates that
/// arrive both via the backlog drain and the live broadcast during the
/// subscribe-then-drain race window, and to self-filter local echoes.
struct SeenEvents {
    ids: VecDeque<Uuid>,
    capacity: usize,
}

impl SeenEvents {
    fn new(capacity: usize) -> Self {
        Self {
            ids: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    fn contains(&self, id: Uuid) -> bool {
        self.ids.iter().any(|&x| x == id)
    }

    fn insert(&mut self, id: Uuid) {
        if self.ids.iter().any(|&x| x == id) {
            return;
        }
        if self.ids.len() >= self.capacity {
            self.ids.pop_front();
        }
        self.ids.push_back(id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seen_events_dedupes_within_capacity() {
        let mut s = SeenEvents::new(3);
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        s.insert(a);
        s.insert(b);
        assert!(s.contains(a));
        assert!(s.contains(b));
        s.insert(a);
        assert_eq!(s.ids.len(), 2);
    }

    #[test]
    fn seen_events_evicts_oldest() {
        let mut s = SeenEvents::new(2);
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let c = Uuid::new_v4();
        s.insert(a);
        s.insert(b);
        s.insert(c);
        assert!(!s.contains(a));
        assert!(s.contains(b));
        assert!(s.contains(c));
    }
}
