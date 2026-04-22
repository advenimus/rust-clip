//! The `rustclip-client sync` daemon: keeps a WebSocket open, mirrors the
//! local clipboard to the server and applies incoming events to the clipboard.

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result, anyhow};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use futures_util::{SinkExt, StreamExt};
use rand::Rng;
use rustclip_shared::{
    MAX_INLINE_CIPHERTEXT_BYTES, PROTOCOL_VERSION,
    protocol::{
        ClientMessage, ClipEventMessage, ContentRef, MIME_BUNDLE, MIME_PNG, MIME_TEXT,
        ServerMessage, WS_SUBPROTOCOL, build_aad,
    },
};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::{
    Message, client::IntoClientRequest, http::HeaderValue, protocol::CloseFrame,
};
use tracing::{debug, info, warn};
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    clipboard::{ClipEvent, ClipboardHandle},
    config::ClientConfig,
    crypto::Cipher,
    files::{self, FileBundle, PackError},
    history::{Direction, History},
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
    content_key: Zeroizing<[u8; 32]>,
    clipboard: ClipboardHandle,
    mut event_rx: mpsc::Receiver<ClipEvent>,
) -> Result<()> {
    let ws_url = http_to_ws(&server_url)?;
    // Key is cloned into XChaCha20Poly1305 which ZeroizeOnDrop's its
    // internal copy; `content_key` itself gets wiped when this task
    // returns thanks to `Zeroizing`.
    let cipher = Cipher::new(&content_key);
    let rest = ServerClient::new(&server_url)?;
    let history = Arc::new(Mutex::new(History::open_default_with_key(&content_key)?));

    let mut backoff = RECONNECT_INITIAL;
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
            &history,
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
        let jittered = jitter(backoff);
        debug!(?jittered, "reconnect backoff with jitter");
        tokio::time::sleep(jittered).await;
        backoff = (backoff * 2).min(RECONNECT_MAX);
    }
}

/// Applies ±25% full jitter to a base backoff. Prevents synchronized
/// reconnect stampedes when many clients share a dropped upstream link.
fn jitter(base: Duration) -> Duration {
    let base_ms = base.as_millis() as u64;
    if base_ms == 0 {
        return base;
    }
    let spread = base_ms / 4;
    let offset = rand::thread_rng().gen_range(0..=spread * 2);
    let jittered = base_ms.saturating_sub(spread).saturating_add(offset);
    Duration::from_millis(jittered)
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
    history: &Arc<Mutex<History>>,
) -> Result<()> {
    let mut request = ws_url
        .into_client_request()
        .context("building ws request")?;
    let bearer = HeaderValue::from_str(&format!("Bearer {device_token}"))
        .context("invalid device token for header")?;
    request.headers_mut().insert("authorization", bearer);
    request.headers_mut().insert(
        "sec-websocket-protocol",
        HeaderValue::from_static(WS_SUBPROTOCOL),
    );

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
                let Some((outgoing, preview)) =
                    build_outgoing(cipher, rest, device_token, device_id, event).await?
                else {
                    continue;
                };
                seen.insert(outgoing.id);
                if let Err(e) = record_outgoing(history, &outgoing, &preview) {
                    warn!(error = %e, "failed to record outgoing history");
                }
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
                            Ok(msg) => handle_server(msg, cipher, rest, device_token, device_id, clipboard, seen, history).await,
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

/// A compact representation of the outgoing payload we keep after the
/// ClipEvent is built, used to record a local history entry. Keeps the
/// decrypted metadata separate from the wire event.
pub enum OutgoingPreview {
    Text(String),
    /// PNG bytes ride along so `record_outgoing` can best-effort stash
    /// them in the `ImageHistoryStore` — letting the user re-copy past
    /// images from the History window.
    Image {
        width: usize,
        height: usize,
        png_bytes: Vec<u8>,
    },
    Bundle {
        summary: String,
    },
}

/// Build the on-wire event for one locally-detected clip.
///
/// Returns `Ok(None)` to mean "skip this event silently" — e.g. an
/// auto-detected file bundle exceeds the configured size cap. The caller
/// continues the loop without sending. Hard failures still bubble up via
/// `Err`.
async fn build_outgoing(
    cipher: &Cipher,
    rest: &ServerClient,
    device_token: &str,
    device_id: Uuid,
    event: ClipEvent,
) -> Result<Option<(ClipEventMessage, OutgoingPreview)>> {
    match event {
        ClipEvent::Text(text) => {
            info!(bytes = text.len(), "outgoing text clip");
            let msg = encrypt_and_build_event(
                cipher,
                rest,
                device_token,
                device_id,
                text.as_bytes(),
                MIME_TEXT,
            )
            .await?;
            Ok(Some((msg, OutgoingPreview::Text(text))))
        }
        ClipEvent::Image(image) => {
            info!(
                width = image.width,
                height = image.height,
                "outgoing image clip"
            );
            let png_bytes = image_codec::encode_png(&image)?;
            let width = image.width;
            let height = image.height;
            let msg = encrypt_and_build_event(
                cipher,
                rest,
                device_token,
                device_id,
                &png_bytes,
                MIME_PNG,
            )
            .await?;
            Ok(Some((
                msg,
                OutgoingPreview::Image {
                    width,
                    height,
                    png_bytes,
                },
            )))
        }
        ClipEvent::Files(paths) => {
            let cap = ClientConfig::load().unwrap_or_default().auto_sync_max_bytes;
            let path_count = paths.len();
            info!(
                count = path_count,
                first = %paths.first().map(|p| p.display().to_string()).unwrap_or_default(),
                "outgoing file bundle detected from clipboard",
            );
            let paths_for_task = paths.clone();
            let pack_result = tokio::task::spawn_blocking(move || {
                files::pack_checked(&paths_for_task, Some(cap))
            })
            .await
            .map_err(|e| anyhow!("pack task panicked: {e}"))?;
            let bundle = match pack_result {
                Ok(b) => b,
                Err(PackError::TooLarge { total_bytes, cap }) => {
                    warn!(
                        paths = path_count,
                        total_bytes,
                        cap,
                        "auto-sync file bundle exceeds cap; skipping (use `send-files` CLI to override)",
                    );
                    return Ok(None);
                }
                Err(PackError::Other(e)) => {
                    // Pasteboard junk (e.g. a file URL pointing at `/`
                    // or a path that isn't stat-able) would otherwise
                    // kill the whole WS session. Log the specific error
                    // and skip this event — the next genuine copy will
                    // recover on its own.
                    warn!(
                        paths = path_count,
                        error = %e,
                        "skipping unpackable file bundle",
                    );
                    return Ok(None);
                }
            };
            let summary = bundle.summary.clone();
            let msg = encrypt_and_build_event(
                cipher,
                rest,
                device_token,
                device_id,
                &bundle.tar_bytes,
                MIME_BUNDLE,
            )
            .await?;
            Ok(Some((msg, OutgoingPreview::Bundle { summary })))
        }
    }
}

/// Build the full clip_event envelope, including AAD-bound AEAD.
///
/// Because the AAD references the event id and (for blob payloads)
/// the blob id, both are pre-generated client-side so they can be
/// bound *before* encryption. The blob id is then sent to the server
/// via `X-Rustclip-Blob-Id` so the receiver's AAD matches.
///
/// `device_id` is the caller's own device id; it rides in AAD so a
/// malicious server that rewrites `source_device_id` on broadcast
/// fails Poly1305 at the receiver.
async fn encrypt_and_build_event(
    cipher: &Cipher,
    rest: &ServerClient,
    device_token: &str,
    device_id: Uuid,
    plaintext: &[u8],
    mime: &str,
) -> Result<ClipEventMessage> {
    // +16 = Poly1305 tag that chacha20poly1305 appends.
    let goes_blob = plaintext.len() + 16 > MAX_INLINE_CIPHERTEXT_BYTES;
    let event_id = Uuid::new_v4();
    let created_at = now_millis();
    let plain_len = plaintext.len() as i64;

    // Build the envelope with placeholder ciphertext/nonce so AAD is
    // computed over exactly the fields the receiver will see on the
    // wire. sha256_hex is excluded from AAD (see shared::build_aad).
    let mut envelope = ClipEventMessage {
        id: event_id,
        v: PROTOCOL_VERSION,
        source_device_id: Some(device_id),
        content: if goes_blob {
            ContentRef::Blob {
                blob_id: Uuid::new_v4(),
                nonce_b64: String::new(),
                sha256_hex: String::new(),
            }
        } else {
            ContentRef::Inline {
                ciphertext_b64: String::new(),
                nonce_b64: String::new(),
            }
        },
        mime_hint: mime.into(),
        size_bytes: plain_len,
        created_at,
    };

    let aad = build_aad(&envelope);
    let (nonce, ciphertext) = cipher.encrypt(plaintext, &aad)?;

    envelope.content = match envelope.content {
        ContentRef::Blob { blob_id, .. } => {
            let upload = rest
                .upload_blob(device_token, blob_id, ciphertext)
                .await
                .context("uploading blob ciphertext")?;
            // upload.blob_id should echo what we sent; if the server
            // returned a different id the subsequent AAD mismatch at
            // the receiver would surface the tampering anyway.
            ContentRef::Blob {
                blob_id: upload.blob_id,
                nonce_b64: BASE64.encode(&nonce),
                sha256_hex: upload.sha256_hex,
            }
        }
        ContentRef::Inline { .. } => ContentRef::Inline {
            ciphertext_b64: BASE64.encode(&ciphertext),
            nonce_b64: BASE64.encode(&nonce),
        },
    };
    Ok(envelope)
}

fn record_outgoing(
    history: &Arc<Mutex<History>>,
    event: &ClipEventMessage,
    preview: &OutgoingPreview,
) -> Result<()> {
    // Clone the (cheap) image store out while we briefly hold the
    // lock, so the actual disk write happens after the mutex is
    // dropped. Under the lock we only touch SQLite which is fast.
    let image_bytes_to_persist: Option<(
        uuid::Uuid,
        Vec<u8>,
        crate::image_history::ImageHistoryStore,
    )> = {
        let mut h = history
            .lock()
            .map_err(|_| anyhow!("history mutex poisoned"))?;
        match preview {
            OutgoingPreview::Text(text) => {
                h.record_text(Direction::Outgoing, text, event.id)?;
                None
            }
            OutgoingPreview::Image {
                width,
                height,
                png_bytes,
            } => {
                h.record_image(
                    Direction::Outgoing,
                    *width as u32,
                    *height as u32,
                    event.size_bytes,
                    event.id,
                )?;
                h.image_store()
                    .cloned()
                    .map(|store| (event.id, png_bytes.clone(), store))
            }
            OutgoingPreview::Bundle { summary } => {
                h.record_bundle(Direction::Outgoing, summary, event.size_bytes, event.id)?;
                None
            }
        }
    };

    if let Some((id, bytes, store)) = image_bytes_to_persist {
        // Best-effort: failing to stash the image means the user can't
        // re-copy it from history later, but the clip itself already
        // went out over the wire. Don't bounce the error upstream.
        if let Err(e) = store.put(id, &bytes) {
            warn!(event_id = %id, error = %e, "persisting outgoing image to history store");
        }
    }

    Ok(())
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
    device_id: Uuid,
    cipher: &Cipher,
    bundle: FileBundle,
) -> Result<Uuid> {
    let rest = ServerClient::new(server_url)?;
    let event = encrypt_and_build_event(
        cipher,
        &rest,
        device_token,
        device_id,
        &bundle.tar_bytes,
        MIME_BUNDLE,
    )
    .await?;
    let event_id = event.id;

    let ws_url = http_to_ws(server_url)?;
    let mut request = ws_url
        .as_str()
        .into_client_request()
        .context("building ws request")?;
    let bearer = HeaderValue::from_str(&format!("Bearer {device_token}"))
        .context("invalid device token for header")?;
    request.headers_mut().insert("authorization", bearer);
    request.headers_mut().insert(
        "sec-websocket-protocol",
        HeaderValue::from_static(WS_SUBPROTOCOL),
    );
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
                            return Ok(event_id);
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

#[allow(clippy::too_many_arguments)]
async fn handle_server(
    msg: ServerMessage,
    cipher: &Cipher,
    rest: &ServerClient,
    device_token: &str,
    device_id: Uuid,
    clipboard: &ClipboardHandle,
    seen: &mut SeenEvents,
    history: &Arc<Mutex<History>>,
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
            if let Err(e) =
                apply_incoming(event, cipher, rest, device_token, clipboard, history).await
            {
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
    history: &Arc<Mutex<History>>,
) -> Result<()> {
    // Reject v1 events — they were encrypted without AAD and we do
    // not want to run a decrypt path that bypasses authentication of
    // envelope metadata. Any pre-upgrade buffered events simply age
    // out of the server-side offline TTL window.
    if event.v < PROTOCOL_VERSION {
        return Err(anyhow!(
            "dropping pre-v2 clip event {}: protocol upgrade requires re-enrollment for old buffered events",
            event.id
        ));
    }
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
        ContentRef::Blob {
            blob_id,
            nonce_b64,
            sha256_hex,
        } => {
            let ct = rest.download_blob(device_token, *blob_id).await?;
            // Verify the blob matches the hash recorded in the event before
            // handing it to the AEAD. If the server (or something on disk)
            // swapped the backing file, we abort here instead of letting the
            // attacker probe decryption behavior for same-key ciphertexts.
            use sha2::{Digest, Sha256};
            let actual = hex::encode(Sha256::digest(&ct));
            if !sha256_eq(&actual, sha256_hex) {
                return Err(anyhow!(
                    "blob {blob_id} hash mismatch (event wanted {sha256_hex}, disk has {actual})"
                ));
            }
            let nn = BASE64
                .decode(nonce_b64.as_bytes())
                .map_err(|_| anyhow!("nonce not base64"))?;
            (ct, nn)
        }
    };
    // AAD is computed over the envelope the server delivered. Any
    // metadata tamper (relabeled mime, shifted timestamp, spoofed
    // source device) will make the AEAD tag check fail here.
    let aad = build_aad(&event);
    let plaintext = cipher.decrypt(&nonce, &ciphertext, &aad)?;

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
            clipboard.write_text(text.clone())?;
            if let Ok(mut h) = history.lock() {
                let _ = h.record_text(Direction::Incoming, &text, event.id);
            }
        }
        MIME_PNG => {
            let image = image_codec::decode_png(&plaintext)?;
            let width = image.width;
            let height = image.height;
            info!(
                width,
                height,
                event_id = %event.id,
                "received image clip"
            );
            clipboard.write_image(image)?;
            // Clone the image store out under the short lock, then
            // write the encrypted PNG to disk afterwards so the lock
            // doesn't cover disk I/O.
            let image_store_clone = if let Ok(mut h) = history.lock() {
                let _ = h.record_image(
                    Direction::Incoming,
                    width as u32,
                    height as u32,
                    event.size_bytes,
                    event.id,
                );
                h.image_store().cloned()
            } else {
                None
            };
            if let Some(store) = image_store_clone {
                if let Err(e) = store.put(event.id, &plaintext) {
                    warn!(event_id = %event.id, error = %e, "persisting incoming image to history store");
                }
            }
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
            // Put only the top-level inbox entries on the clipboard. For
            // a single-file bundle that's just the file; for a folder
            // bundle it's the folder itself, so Explorer / Finder's
            // Ctrl+V recurses and preserves the directory structure.
            let top_level = files::top_level_entries(&dest).unwrap_or_else(|_| written.clone());
            if let Err(e) = clipboard.write_file_list(top_level) {
                warn!(error = %e, "requesting file-list write failed");
            }
            let summary = summarize_incoming_bundle(&written);
            if let Ok(mut h) = history.lock() {
                let _ = h.record_bundle(Direction::Incoming, &summary, event.size_bytes, event.id);
            }
        }
        other => {
            warn!(mime = %other, "unsupported mime, dropping");
        }
    }
    Ok(())
}

/// Case-insensitive hex compare. The hash isn't a secret so constant-time
/// is unnecessary, but we normalize because different sha2 versions have
/// emitted both cases at different times.
fn sha256_eq(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

fn summarize_incoming_bundle(paths: &[std::path::PathBuf]) -> String {
    if paths.len() == 1 {
        paths[0]
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "file".into())
    } else {
        format!("{} files", paths.len())
    }
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
