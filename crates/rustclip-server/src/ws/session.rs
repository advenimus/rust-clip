//! Per-connection WS session task. Owns one socket and one broadcast receiver.

use std::time::Instant;

use axum::extract::ws::{Message, WebSocket};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use futures_util::{SinkExt, StreamExt};
use rustclip_shared::{
    MAX_INLINE_CIPHERTEXT_BYTES,
    protocol::{ClientMessage, ClipEventMessage, ContentRef, ServerMessage},
};
use sqlx::FromRow;
use time::{Duration, OffsetDateTime};
use tokio::sync::broadcast;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Token-bucket rate cap for inbound ClipEvent messages per WS connection.
/// 30 events / 10s ≈ 3 events/s steady-state with burst headroom.
const WS_EVENT_BUCKET_CAPACITY: f64 = 30.0;
const WS_EVENT_REFILL_PER_SEC: f64 = 3.0;

struct EventBucket {
    tokens: f64,
    last_refill: Instant,
}

impl EventBucket {
    fn new() -> Self {
        Self {
            tokens: WS_EVENT_BUCKET_CAPACITY,
            last_refill: Instant::now(),
        }
    }

    fn try_take(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.last_refill).as_secs_f64();
        self.tokens =
            (self.tokens + elapsed * WS_EVENT_REFILL_PER_SEC).min(WS_EVENT_BUCKET_CAPACITY);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

use crate::{
    api::device_auth::DeviceAuth, db::now_millis, state::AppState, ws::hub::ClipBroadcast,
};

pub async fn run(socket: WebSocket, state: AppState, auth: DeviceAuth) {
    info!(user_id = %auth.user_id, device_id = %auth.device_id, "ws connected");
    let (mut writer, mut reader) = socket.split();

    // Subscribe first so no event is lost during the backlog drain window.
    let mut live_rx = state.hub.subscribe(auth.user_id);

    if send_server(&mut writer, &ServerMessage::BacklogStart)
        .await
        .is_err()
    {
        return;
    }
    match drain_backlog(&state, &auth, &mut writer).await {
        Ok(n) => debug!(drained = n, device_id = %auth.device_id, "backlog delivered"),
        Err(e) => warn!(error = %e, device_id = %auth.device_id, "backlog drain failed"),
    }
    if send_server(&mut writer, &ServerMessage::BacklogEnd)
        .await
        .is_err()
    {
        return;
    }

    let mut event_bucket = EventBucket::new();

    loop {
        tokio::select! {
            frame = reader.next() => match frame {
                Some(Ok(Message::Text(text))) => {
                    if let Err(e) = handle_client_text(&state, &auth, &text, &mut writer, &mut live_rx, &mut event_bucket).await {
                        warn!(error = %e, "handling client text failed");
                        let _ = send_server(&mut writer, &ServerMessage::Error {
                            code: "bad_message".into(),
                            message: e.to_string(),
                        }).await;
                    }
                }
                Some(Ok(Message::Ping(p))) => {
                    let _ = writer.send(Message::Pong(p)).await;
                }
                Some(Ok(Message::Close(_))) | None => {
                    info!(device_id = %auth.device_id, "ws closed by peer");
                    break;
                }
                Some(Err(e)) => {
                    warn!(error = %e, "ws read error");
                    break;
                }
                _ => {}
            },
            msg = live_rx.recv() => match msg {
                Ok(bcast) => {
                    if bcast.source_device_id == auth.device_id {
                        continue;
                    }
                    let mut event = bcast.event.clone();
                    event.source_device_id = Some(bcast.source_device_id);
                    if send_server(&mut writer, &ServerMessage::ClipEvent(event.clone())).await.is_err() {
                        break;
                    }
                    if let Err(e) = mark_delivered(&state, event.id, auth.device_id).await {
                        warn!(error = %e, "failed to mark clip delivered");
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!(missed = n, device_id = %auth.device_id, "broadcast lagged");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    }

    info!(device_id = %auth.device_id, "ws session ended");
}

async fn handle_client_text(
    state: &AppState,
    auth: &DeviceAuth,
    text: &str,
    writer: &mut futures_util::stream::SplitSink<WebSocket, Message>,
    _live_rx: &mut broadcast::Receiver<std::sync::Arc<ClipBroadcast>>,
    bucket: &mut EventBucket,
) -> anyhow::Result<()> {
    let msg: ClientMessage =
        serde_json::from_str(text).map_err(|e| anyhow::anyhow!("invalid json: {e}"))?;
    match msg {
        ClientMessage::Ping => {
            send_server(writer, &ServerMessage::Pong).await.ok();
        }
        ClientMessage::ClipEvent(event) => {
            if !bucket.try_take() {
                warn!(device_id = %auth.device_id, "ws clip event rate cap exceeded");
                send_server(
                    writer,
                    &ServerMessage::Error {
                        code: "rate_limited".into(),
                        message: "clip event rate limit exceeded; event dropped".into(),
                    },
                )
                .await
                .ok();
                return Ok(());
            }
            persist_and_broadcast(state, auth, event.clone()).await?;
            send_server(writer, &ServerMessage::Ack { id: event.id })
                .await
                .ok();
        }
    }
    Ok(())
}

async fn persist_and_broadcast(
    state: &AppState,
    auth: &DeviceAuth,
    mut event: ClipEventMessage,
) -> anyhow::Result<()> {
    // Validate basic fields.
    if event.mime_hint.trim().is_empty() {
        anyhow::bail!("mime_hint is required");
    }

    let (content_kind, inline_bytes, blob_id, nonce_bytes) = match &event.content {
        ContentRef::Inline {
            ciphertext_b64,
            nonce_b64,
        } => {
            let ct = BASE64
                .decode(ciphertext_b64.as_bytes())
                .map_err(|_| anyhow::anyhow!("ciphertext is not valid base64"))?;
            if ct.len() > MAX_INLINE_CIPHERTEXT_BYTES {
                anyhow::bail!("inline ciphertext exceeds server limit");
            }
            let nonce = BASE64
                .decode(nonce_b64.as_bytes())
                .map_err(|_| anyhow::anyhow!("nonce is not valid base64"))?;
            ("inline", Some(ct), None::<Uuid>, nonce)
        }
        ContentRef::Blob {
            blob_id,
            nonce_b64,
            sha256_hex: _,
        } => {
            let nonce = BASE64
                .decode(nonce_b64.as_bytes())
                .map_err(|_| anyhow::anyhow!("nonce is not valid base64"))?;
            ("blob", None, Some(*blob_id), nonce)
        }
    };

    let ttl_hours = state.settings.snapshot().await.offline_ttl_hours as i64;
    let expires_at =
        (OffsetDateTime::now_utc() + Duration::hours(ttl_hours)).unix_timestamp() * 1000;

    let mut tx = state.db.begin().await?;
    let res = sqlx::query(
        "INSERT OR IGNORE INTO clip_events \
         (id, user_id, source_device_id, content_kind, inline_ciphertext, blob_id, \
          nonce, mime_hint, size_bytes, created_at, expires_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(event.id)
    .bind(auth.user_id)
    .bind(auth.device_id)
    .bind(content_kind)
    .bind(inline_bytes)
    .bind(blob_id)
    .bind(&nonce_bytes)
    .bind(&event.mime_hint)
    .bind(event.size_bytes)
    .bind(event.created_at)
    .bind(expires_at)
    .execute(&mut *tx)
    .await?;

    if res.rows_affected() == 0 {
        // Duplicate id from a client retry. Just ack the sender and return;
        // other devices already have it.
        tx.commit().await?;
        return Ok(());
    }

    sqlx::query(
        "INSERT INTO clip_deliveries (clip_event_id, target_device_id) \
         SELECT ?, d.id FROM devices d \
         WHERE d.user_id = ? AND d.id != ? AND d.revoked_at IS NULL",
    )
    .bind(event.id)
    .bind(auth.user_id)
    .bind(auth.device_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    event.source_device_id = Some(auth.device_id);
    state.hub.publish(
        auth.user_id,
        ClipBroadcast {
            source_device_id: auth.device_id,
            event,
        },
    );
    Ok(())
}

#[derive(FromRow)]
struct BacklogRow {
    event_id: Uuid,
    source_device_id: Option<Uuid>,
    content_kind: String,
    inline_ciphertext: Option<Vec<u8>>,
    blob_id: Option<Uuid>,
    nonce: Vec<u8>,
    mime_hint: String,
    size_bytes: i64,
    created_at: i64,
}

async fn drain_backlog(
    state: &AppState,
    auth: &DeviceAuth,
    writer: &mut futures_util::stream::SplitSink<WebSocket, Message>,
) -> anyhow::Result<usize> {
    let rows = sqlx::query_as::<_, BacklogRow>(
        "SELECT \
            ce.id AS event_id, ce.source_device_id, ce.content_kind, \
            ce.inline_ciphertext, ce.blob_id, ce.nonce, \
            ce.mime_hint, ce.size_bytes, ce.created_at \
         FROM clip_deliveries cd \
         JOIN clip_events ce ON ce.id = cd.clip_event_id \
         WHERE cd.target_device_id = ? AND cd.delivered_at IS NULL \
         ORDER BY ce.created_at ASC",
    )
    .bind(auth.device_id)
    .fetch_all(&state.db)
    .await?;

    let mut count = 0;
    for row in rows {
        let content = match row.content_kind.as_str() {
            "inline" => {
                let ct = row.inline_ciphertext.unwrap_or_default();
                ContentRef::Inline {
                    ciphertext_b64: BASE64.encode(&ct),
                    nonce_b64: BASE64.encode(&row.nonce),
                }
            }
            "blob" => ContentRef::Blob {
                blob_id: row.blob_id.unwrap_or_else(Uuid::nil),
                nonce_b64: BASE64.encode(&row.nonce),
                sha256_hex: String::new(),
            },
            other => {
                warn!(kind = %other, "unknown content_kind in backlog row, skipping");
                continue;
            }
        };
        let msg = ServerMessage::ClipEvent(ClipEventMessage {
            id: row.event_id,
            v: rustclip_shared::PROTOCOL_VERSION,
            source_device_id: row.source_device_id,
            content,
            mime_hint: row.mime_hint,
            size_bytes: row.size_bytes,
            created_at: row.created_at,
        });
        send_server(writer, &msg).await?;
        mark_delivered(state, row.event_id, auth.device_id).await?;
        count += 1;
    }
    Ok(count)
}

async fn mark_delivered(state: &AppState, event_id: Uuid, device_id: Uuid) -> sqlx::Result<()> {
    sqlx::query(
        "UPDATE clip_deliveries SET delivered_at = ? \
         WHERE clip_event_id = ? AND target_device_id = ? AND delivered_at IS NULL",
    )
    .bind(now_millis())
    .bind(event_id)
    .bind(device_id)
    .execute(&state.db)
    .await
    .map(|_| ())
}

async fn send_server(
    writer: &mut futures_util::stream::SplitSink<WebSocket, Message>,
    msg: &ServerMessage,
) -> anyhow::Result<()> {
    let text = serde_json::to_string(msg).map_err(|e| anyhow::anyhow!(e))?;
    writer
        .send(Message::Text(text.into()))
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    Ok(())
}
