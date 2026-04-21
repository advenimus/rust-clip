//! WebSocket protocol shared between client and server.
//!
//! Every message is a JSON object with a `type` discriminator and a `v`
//! protocol version tag at the top level. Payload content (ciphertext, nonce)
//! is base64-encoded because JSON cannot carry binary natively.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::PROTOCOL_VERSION;

pub const WS_SUBPROTOCOL: &str = "rustclip.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    ClipEvent(ClipEventMessage),
    Ping,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    ClipEvent(ClipEventMessage),
    Ack { id: Uuid },
    BacklogStart,
    BacklogEnd,
    Error { code: String, message: String },
    Pong,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClipEventMessage {
    /// Client-generated event id. Also serves as dedupe key for the receiving
    /// side.
    pub id: Uuid,
    /// Protocol version this message was produced against.
    #[serde(default = "default_version")]
    pub v: u32,
    /// Source device id. Absent when a client produces the message; the server
    /// fills it in when broadcasting to peers.
    #[serde(default)]
    pub source_device_id: Option<Uuid>,
    pub content: ContentRef,
    /// Plaintext MIME hint (text/plain, image/png, application/octet-stream, ...).
    pub mime_hint: String,
    pub size_bytes: i64,
    /// Client's wall-clock timestamp (unix milliseconds) at copy time.
    pub created_at: i64,
}

fn default_version() -> u32 {
    PROTOCOL_VERSION
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ContentRef {
    Inline {
        ciphertext_b64: String,
        nonce_b64: String,
    },
    Blob {
        blob_id: Uuid,
        nonce_b64: String,
        sha256_hex: String,
    },
}

impl ContentRef {
    pub fn is_inline(&self) -> bool {
        matches!(self, Self::Inline { .. })
    }
    pub fn is_blob(&self) -> bool {
        matches!(self, Self::Blob { .. })
    }
}

pub const MIME_TEXT: &str = "text/plain; charset=utf-8";
pub const MIME_PNG: &str = "image/png";
pub const MIME_BUNDLE: &str = "application/x-rustclip-bundle";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clip_event_roundtrip() {
        let msg = ClipEventMessage {
            id: Uuid::nil(),
            v: PROTOCOL_VERSION,
            source_device_id: None,
            content: ContentRef::Inline {
                ciphertext_b64: "aGVsbG8=".into(),
                nonce_b64: "bm9uY2U=".into(),
            },
            mime_hint: MIME_TEXT.into(),
            size_bytes: 5,
            created_at: 0,
        };
        let s = serde_json::to_string(&ClientMessage::ClipEvent(msg.clone())).unwrap();
        let back: ClientMessage = serde_json::from_str(&s).unwrap();
        match back {
            ClientMessage::ClipEvent(roundtripped) => {
                assert_eq!(roundtripped.mime_hint, msg.mime_hint);
                assert!(roundtripped.content.is_inline());
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn server_message_ack() {
        let s = serde_json::to_string(&ServerMessage::Ack { id: Uuid::nil() }).unwrap();
        assert!(s.contains("\"type\":\"ack\""));
        let back: ServerMessage = serde_json::from_str(&s).unwrap();
        assert!(matches!(back, ServerMessage::Ack { .. }));
    }
}
