//! Shared types and primitives used by the RustClip server and client.
//!
//! Kept dependency-light so both sides depend on it without pulling in
//! runtime-specific machinery (no tokio, no reqwest, no sqlx).

pub mod protocol;
pub mod rest;

/// Wire protocol version.
///
/// v2 (current): AEAD binds envelope metadata as AAD — `id`, a
///   client-populated `source_device_id`, `mime_hint`, `size_bytes`,
///   `created_at`, and the content-kind tag (plus `blob_id` for
///   blob events). Tampering with any of those now fails Poly1305.
///
/// v1: no AAD binding. Ciphertexts produced under v1 cannot be
///   decrypted by v2 clients; pre-upgrade buffered events age out
///   naturally inside the offline-TTL window.
pub const PROTOCOL_VERSION: u32 = 2;

/// Maximum ciphertext size that may ride inline on a WS `clip_event`. Larger
/// payloads must be uploaded via the blob REST endpoint and referenced by id.
pub const MAX_INLINE_CIPHERTEXT_BYTES: usize = 64 * 1024;

pub const PLATFORM_WINDOWS: &str = "windows";
pub const PLATFORM_MACOS: &str = "macos";
pub const PLATFORM_LINUX: &str = "linux";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_version_is_v2() {
        assert_eq!(PROTOCOL_VERSION, 2);
    }
}
