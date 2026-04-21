//! Shared types and primitives used by the RustClip server and client.
//!
//! Kept dependency-light so both sides depend on it without pulling in
//! runtime-specific machinery (no tokio, no reqwest, no sqlx).

pub mod protocol;
pub mod rest;

pub const PROTOCOL_VERSION: u32 = 1;

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
    fn protocol_version_is_v1() {
        assert_eq!(PROTOCOL_VERSION, 1);
    }
}
