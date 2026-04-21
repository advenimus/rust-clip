use anyhow::Result;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub const TOKEN_BYTES: usize = 32;

/// A freshly generated opaque token plus the server-side hash to persist.
pub struct GeneratedToken {
    pub plaintext: String,
    pub hash: String,
}

pub fn generate_token() -> Result<GeneratedToken> {
    let mut bytes = [0u8; TOKEN_BYTES];
    OsRng.fill_bytes(&mut bytes);
    let plaintext = URL_SAFE_NO_PAD.encode(bytes);
    let hash = hash_token(&plaintext);
    Ok(GeneratedToken { plaintext, hash })
}

pub fn hash_token(plaintext: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(plaintext.as_bytes());
    hex::encode(hasher.finalize())
}

#[allow(dead_code)]
pub fn verify_token(plaintext: &str, stored_hash: &str) -> bool {
    let computed = hash_token(plaintext);
    computed.as_bytes().ct_eq(stored_hash.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let token = generate_token().unwrap();
        assert!(verify_token(&token.plaintext, &token.hash));
        assert!(!verify_token("bogus", &token.hash));
    }

    #[test]
    fn hash_is_deterministic() {
        assert_eq!(hash_token("hello"), hash_token("hello"));
        assert_ne!(hash_token("hello"), hash_token("world"));
    }

    #[test]
    fn plaintext_is_url_safe_base64() {
        let token = generate_token().unwrap();
        for ch in token.plaintext.chars() {
            assert!(
                ch.is_ascii_alphanumeric() || ch == '-' || ch == '_',
                "unexpected char: {ch}"
            );
        }
    }
}
