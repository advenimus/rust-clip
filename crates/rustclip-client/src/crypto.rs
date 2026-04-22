//! Client-side content-key derivation and payload encryption.

use anyhow::{Result, anyhow};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, AeadCore, OsRng as AeadOsRng, Payload},
};

pub const CONTENT_KEY_BYTES: usize = 32;
pub const CONTENT_SALT_BYTES: usize = 32;
pub const NONCE_BYTES: usize = 24;

/// Same Argon2id parameters the server rejects against. Keep these in sync.
pub fn derive_content_key(password: &str, content_salt: &[u8]) -> Result<[u8; CONTENT_KEY_BYTES]> {
    if content_salt.len() != CONTENT_SALT_BYTES {
        return Err(anyhow!(
            "content salt must be {CONTENT_SALT_BYTES} bytes, got {}",
            content_salt.len()
        ));
    }
    let params = Params::new(65536, 3, 4, Some(CONTENT_KEY_BYTES))
        .map_err(|e| anyhow!("argon2 params: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; CONTENT_KEY_BYTES];
    argon
        .hash_password_into(password.as_bytes(), content_salt, &mut key)
        .map_err(|e| anyhow!("argon2 derive: {e}"))?;
    Ok(key)
}

pub struct Cipher {
    aead: XChaCha20Poly1305,
}

impl Cipher {
    pub fn new(key: &[u8; CONTENT_KEY_BYTES]) -> Self {
        Self {
            aead: XChaCha20Poly1305::new(key.into()),
        }
    }

    /// Encrypt `plaintext` with the given `aad` (authenticated but not
    /// encrypted). Returns `(nonce, ciphertext_with_tag)`. The AAD is
    /// required on decrypt; if it differs, Poly1305 rejects.
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let nonce = XChaCha20Poly1305::generate_nonce(&mut AeadOsRng);
        let ciphertext = self
            .aead
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| anyhow!("encryption failed"))?;
        Ok((nonce.to_vec(), ciphertext))
    }

    pub fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if nonce.len() != NONCE_BYTES {
            return Err(anyhow!("nonce must be {NONCE_BYTES} bytes"));
        }
        let nonce = XNonce::from_slice(nonce);
        self.aead
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| anyhow!("decryption failed (wrong key, wrong aad, or tampered payload)"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [7u8; CONTENT_KEY_BYTES];
        let c = Cipher::new(&key);
        let (nonce, ct) = c.encrypt(b"hello world", b"aad").unwrap();
        let pt = c.decrypt(&nonce, &ct, b"aad").unwrap();
        assert_eq!(pt, b"hello world");
    }

    #[test]
    fn decrypt_fails_with_wrong_key() {
        let k1 = [7u8; CONTENT_KEY_BYTES];
        let k2 = [8u8; CONTENT_KEY_BYTES];
        let (nonce, ct) = Cipher::new(&k1).encrypt(b"secret", b"aad").unwrap();
        assert!(Cipher::new(&k2).decrypt(&nonce, &ct, b"aad").is_err());
    }

    #[test]
    fn decrypt_fails_with_wrong_aad() {
        let key = [7u8; CONTENT_KEY_BYTES];
        let c = Cipher::new(&key);
        let (nonce, ct) = c.encrypt(b"secret", b"original-aad").unwrap();
        assert!(c.decrypt(&nonce, &ct, b"tampered-aad").is_err());
        assert!(c.decrypt(&nonce, &ct, b"").is_err());
    }

    #[test]
    fn derive_is_deterministic_for_same_inputs() {
        let salt = [3u8; CONTENT_SALT_BYTES];
        let k1 = derive_content_key("pw", &salt).unwrap();
        let k2 = derive_content_key("pw", &salt).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn derive_differs_for_different_salts() {
        let s1 = [1u8; CONTENT_SALT_BYTES];
        let s2 = [2u8; CONTENT_SALT_BYTES];
        let k1 = derive_content_key("pw", &s1).unwrap();
        let k2 = derive_content_key("pw", &s2).unwrap();
        assert_ne!(k1, k2);
    }
}
