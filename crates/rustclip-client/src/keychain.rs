//! OS keychain storage for device credentials.
//!
//! Each entry uses the service `rustclip` and a fixed key name. On macOS this
//! stores in the login keychain; on Windows, Credential Manager; on Linux, the
//! Secret Service API via libsecret / GNOME Keyring / KWallet.

use anyhow::{Context, Result};
use keyring::Entry;

pub const SERVICE: &str = "rustclip";

pub const KEY_SERVER_URL: &str = "server_url";
pub const KEY_DEVICE_TOKEN: &str = "device_token";
pub const KEY_USER_ID: &str = "user_id";
pub const KEY_USERNAME: &str = "username";
pub const KEY_CONTENT_SALT_B64: &str = "content_salt_b64";

pub fn set(key: &str, value: &str) -> Result<()> {
    let entry = Entry::new(SERVICE, key).with_context(|| format!("keychain entry for {key}"))?;
    entry
        .set_password(value)
        .with_context(|| format!("keychain set {key}"))
}

pub fn get(key: &str) -> Result<Option<String>> {
    let entry = Entry::new(SERVICE, key).with_context(|| format!("keychain entry for {key}"))?;
    match entry.get_password() {
        Ok(v) => Ok(Some(v)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(anyhow::anyhow!(e)).with_context(|| format!("keychain get {key}")),
    }
}

pub fn delete(key: &str) -> Result<()> {
    let entry = Entry::new(SERVICE, key).with_context(|| format!("keychain entry for {key}"))?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(anyhow::anyhow!(e)).with_context(|| format!("keychain delete {key}")),
    }
}

pub fn clear_all() -> Result<()> {
    for k in [
        KEY_SERVER_URL,
        KEY_DEVICE_TOKEN,
        KEY_USER_ID,
        KEY_USERNAME,
        KEY_CONTENT_SALT_B64,
    ] {
        delete(k)?;
    }
    Ok(())
}
