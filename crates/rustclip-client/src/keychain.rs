//! OS keychain storage for device credentials.
//!
//! We pack every credential field into a single JSON blob stored as one
//! keychain item. Rationale: on macOS the Security framework raises an
//! access-control prompt per-item, so storing 7 fields as 7 separate
//! items meant 7 password prompts on each launch (and 7 separate "Always
//! Allow" clicks to silence them). A single item means one prompt ever.
//!
//! An in-process cache also memoizes the decrypted blob so repeated
//! lookups within the running app don't touch the Security framework
//! again. The cache is invalidated on save() and clear().
//!
//! Storage backend: `keyring` crate. On macOS this lands in the login
//! keychain; on Windows it uses Credential Manager; on Linux it talks
//! to Secret Service via libsecret / GNOME Keyring / KWallet.

use std::sync::{Mutex, OnceLock};

use anyhow::{Context, Result};
use keyring::Entry;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub const SERVICE: &str = "rustclip";
pub const ACCOUNT: &str = "credentials";

/// Everything the client needs to talk to the server and decrypt
/// content, stored as one keychain item.
///
/// M1: the struct carries the derived content key as base64. On
/// logout and on cache invalidation we proactively zeroize the
/// secret fields before the allocations are freed. Plain `Drop` on
/// `String` leaves the heap bytes recoverable by a debugger or a
/// core dump; `Zeroize` overwrites them first.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credentials {
    pub server_url: String,
    pub device_token: String,
    pub user_id: String,
    pub device_id: String,
    pub username: String,
    pub content_salt_b64: String,
    pub content_key_b64: String,
}

impl Credentials {
    /// Wipe the fields that carry long-term secret material. Non-
    /// secret fields (usernames, ids, server URL) are left alone —
    /// they don't merit the cost of reallocating on every load.
    fn zeroize_secrets(&mut self) {
        self.device_token.zeroize();
        self.content_salt_b64.zeroize();
        self.content_key_b64.zeroize();
    }
}

impl Drop for Credentials {
    fn drop(&mut self) {
        self.zeroize_secrets();
    }
}

// None = not yet read. Some(None) = read, no entry stored. Some(Some(..)) = cached.
static CACHE: OnceLock<Mutex<Option<Option<Credentials>>>> = OnceLock::new();

fn cache_cell() -> &'static Mutex<Option<Option<Credentials>>> {
    CACHE.get_or_init(|| Mutex::new(None))
}

fn entry() -> Result<Entry> {
    Entry::new(SERVICE, ACCOUNT).context("opening keychain entry")
}

/// Load credentials, returning `None` if the device isn't enrolled.
/// Subsequent calls within the same process return a cached copy and
/// do not hit the OS keychain.
pub fn load() -> Result<Option<Credentials>> {
    {
        let guard = cache_cell().lock().unwrap();
        if let Some(cached) = guard.as_ref() {
            return Ok(cached.clone());
        }
    }
    let e = entry()?;
    let result = match e.get_password() {
        Ok(json) => {
            Some(serde_json::from_str::<Credentials>(&json).context("parsing keychain JSON")?)
        }
        Err(keyring::Error::NoEntry) => None,
        Err(err) => return Err(anyhow::anyhow!(err)).context("keychain load"),
    };
    *cache_cell().lock().unwrap() = Some(result.clone());
    Ok(result)
}

/// Persist credentials. Overwrites any existing entry.
pub fn save(creds: &Credentials) -> Result<()> {
    let json = serde_json::to_string(creds).context("serializing credentials")?;
    let e = entry()?;
    e.set_password(&json).context("keychain save")?;
    *cache_cell().lock().unwrap() = Some(Some(creds.clone()));
    Ok(())
}

/// Remove any stored credentials. Idempotent — returns Ok even if no
/// entry was present. Zeroizes any cached copy in-process so a
/// subsequent core dump can't recover the content key.
pub fn clear() -> Result<()> {
    let e = entry()?;
    match e.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => {}
        Err(err) => return Err(anyhow::anyhow!(err)).context("keychain clear"),
    }
    let mut guard = cache_cell().lock().unwrap();
    if let Some(Some(mut prev)) = guard.take() {
        // `prev` was the cached Credentials; Drop will zeroize its
        // secret fields but the explicit call is defense-in-depth
        // in case someone later weakens the Drop impl.
        prev.zeroize_secrets();
    }
    *guard = Some(None);
    Ok(())
}

/// Force the next `load()` call to hit the OS keychain again. Call
/// after external state changes (e.g. the user cleared the item via
/// Keychain Access).
#[allow(dead_code)]
pub fn invalidate_cache() {
    *cache_cell().lock().unwrap() = None;
}
