//! GUI-facing helpers. The CLI `commands` module is fine for terminal UX
//! but prints results to stdout; the GUI needs structured return values.
//! These functions mirror the same operations without side effects on
//! stdout.

use anyhow::{Context, Result, anyhow};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use rand::{RngCore, rngs::OsRng};
use rustclip_shared::rest::{EnrollRequest, LoginRequest, MeResponse};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

use crate::{
    commands,
    config::ClientConfig,
    crypto, files,
    history::{self, History, HistoryItem, HistoryKind},
    http::ServerClient,
    keychain::{self, Credentials},
    sync,
};

const CONTENT_SALT_BYTES: usize = 32;

/// Snapshot of locally-stored credentials. `None` means the device is
/// not enrolled; otherwise the caller can start a sync or call
/// `remote_me` on the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountStatus {
    pub server_url: String,
    pub username: String,
    pub user_id: String,
    pub device_id: String,
}

impl From<&Credentials> for AccountStatus {
    fn from(c: &Credentials) -> Self {
        Self {
            server_url: c.server_url.clone(),
            username: c.username.clone(),
            user_id: c.user_id.clone(),
            device_id: c.device_id.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollInput {
    pub server_url: String,
    pub enrollment_token: String,
    pub password: String,
    pub device_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginInput {
    pub server_url: String,
    pub username: String,
    pub password: String,
    pub device_name: Option<String>,
}

pub fn local_account() -> Result<Option<AccountStatus>> {
    Ok(keychain::load()?.as_ref().map(AccountStatus::from))
}

pub async fn remote_me() -> Result<MeResponse> {
    let creds = keychain::load()?.ok_or_else(|| anyhow!("not enrolled"))?;
    let client = ServerClient::new(&creds.server_url)?;
    client.me(&creds.device_token).await
}

pub async fn enroll(input: EnrollInput) -> Result<AccountStatus> {
    validate_password(&input.password)?;
    let device_name = input
        .device_name
        .unwrap_or_else(commands::default_device_name);
    let content_salt_b64 = random_content_salt();
    let content_salt = BASE64.decode(content_salt_b64.as_bytes())?;
    let content_key = crypto::derive_content_key(&input.password, &content_salt)?;
    let content_key_b64 = BASE64.encode(content_key);

    let client = ServerClient::new(&input.server_url)?;
    let resp = client
        .enroll(&EnrollRequest {
            enrollment_token: input.enrollment_token,
            password: input.password,
            content_salt_b64: content_salt_b64.clone(),
            device_name,
            platform: commands::current_platform().to_string(),
        })
        .await?;

    let creds = Credentials {
        server_url: input.server_url,
        device_token: resp.device_token,
        user_id: resp.user_id.to_string(),
        device_id: resp.device_id.to_string(),
        username: resp.username,
        content_salt_b64,
        content_key_b64,
    };
    keychain::save(&creds)?;
    Ok(AccountStatus::from(&creds))
}

pub async fn login(input: LoginInput) -> Result<AccountStatus> {
    let device_name = input
        .device_name
        .unwrap_or_else(commands::default_device_name);
    let client = ServerClient::new(&input.server_url)?;
    let resp = client
        .login(&LoginRequest {
            username: input.username,
            password: input.password.clone(),
            device_name,
            platform: commands::current_platform().to_string(),
        })
        .await?;

    let content_salt = BASE64.decode(resp.content_salt_b64.as_bytes())?;
    let content_key = crypto::derive_content_key(&input.password, &content_salt)?;
    let content_key_b64 = BASE64.encode(content_key);

    let creds = Credentials {
        server_url: input.server_url,
        device_token: resp.device_token,
        user_id: resp.user_id.to_string(),
        device_id: resp.device_id.to_string(),
        username: resp.username,
        content_salt_b64: resp.content_salt_b64,
        content_key_b64,
    };
    keychain::save(&creds)?;
    Ok(AccountStatus::from(&creds))
}

pub async fn logout() -> Result<()> {
    let creds = keychain::load()?.ok_or_else(|| anyhow!("not enrolled"))?;
    let client = ServerClient::new(&creds.server_url)?;
    let _ = client.logout(&creds.device_token).await;
    keychain::clear()?;
    Ok(())
}

pub fn reset() -> Result<()> {
    keychain::clear()
}

pub struct SyncContext {
    pub server_url: String,
    pub device_token: String,
    pub device_id: Uuid,
    pub content_key: zeroize::Zeroizing<[u8; 32]>,
}

pub fn load_sync_context() -> Result<SyncContext> {
    let creds =
        keychain::load()?.ok_or_else(|| anyhow!("not enrolled; run enroll or login first"))?;
    let device_id = Uuid::parse_str(&creds.device_id).context("parsing device id")?;
    let content_key_bytes = BASE64
        .decode(creds.content_key_b64.as_bytes())
        .context("decoding content key from keychain")?;
    if content_key_bytes.len() != crypto::CONTENT_KEY_BYTES {
        return Err(anyhow!(
            "content key must be {} bytes",
            crypto::CONTENT_KEY_BYTES
        ));
    }
    let mut content_key = zeroize::Zeroizing::new([0u8; 32]);
    content_key.copy_from_slice(&content_key_bytes);
    let mut content_key_bytes = content_key_bytes;
    zeroize::Zeroize::zeroize(&mut content_key_bytes);
    Ok(SyncContext {
        server_url: creds.server_url.clone(),
        device_token: creds.device_token.clone(),
        device_id,
        content_key,
    })
}

pub async fn run_sync(
    ctx: SyncContext,
    clipboard: crate::clipboard::ClipboardHandle,
    event_rx: tokio::sync::mpsc::Receiver<crate::clipboard::ClipEvent>,
) -> Result<()> {
    sync::run(
        ctx.server_url,
        ctx.device_token,
        ctx.device_id,
        ctx.content_key,
        clipboard,
        event_rx,
    )
    .await
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntryView {
    pub id: String,
    pub direction: String,
    pub kind: String,
    pub preview: String,
    pub size_bytes: i64,
    pub created_at: i64,
}

impl From<HistoryItem> for HistoryEntryView {
    fn from(item: HistoryItem) -> Self {
        Self {
            id: item.id.to_string(),
            direction: item.direction.to_string(),
            kind: kind_label(item.kind).into(),
            preview: item.preview,
            size_bytes: item.size_bytes,
            created_at: item.created_at,
        }
    }
}

fn kind_label(k: HistoryKind) -> &'static str {
    match k {
        HistoryKind::Text => "text",
        HistoryKind::Image => "image",
        HistoryKind::Bundle => "bundle",
    }
}

pub fn list_history(limit: i64) -> Result<Vec<HistoryEntryView>> {
    let history = open_history_best_effort()?;
    Ok(history
        .list(limit)?
        .into_iter()
        .map(HistoryEntryView::from)
        .collect())
}

pub fn clear_history() -> Result<()> {
    let mut history = History::open_default()?;
    history.clear()
}

pub fn history_item_text(entry_id: &str) -> Result<Option<String>> {
    let id = Uuid::parse_str(entry_id).context("parsing history id")?;
    let history = open_history_best_effort()?;
    let items = history.list(history::DEFAULT_MAX_ITEMS)?;
    Ok(items
        .into_iter()
        .find(|it| it.id == id && matches!(it.kind, HistoryKind::Text))
        .map(|it| it.preview))
}

/// Look up the kind of a single history row (text / image / bundle).
/// Used by the GUI's unified `cmd_copy_history_item` to dispatch.
/// Returns `Ok(None)` if no such id exists.
pub fn history_item_kind(entry_id: &str) -> Result<Option<HistoryKind>> {
    let id = Uuid::parse_str(entry_id).context("parsing history id")?;
    let history = open_history_best_effort()?;
    let items = history.list(history::DEFAULT_MAX_ITEMS)?;
    Ok(items.into_iter().find(|it| it.id == id).map(|it| it.kind))
}

/// Look up an image-history row and return the decoded RGBA bytes
/// ready for `ClipboardCmd::WriteImage`. Returns `Ok(None)` if the row
/// isn't an image, or if the backing `.enc` file is missing (pre-v0.2.1
/// rows, or a retention-sweep race). Returns `Err` on malformed
/// ciphertext / wrong key.
pub fn history_item_image(entry_id: &str) -> Result<Option<crate::clipboard::ImageBytes>> {
    let id = Uuid::parse_str(entry_id).context("parsing history id")?;
    let history = open_history_best_effort()?;
    // Confirm the row exists and is an image row — callers pass any id
    // here and we want to fail clearly if it's text/bundle.
    let items = history.list(history::DEFAULT_MAX_ITEMS)?;
    let row_is_image = items
        .iter()
        .any(|it| it.id == id && matches!(it.kind, HistoryKind::Image));
    if !row_is_image {
        return Ok(None);
    }
    let Some(store) = history.image_store() else {
        return Ok(None);
    };
    let Some(png_bytes) = store.get(id)? else {
        return Ok(None);
    };
    let image = crate::image_codec::decode_png(&png_bytes)?;
    Ok(Some(image))
}

/// Look up a bundle row and resolve its top-level inbox entries so the
/// caller can push them onto the OS file clipboard. Returns `Ok(None)`
/// if the row isn't a bundle or if the inbox folder is missing
/// (user manually deleted, or a pre-history-retention-cleanup row from
/// a prior version that's been swept).
pub fn history_item_bundle_paths(entry_id: &str) -> Result<Option<Vec<PathBuf>>> {
    let id = Uuid::parse_str(entry_id).context("parsing history id")?;
    let history = open_history_best_effort()?;
    let items = history.list(history::DEFAULT_MAX_ITEMS)?;
    let row_is_bundle = items
        .iter()
        .any(|it| it.id == id && matches!(it.kind, HistoryKind::Bundle));
    if !row_is_bundle {
        return Ok(None);
    }
    let dir = files::inbox_dir().join(id.to_string());
    if !dir.exists() {
        return Ok(None);
    }
    let paths = files::top_level_entries(&dir)?;
    if paths.is_empty() {
        return Ok(None);
    }
    Ok(Some(paths))
}

/// Open the history DB with the preview cipher if the keychain has a
/// content key; fall back to unencrypted mode (encrypted rows become
/// `"(encrypted)"`) if the user isn't currently logged in.
fn open_history_best_effort() -> Result<History> {
    match load_sync_context() {
        Ok(ctx) => History::open_default_with_key(&ctx.content_key),
        Err(_) => History::open_default(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfigView {
    pub auto_sync_files: bool,
    pub auto_sync_max_bytes: u64,
    pub notifications_enabled: bool,
}

impl From<ClientConfig> for ClientConfigView {
    fn from(c: ClientConfig) -> Self {
        Self {
            auto_sync_files: c.auto_sync_files,
            auto_sync_max_bytes: c.auto_sync_max_bytes,
            notifications_enabled: c.notifications_enabled,
        }
    }
}

impl From<ClientConfigView> for ClientConfig {
    fn from(v: ClientConfigView) -> Self {
        Self {
            auto_sync_files: v.auto_sync_files,
            auto_sync_max_bytes: v.auto_sync_max_bytes,
            notifications_enabled: v.notifications_enabled,
        }
    }
}

pub fn get_client_config() -> Result<ClientConfigView> {
    Ok(ClientConfig::load()?.into())
}

pub fn set_client_config(view: ClientConfigView) -> Result<ClientConfigView> {
    let cfg: ClientConfig = view.into();
    cfg.save()?;
    Ok(cfg.into())
}

pub async fn send_files(paths: Vec<PathBuf>) -> Result<Uuid> {
    let ctx = load_sync_context()?;
    let bundle = files::pack(&paths)?;
    let summary = bundle.summary.clone();
    let total_bytes = bundle.total_bytes as i64;
    let cipher = crypto::Cipher::new(&ctx.content_key);
    let event_id = sync::send_bundle_one_shot(
        &ctx.server_url,
        &ctx.device_token,
        ctx.device_id,
        &cipher,
        bundle,
    )
    .await?;

    if let Ok(mut h) = History::open_default_with_key(&ctx.content_key) {
        let _ = h.record_bundle(
            history::Direction::Outgoing,
            &summary,
            total_bytes,
            event_id,
        );
    }
    Ok(event_id)
}

fn random_content_salt() -> String {
    let mut buf = [0u8; CONTENT_SALT_BYTES];
    OsRng.fill_bytes(&mut buf);
    BASE64.encode(buf)
}

fn validate_password(pw: &str) -> Result<()> {
    if pw.len() < 8 {
        return Err(anyhow!("password must be at least 8 characters"));
    }
    Ok(())
}
