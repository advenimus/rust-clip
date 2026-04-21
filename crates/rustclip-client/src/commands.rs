//! Implementations for each CLI subcommand.

use anyhow::{Context, Result, anyhow};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use rand::{RngCore, rngs::OsRng};
use rustclip_shared::rest::{EnrollRequest, LoginRequest};
use uuid::Uuid;

use std::path::PathBuf;

use crate::{crypto, files, history::History, http::ServerClient, keychain, sync};

const CONTENT_SALT_BYTES: usize = 32;

pub fn default_device_name() -> String {
    gethostname::gethostname().to_string_lossy().into_owned()
}

pub fn current_platform() -> &'static str {
    if cfg!(target_os = "macos") {
        rustclip_shared::PLATFORM_MACOS
    } else if cfg!(target_os = "windows") {
        rustclip_shared::PLATFORM_WINDOWS
    } else {
        rustclip_shared::PLATFORM_LINUX
    }
}

fn read_password(prompt: &str) -> Result<String> {
    rpassword::prompt_password(prompt).context("reading password")
}

fn read_secret(prompt: &str) -> Result<String> {
    rpassword::prompt_password(prompt).context("reading secret")
}

fn random_content_salt() -> String {
    let mut buf = [0u8; CONTENT_SALT_BYTES];
    OsRng.fill_bytes(&mut buf);
    BASE64.encode(buf)
}

pub async fn enroll(
    server_url: String,
    device_name: Option<String>,
    enrollment_token_opt: Option<String>,
    password_opt: Option<String>,
) -> Result<()> {
    let device_name = device_name.unwrap_or_else(default_device_name);
    let enrollment_token = match enrollment_token_opt {
        Some(t) => t,
        None => read_secret("Enrollment token: ")?,
    };
    let password = match password_opt {
        Some(p) => p,
        None => {
            let p = read_password("Choose a password: ")?;
            let confirm = read_password("Confirm password: ")?;
            if p != confirm {
                return Err(anyhow!("passwords did not match"));
            }
            p
        }
    };
    if password.len() < 8 {
        return Err(anyhow!("password must be at least 8 characters"));
    }
    let content_salt_b64 = random_content_salt();
    let content_salt = BASE64.decode(content_salt_b64.as_bytes())?;
    let content_key = crypto::derive_content_key(&password, &content_salt)?;
    let content_key_b64 = BASE64.encode(content_key);

    let client = ServerClient::new(&server_url)?;
    let resp = client
        .enroll(&EnrollRequest {
            enrollment_token,
            password,
            content_salt_b64: content_salt_b64.clone(),
            device_name: device_name.clone(),
            platform: current_platform().to_string(),
        })
        .await?;

    persist_credentials(
        &server_url,
        &resp.device_token,
        &resp.user_id.to_string(),
        &resp.device_id.to_string(),
        &resp.username,
        &content_salt_b64,
        &content_key_b64,
    )?;

    println!("enrolled as {} ({})", resp.display_name, resp.username);
    println!("device id: {}", resp.device_id);
    println!("credentials stored in system keychain.");
    println!("start syncing with: rustclip-client sync");
    Ok(())
}

pub async fn login(
    server_url: String,
    username: String,
    device_name: Option<String>,
    password_opt: Option<String>,
) -> Result<()> {
    let device_name = device_name.unwrap_or_else(default_device_name);
    let password = match password_opt {
        Some(p) => p,
        None => read_password("Password: ")?,
    };

    let client = ServerClient::new(&server_url)?;
    let resp = client
        .login(&LoginRequest {
            username,
            password: password.clone(),
            device_name: device_name.clone(),
            platform: current_platform().to_string(),
        })
        .await?;

    let content_salt = BASE64.decode(resp.content_salt_b64.as_bytes())?;
    let content_key = crypto::derive_content_key(&password, &content_salt)?;
    let content_key_b64 = BASE64.encode(content_key);

    persist_credentials(
        &server_url,
        &resp.device_token,
        &resp.user_id.to_string(),
        &resp.device_id.to_string(),
        &resp.username,
        &resp.content_salt_b64,
        &content_key_b64,
    )?;

    println!("logged in as {} ({})", resp.display_name, resp.username);
    println!("device id: {}", resp.device_id);
    println!("credentials stored in system keychain.");
    println!("start syncing with: rustclip-client sync");
    Ok(())
}

pub async fn sync_cmd() -> Result<()> {
    let server_url = keychain::get(keychain::KEY_SERVER_URL)?
        .ok_or_else(|| anyhow!("not enrolled; run `enroll` or `login` first"))?;
    let device_token = keychain::get(keychain::KEY_DEVICE_TOKEN)?
        .ok_or_else(|| anyhow!("no device token stored"))?;
    let device_id_str =
        keychain::get(keychain::KEY_DEVICE_ID)?.ok_or_else(|| anyhow!("no device id stored"))?;
    let device_id = Uuid::parse_str(&device_id_str).context("parsing device id")?;
    let content_key_b64 = keychain::get(keychain::KEY_CONTENT_KEY_B64)?
        .ok_or_else(|| anyhow!("no content key stored; re-login to rebuild"))?;
    let content_key_bytes = BASE64
        .decode(content_key_b64.as_bytes())
        .context("decoding content key from keychain")?;
    if content_key_bytes.len() != crypto::CONTENT_KEY_BYTES {
        return Err(anyhow!(
            "content key must be {} bytes",
            crypto::CONTENT_KEY_BYTES
        ));
    }
    let mut content_key = [0u8; 32];
    content_key.copy_from_slice(&content_key_bytes);

    println!("connecting to {server_url}");
    sync::run(server_url, device_token, device_id, content_key).await
}

pub async fn status() -> Result<()> {
    let server_url = keychain::get(keychain::KEY_SERVER_URL)?
        .ok_or_else(|| anyhow!("no server configured; run `enroll` or `login` first"))?;
    let token = keychain::get(keychain::KEY_DEVICE_TOKEN)?
        .ok_or_else(|| anyhow!("no device token stored"))?;

    let client = ServerClient::new(&server_url)?;
    let me = client.me(&token).await?;
    println!("server: {server_url}");
    println!("user: {} ({})", me.display_name, me.username);
    println!("device: {} [{}]", me.device.device_name, me.device.platform);
    println!("device id: {}", me.device.device_id);
    Ok(())
}

pub async fn logout() -> Result<()> {
    let server_url =
        keychain::get(keychain::KEY_SERVER_URL)?.ok_or_else(|| anyhow!("no server configured"))?;
    let token = keychain::get(keychain::KEY_DEVICE_TOKEN)?
        .ok_or_else(|| anyhow!("no device token stored"))?;

    let client = ServerClient::new(&server_url)?;
    if let Err(e) = client.logout(&token).await {
        eprintln!("warning: server-side logout failed: {e}");
    }
    keychain::clear_all()?;
    println!("signed out and cleared keychain.");
    Ok(())
}

pub fn reset() -> Result<()> {
    keychain::clear_all()?;
    println!("cleared local keychain entries.");
    Ok(())
}

pub fn show_history(limit: i64) -> Result<()> {
    let history = History::open_default()?;
    let items = history.list(limit)?;
    if items.is_empty() {
        println!("history is empty.");
        return Ok(());
    }
    for item in items {
        let when = format_millis(item.created_at);
        let kind = match item.kind {
            crate::history::HistoryKind::Text => "text",
            crate::history::HistoryKind::Image => "image",
            crate::history::HistoryKind::Bundle => "bundle",
        };
        println!(
            "{when} [{dir:<8}] {kind:<6} {size:>8} B  {preview}",
            dir = item.direction,
            size = item.size_bytes,
            preview = item.preview.replace('\n', " "),
        );
    }
    Ok(())
}

pub fn clear_history() -> Result<()> {
    let mut history = History::open_default()?;
    history.clear()?;
    println!("history cleared.");
    Ok(())
}

fn format_millis(ms: i64) -> String {
    use time::{OffsetDateTime, format_description::well_known::Rfc3339};
    OffsetDateTime::from_unix_timestamp_nanos((ms as i128) * 1_000_000)
        .ok()
        .and_then(|dt| dt.format(&Rfc3339).ok())
        .unwrap_or_else(|| ms.to_string())
}

pub async fn send_files(paths: Vec<PathBuf>) -> Result<()> {
    let server_url = keychain::get(keychain::KEY_SERVER_URL)?
        .ok_or_else(|| anyhow!("not enrolled; run `enroll` or `login` first"))?;
    let device_token = keychain::get(keychain::KEY_DEVICE_TOKEN)?
        .ok_or_else(|| anyhow!("no device token stored"))?;
    let content_key_b64 = keychain::get(keychain::KEY_CONTENT_KEY_B64)?
        .ok_or_else(|| anyhow!("no content key stored; re-login to rebuild"))?;
    let content_key_bytes = BASE64
        .decode(content_key_b64.as_bytes())
        .context("decoding content key from keychain")?;
    if content_key_bytes.len() != crypto::CONTENT_KEY_BYTES {
        return Err(anyhow!(
            "content key must be {} bytes",
            crypto::CONTENT_KEY_BYTES
        ));
    }
    let mut content_key = [0u8; 32];
    content_key.copy_from_slice(&content_key_bytes);

    let bundle = files::pack(&paths)?;
    println!(
        "packed {} ({} bytes uncompressed)",
        bundle.summary, bundle.total_bytes
    );

    let summary = bundle.summary.clone();
    let total_bytes = bundle.total_bytes as i64;
    let cipher = crypto::Cipher::new(&content_key);
    let event_id = sync::send_bundle_one_shot(&server_url, &device_token, &cipher, bundle).await?;

    if let Ok(mut h) = History::open_default() {
        let _ = h.record_bundle(
            crate::history::Direction::Outgoing,
            &summary,
            total_bytes,
            event_id,
        );
    }
    println!("sent.");
    Ok(())
}

fn persist_credentials(
    server_url: &str,
    device_token: &str,
    user_id: &str,
    device_id: &str,
    username: &str,
    content_salt_b64: &str,
    content_key_b64: &str,
) -> Result<()> {
    keychain::set(keychain::KEY_SERVER_URL, server_url)?;
    keychain::set(keychain::KEY_DEVICE_TOKEN, device_token)?;
    keychain::set(keychain::KEY_USER_ID, user_id)?;
    keychain::set(keychain::KEY_DEVICE_ID, device_id)?;
    keychain::set(keychain::KEY_USERNAME, username)?;
    keychain::set(keychain::KEY_CONTENT_SALT_B64, content_salt_b64)?;
    keychain::set(keychain::KEY_CONTENT_KEY_B64, content_key_b64)?;
    Ok(())
}
