//! Implementations for each CLI subcommand.

use anyhow::{Context, Result, anyhow};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use rand::{RngCore, rngs::OsRng};
use rustclip_shared::rest::{EnrollRequest, LoginRequest};

use crate::{http::ServerClient, keychain};

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

pub async fn enroll(server_url: String, device_name: Option<String>) -> Result<()> {
    let device_name = device_name.unwrap_or_else(default_device_name);
    let enrollment_token = read_secret("Enrollment token: ")?;
    let password = read_password("Choose a password: ")?;
    let confirm = read_password("Confirm password: ")?;
    if password != confirm {
        return Err(anyhow!("passwords did not match"));
    }
    if password.len() < 8 {
        return Err(anyhow!("password must be at least 8 characters"));
    }
    let content_salt_b64 = random_content_salt();

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
        &resp.username,
        &content_salt_b64,
    )?;

    println!("enrolled as {} ({})", resp.display_name, resp.username);
    println!("device id: {}", resp.device_id);
    println!("device token stored in system keychain.");
    Ok(())
}

pub async fn login(
    server_url: String,
    username: String,
    device_name: Option<String>,
) -> Result<()> {
    let device_name = device_name.unwrap_or_else(default_device_name);
    let password = read_password("Password: ")?;

    let client = ServerClient::new(&server_url)?;
    let resp = client
        .login(&LoginRequest {
            username,
            password,
            device_name: device_name.clone(),
            platform: current_platform().to_string(),
        })
        .await?;

    persist_credentials(
        &server_url,
        &resp.device_token,
        &resp.user_id.to_string(),
        &resp.username,
        &resp.content_salt_b64,
    )?;

    println!("logged in as {} ({})", resp.display_name, resp.username);
    println!("device id: {}", resp.device_id);
    println!("device token stored in system keychain.");
    Ok(())
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

fn persist_credentials(
    server_url: &str,
    device_token: &str,
    user_id: &str,
    username: &str,
    content_salt_b64: &str,
) -> Result<()> {
    keychain::set(keychain::KEY_SERVER_URL, server_url)?;
    keychain::set(keychain::KEY_DEVICE_TOKEN, device_token)?;
    keychain::set(keychain::KEY_USER_ID, user_id)?;
    keychain::set(keychain::KEY_USERNAME, username)?;
    keychain::set(keychain::KEY_CONTENT_SALT_B64, content_salt_b64)?;
    Ok(())
}
