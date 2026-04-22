use std::{
    env,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};

use anyhow::{Context, Result};

pub const DEFAULT_BIND_ADDR: &str = "0.0.0.0:9123";
pub const DEFAULT_DATA_DIR: &str = "/data";
pub const DEFAULT_MAX_PAYLOAD_BYTES: u64 = 25 * 1024 * 1024;
pub const DEFAULT_OFFLINE_TTL_HOURS: u32 = 24;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Config {
    pub bind_addr: SocketAddr,
    pub data_dir: PathBuf,
    pub public_url: String,
    pub admin_username: Option<String>,
    pub admin_password: Option<String>,
    pub max_payload_bytes: u64,
    pub offline_ttl_hours: u32,
    /// Peer IPs whose `X-Forwarded-For` header is honored when
    /// computing the rate-limit key. Empty = never trust XFF and
    /// always use the socket peer address.
    pub trusted_proxies: Vec<IpAddr>,
    /// Optional bearer token guarding `/metrics`. When `None`, the
    /// endpoint is open (operator is expected to firewall it).
    pub metrics_token: Option<String>,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let bind_addr: SocketAddr = env::var("RUSTCLIP_BIND_ADDR")
            .unwrap_or_else(|_| DEFAULT_BIND_ADDR.to_string())
            .parse()
            .context("RUSTCLIP_BIND_ADDR must be host:port")?;

        let data_dir: PathBuf = env::var("RUSTCLIP_DATA_DIR")
            .unwrap_or_else(|_| DEFAULT_DATA_DIR.to_string())
            .into();

        let public_url =
            env::var("RUSTCLIP_PUBLIC_URL").unwrap_or_else(|_| format!("http://{bind_addr}"));

        let admin_username = env::var("RUSTCLIP_ADMIN_USERNAME")
            .ok()
            .filter(|s| !s.is_empty());
        let admin_password = env::var("RUSTCLIP_ADMIN_PASSWORD")
            .ok()
            .filter(|s| !s.is_empty());

        let max_payload_bytes = env::var("RUSTCLIP_MAX_PAYLOAD_BYTES")
            .ok()
            .map(|s| s.parse::<u64>())
            .transpose()
            .context("RUSTCLIP_MAX_PAYLOAD_BYTES must be an integer")?
            .unwrap_or(DEFAULT_MAX_PAYLOAD_BYTES);

        let offline_ttl_hours = env::var("RUSTCLIP_OFFLINE_TTL_HOURS")
            .ok()
            .map(|s| s.parse::<u32>())
            .transpose()
            .context("RUSTCLIP_OFFLINE_TTL_HOURS must be an integer")?
            .unwrap_or(DEFAULT_OFFLINE_TTL_HOURS);

        let trusted_proxies = env::var("RUSTCLIP_TRUSTED_PROXIES")
            .ok()
            .map(|s| {
                s.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(|s| {
                        s.parse::<IpAddr>()
                            .with_context(|| format!("invalid proxy ip: {s}"))
                    })
                    .collect::<Result<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_default();

        let metrics_token = env::var("RUSTCLIP_METRICS_TOKEN")
            .ok()
            .filter(|s| !s.is_empty());

        Ok(Self {
            bind_addr,
            data_dir,
            public_url,
            admin_username,
            admin_password,
            max_payload_bytes,
            offline_ttl_hours,
            trusted_proxies,
            metrics_token,
        })
    }

    pub fn database_path(&self) -> PathBuf {
        self.data_dir.join("rustclip.db")
    }

    pub fn blobs_dir(&self) -> PathBuf {
        self.data_dir.join("blobs")
    }
}
