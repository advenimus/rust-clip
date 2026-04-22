//! Periodic GitHub release poll that powers the admin portal's "update
//! available" banner. The server never applies updates itself — it only
//! surfaces what the latest published release is. Admins upgrade via
//! `docker compose pull` or Watchtower.

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use serde::Deserialize;
use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::settings::SettingsStore;

pub const CHECK_INTERVAL: Duration = Duration::from_secs(6 * 3600);
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
pub const RELEASES_URL: &str = "https://api.github.com/repos/advenimus/rust-clip/releases/latest";

#[derive(Debug, Clone)]
pub struct LatestRelease {
    pub tag_name: String,
    pub html_url: String,
    pub published_at: String,
    pub body: String,
}

#[derive(Clone, Default)]
pub struct UpdateState {
    inner: Arc<RwLock<Option<LatestRelease>>>,
}

impl UpdateState {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn snapshot(&self) -> Option<LatestRelease> {
        self.inner.read().await.clone()
    }

    pub async fn set(&self, r: Option<LatestRelease>) {
        *self.inner.write().await = r;
    }
}

pub fn spawn(state: UpdateState, settings: SettingsStore) {
    tokio::spawn(async move {
        // Initial delay so boot isn't blocked on an outbound request.
        tokio::time::sleep(Duration::from_secs(10)).await;
        let mut ticker = tokio::time::interval(CHECK_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            let snap = settings.snapshot().await;
            if snap.update_check_enabled {
                match fetch_latest().await {
                    Ok(release) => {
                        debug!(tag = %release.tag_name, "update check ok");
                        state.set(Some(release)).await;
                    }
                    Err(e) => {
                        warn!(error = %e, "update check failed");
                    }
                }
            } else {
                debug!("update check disabled; skipping tick");
                state.set(None).await;
            }
            ticker.tick().await;
        }
    });
}

#[derive(Deserialize)]
struct GithubRelease {
    tag_name: String,
    html_url: String,
    published_at: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
}

async fn fetch_latest() -> Result<LatestRelease> {
    let user_agent = format!("rustclip-server/{}", env!("CARGO_PKG_VERSION"));
    let client = reqwest::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .user_agent(user_agent)
        .build()
        .context("building http client")?;
    let resp = client
        .get(RELEASES_URL)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .context("sending request to github")?;
    if !resp.status().is_success() {
        anyhow::bail!("github returned HTTP {}", resp.status());
    }
    let release: GithubRelease = resp.json().await.context("parsing github response")?;
    if release.draft || release.prerelease {
        anyhow::bail!("latest release is draft/prerelease; skipping");
    }
    Ok(LatestRelease {
        tag_name: release.tag_name,
        html_url: release.html_url,
        published_at: release.published_at,
        body: release.body,
    })
}

/// Returns true iff `latest_tag` parses to a strictly-greater semver than
/// `current`. Both may carry a leading `v`; pre-release suffixes compare per
/// the semver spec. Any parse failure returns false (fail closed — we'd
/// rather hide the banner than render a noisy false positive).
pub fn is_newer(current: &str, latest_tag: &str) -> bool {
    let Some(current_v) = parse_semver(current) else {
        return false;
    };
    let Some(latest_v) = parse_semver(latest_tag) else {
        return false;
    };
    latest_v > current_v
}

fn parse_semver(s: &str) -> Option<semver::Version> {
    let trimmed = s.trim().trim_start_matches('v');
    semver::Version::parse(trimmed).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newer_detects_patch_bump() {
        assert!(is_newer("0.1.2", "v0.1.3"));
        assert!(is_newer("v0.1.2", "0.1.3"));
    }

    #[test]
    fn newer_detects_minor_and_major() {
        assert!(is_newer("0.1.2", "v0.2.0"));
        assert!(is_newer("0.1.2", "v1.0.0"));
    }

    #[test]
    fn equal_is_not_newer() {
        assert!(!is_newer("0.1.2", "v0.1.2"));
        assert!(!is_newer("v0.1.2", "0.1.2"));
    }

    #[test]
    fn older_is_not_newer() {
        assert!(!is_newer("0.2.0", "v0.1.9"));
        assert!(!is_newer("1.0.0", "v0.9.9"));
    }

    #[test]
    fn prerelease_is_older_than_release() {
        // 0.1.3-rc1 < 0.1.3 per semver
        assert!(is_newer("0.1.3-rc1", "v0.1.3"));
        assert!(!is_newer("0.1.3", "v0.1.3-rc1"));
    }

    #[test]
    fn unparseable_is_never_newer() {
        assert!(!is_newer("0.1.2", "not-a-version"));
        assert!(!is_newer("garbage", "v0.1.3"));
    }
}
