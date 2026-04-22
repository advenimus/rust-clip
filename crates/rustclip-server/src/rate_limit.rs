//! In-process token-bucket rate limiter keyed by an opaque string.
//!
//! Used for per-IP throttling on auth endpoints. Buckets are lazily
//! created and periodically pruned so quiet clients don't pin memory.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use tokio::sync::Mutex;

use crate::state::AppState;

#[derive(Debug, Clone, Copy)]
pub struct RateLimitConfig {
    pub capacity: f64,
    pub refill_per_sec: f64,
}

impl RateLimitConfig {
    pub const fn new(capacity: f64, refill_per_sec: f64) -> Self {
        Self {
            capacity,
            refill_per_sec,
        }
    }
}

pub const ADMIN_LOGIN_LIMIT: RateLimitConfig = RateLimitConfig::new(10.0, 10.0 / 60.0);
pub const AUTH_API_LIMIT: RateLimitConfig = RateLimitConfig::new(10.0, 10.0 / 60.0);
/// Per-username admin-login lockout: 5 attempts, then one refill every
/// 5 minutes. Harder than the per-IP limit because it ignores XFF
/// spoofing and bot-net distribution.
pub const ADMIN_USERNAME_LOCKOUT: RateLimitConfig = RateLimitConfig::new(5.0, 1.0 / 300.0);
/// Per-device blob upload limit: 20-burst then one every 6 seconds.
pub const BLOB_UPLOAD_LIMIT: RateLimitConfig = RateLimitConfig::new(20.0, 10.0 / 60.0);

struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

impl Bucket {
    fn new(cap: f64) -> Self {
        Self {
            tokens: cap,
            last_refill: Instant::now(),
        }
    }
}

#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<Mutex<HashMap<String, Bucket>>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn check(&self, key: &str, cfg: RateLimitConfig) -> bool {
        let mut map = self.inner.lock().await;
        let now = Instant::now();
        let bucket = map
            .entry(key.to_string())
            .or_insert_with(|| Bucket::new(cfg.capacity));
        let elapsed = now
            .saturating_duration_since(bucket.last_refill)
            .as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * cfg.refill_per_sec).min(cfg.capacity);
        bucket.last_refill = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    pub async fn prune_full(&self, cfg: RateLimitConfig) {
        let mut map = self.inner.lock().await;
        let now = Instant::now();
        map.retain(|_, bucket| {
            let elapsed = now
                .saturating_duration_since(bucket.last_refill)
                .as_secs_f64();
            let projected = (bucket.tokens + elapsed * cfg.refill_per_sec).min(cfg.capacity);
            // Keep a bucket only while it still has a deficit. Fully recovered
            // buckets add no value because a new bucket starts at capacity.
            projected < cfg.capacity
        });
    }

    pub fn spawn_pruner(self, cfg: RateLimitConfig, interval: Duration) {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                self.prune_full(cfg).await;
            }
        });
    }
}

/// Resolve the client IP that rate limits should be keyed on.
///
/// Trust rules:
/// - If the socket peer is in `trusted_proxies`, honor the first value
///   in `X-Forwarded-For` (that's the originating client per RFC 7239).
/// - Otherwise use the socket peer address directly — an attacker
///   cannot spoof this without controlling the network path.
///
/// Returns a stable string identifier suitable for use as a bucket key.
pub fn resolve_client_ip(
    headers: &HeaderMap,
    peer: SocketAddr,
    trusted_proxies: &[IpAddr],
) -> String {
    if trusted_proxies.contains(&peer.ip()) {
        if let Some(xff) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return xff.to_string();
        }
    }
    peer.ip().to_string()
}

pub async fn admin_login_layer(
    State(state): State<AppState>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    limit_non_get(
        &state.auth_limiter,
        ADMIN_LOGIN_LIMIT,
        &state.config.trusted_proxies,
        req,
        next,
        "admin_login",
    )
    .await
}

pub async fn auth_api_layer(
    State(state): State<AppState>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    limit_non_get(
        &state.auth_limiter,
        AUTH_API_LIMIT,
        &state.config.trusted_proxies,
        req,
        next,
        "auth_api",
    )
    .await
}

async fn limit_non_get(
    limiter: &RateLimiter,
    cfg: RateLimitConfig,
    trusted_proxies: &[IpAddr],
    req: Request<axum::body::Body>,
    next: Next,
    scope: &'static str,
) -> Response {
    if req.method() == axum::http::Method::GET {
        return next.run(req).await;
    }
    // The connecting socket peer is attached as a request extension by
    // axum when the server is started via
    // `into_make_service_with_connect_info::<SocketAddr>()`. Extract it
    // manually here to sidestep the middleware-extractor tuple limits.
    let peer_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(s)| resolve_client_ip(req.headers(), *s, trusted_proxies))
        .unwrap_or_else(|| "unknown".to_string());
    let key = format!("{scope}:{peer_ip}");
    if !limiter.check(&key, cfg).await {
        tracing::warn!(scope, ip = %peer_ip, "rate limit exceeded");
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(
                axum::http::header::RETRY_AFTER,
                axum::http::HeaderValue::from_static("60"),
            )],
            "rate limit exceeded",
        )
            .into_response();
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn allows_until_capacity_then_blocks() {
        let cfg = RateLimitConfig::new(3.0, 0.0001);
        let limiter = RateLimiter::new();
        for _ in 0..3 {
            assert!(limiter.check("ip", cfg).await);
        }
        assert!(!limiter.check("ip", cfg).await);
    }

    #[tokio::test]
    async fn refills_over_time() {
        let cfg = RateLimitConfig::new(1.0, 50.0);
        let limiter = RateLimiter::new();
        assert!(limiter.check("ip", cfg).await);
        assert!(!limiter.check("ip", cfg).await);
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(limiter.check("ip", cfg).await, "should refill after 40ms");
    }

    #[tokio::test]
    async fn independent_keys() {
        let cfg = RateLimitConfig::new(1.0, 0.0001);
        let limiter = RateLimiter::new();
        assert!(limiter.check("a", cfg).await);
        assert!(limiter.check("b", cfg).await);
        assert!(!limiter.check("a", cfg).await);
        assert!(!limiter.check("b", cfg).await);
    }

    #[tokio::test]
    async fn prune_full_removes_recovered_buckets() {
        let cfg = RateLimitConfig::new(2.0, 1000.0);
        let limiter = RateLimiter::new();
        limiter.check("a", cfg).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        limiter.prune_full(cfg).await;
        let map = limiter.inner.lock().await;
        assert!(
            !map.contains_key("a"),
            "fully-refilled bucket should be pruned"
        );
    }
}
