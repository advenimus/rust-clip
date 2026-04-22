//! Session-bound CSRF tokens for the admin portal.
//!
//! SameSite=Strict on the session cookie blocks most cross-site form
//! submissions already, but does not cover:
//! - Legacy browsers that don't honor Strict.
//! - Attacks from another tab on the same site (subdomain takeover,
//!   a rogue iframe embed, etc.).
//! - Any attack that rides a browser extension running in the admin's
//!   origin.
//!
//! The scheme here is the classic double-submit pattern bound to the
//! session: a per-session random token is stored in `Session`, echoed
//! into every admin form template, and validated on state-changing
//! requests by this middleware.

use axum::{
    body::{Body, to_bytes},
    extract::{FromRequestParts, Request, State},
    http::{Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use rand::rngs::OsRng;
use subtle::ConstantTimeEq;
use tower_sessions::Session;

use crate::state::AppState;

/// Session key under which we stash the token.
pub const SESSION_KEY: &str = "csrf_token";
/// Form field name we look for on state-changing requests.
pub const FIELD_NAME: &str = "_csrf";
/// Header alternative for XHR/fetch callers that cannot embed a form field.
pub const HEADER_NAME: &str = "x-csrf-token";
/// 32 bytes of entropy, base64url-encoded. Plenty to defeat guessing.
const TOKEN_BYTES: usize = 32;
/// Hard cap on admin request bodies — matches the 1 MiB axum default
/// limit applied to the admin router in `main.rs`. The middleware has
/// to materialize the body to parse the CSRF field, and this cap keeps
/// that memory bounded.
const MAX_ADMIN_BODY_BYTES: usize = 1024 * 1024;

/// Return the current session's CSRF token, creating one lazily if
/// absent. Call this from every admin GET handler before rendering a
/// template that contains a form.
pub async fn ensure_token(session: &Session) -> Result<String, SessionError> {
    if let Some(existing) = session
        .get::<String>(SESSION_KEY)
        .await
        .map_err(|e| SessionError(e.to_string()))?
    {
        return Ok(existing);
    }
    let mut buf = [0u8; TOKEN_BYTES];
    OsRng.fill_bytes(&mut buf);
    let token = URL_SAFE_NO_PAD.encode(buf);
    session
        .insert(SESSION_KEY, &token)
        .await
        .map_err(|e| SessionError(e.to_string()))?;
    Ok(token)
}

#[derive(Debug)]
pub struct SessionError(pub String);

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "csrf session error: {}", self.0)
    }
}

impl std::error::Error for SessionError {}

/// Middleware that validates `_csrf` on every state-changing admin
/// request. Read-only methods (GET/HEAD/OPTIONS) pass through. The
/// admin login form (POST /admin/login) is also validated — the
/// session cookie is created on first GET of `/admin/login` and the
/// token is embedded in the rendered form.
pub async fn csrf_layer(
    State(_state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let method = req.method();
    if matches!(
        method,
        &Method::GET | &Method::HEAD | &Method::OPTIONS | &Method::TRACE
    ) {
        return next.run(req).await;
    }

    // Pull the session out via the application-level session layer so
    // we can read the expected token before consuming the body.
    let (mut parts, body) = req.into_parts();
    let session = match Session::from_request_parts(&mut parts, &_state).await {
        Ok(s) => s,
        Err(_) => return forbidden("missing session"),
    };
    let expected = match session.get::<String>(SESSION_KEY).await {
        Ok(Some(s)) => s,
        Ok(None) => return forbidden("missing csrf token in session"),
        Err(_) => return forbidden("session error"),
    };

    // Prefer the header form; fall back to parsing the body.
    let header_match = parts
        .headers
        .get(HEADER_NAME)
        .and_then(|v| v.to_str().ok())
        .map(|v| ct_eq(v.as_bytes(), expected.as_bytes()));

    if matches!(header_match, Some(true)) {
        let rebuilt = Request::from_parts(parts, body);
        return next.run(rebuilt).await;
    }

    // Materialize the body so we can parse the `_csrf` field, then
    // feed the exact same bytes to the downstream handler.
    let bytes = match to_bytes(body, MAX_ADMIN_BODY_BYTES).await {
        Ok(b) => b,
        Err(_) => return forbidden("failed to read body"),
    };

    let content_type = parts
        .headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let body_match = if content_type.starts_with("application/x-www-form-urlencoded") {
        extract_form_field(&bytes, FIELD_NAME)
            .map(|v| ct_eq(v.as_bytes(), expected.as_bytes()))
            .unwrap_or(false)
    } else {
        // We don't accept multipart, JSON, or other content types on
        // admin routes (header check would have caught API-style
        // callers). Anything else is rejected.
        false
    };

    if !body_match {
        tracing::warn!(path = %parts.uri.path(), "csrf validation failed");
        return forbidden("csrf token missing or invalid");
    }

    let rebuilt = Request::from_parts(parts, Body::from(bytes));
    next.run(rebuilt).await
}

fn forbidden(reason: &'static str) -> Response {
    tracing::warn!(reason, "csrf rejected");
    (StatusCode::FORBIDDEN, "forbidden").into_response()
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        // Still run a constant-time compare on equal-length prefix to
        // avoid leaking length via timing differences on the fast path.
        let _ = a.ct_eq(&b[..a.len().min(b.len())]);
        return false;
    }
    a.ct_eq(b).into()
}

fn extract_form_field(body: &[u8], field: &str) -> Option<String> {
    let s = std::str::from_utf8(body).ok()?;
    for pair in s.split('&') {
        let mut it = pair.splitn(2, '=');
        let k = it.next()?;
        let v = it.next().unwrap_or("");
        if urldecode(k) == field {
            return Some(urldecode(v));
        }
    }
    None
}

fn urldecode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = hex_nibble(bytes[i + 1]);
                let lo = hex_nibble(bytes[i + 2]);
                match (hi, lo) {
                    (Some(h), Some(l)) => {
                        out.push((h << 4) | l);
                        i += 3;
                    }
                    _ => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_csrf_field() {
        let body = b"username=alice&_csrf=abc123&password=hunter2";
        assert_eq!(extract_form_field(body, "_csrf"), Some("abc123".into()));
        assert_eq!(extract_form_field(body, "missing"), None);
    }

    #[test]
    fn urldecode_handles_percent_and_plus() {
        assert_eq!(urldecode("hello+world"), "hello world");
        assert_eq!(urldecode("%2F%3D%21"), "/=!");
        assert_eq!(urldecode("plain"), "plain");
    }

    #[test]
    fn ct_eq_matches_equal() {
        assert!(ct_eq(b"abcd", b"abcd"));
        assert!(!ct_eq(b"abcd", b"abce"));
        assert!(!ct_eq(b"abcd", b"abcde"));
    }
}
