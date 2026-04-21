//! Thin HTTP client that talks to the RustClip server.

use anyhow::{Context, Result, anyhow};
use reqwest::{Client, StatusCode};
use rustclip_shared::rest::{
    EnrollRequest, EnrollResponse, ErrorResponse, LoginRequest, LoginResponse, MeResponse,
};
use std::time::Duration;

pub struct ServerClient {
    http: Client,
    base_url: String,
}

impl ServerClient {
    pub fn new(base_url: impl Into<String>) -> Result<Self> {
        let http = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("rustclip-client/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("building http client")?;
        Ok(Self {
            http,
            base_url: base_url.into().trim_end_matches('/').to_string(),
        })
    }

    pub async fn enroll(&self, req: &EnrollRequest) -> Result<EnrollResponse> {
        let url = format!("{}/api/v1/auth/enroll", self.base_url);
        let resp = self.http.post(&url).json(req).send().await?;
        parse_json(resp).await
    }

    pub async fn login(&self, req: &LoginRequest) -> Result<LoginResponse> {
        let url = format!("{}/api/v1/auth/login", self.base_url);
        let resp = self.http.post(&url).json(req).send().await?;
        parse_json(resp).await
    }

    pub async fn me(&self, token: &str) -> Result<MeResponse> {
        let url = format!("{}/api/v1/me", self.base_url);
        let resp = self.http.get(&url).bearer_auth(token).send().await?;
        parse_json(resp).await
    }

    pub async fn logout(&self, token: &str) -> Result<()> {
        let url = format!("{}/api/v1/auth/logout", self.base_url);
        let resp = self.http.post(&url).bearer_auth(token).send().await?;
        if !resp.status().is_success() {
            let e = extract_error(resp).await?;
            return Err(anyhow!(e));
        }
        Ok(())
    }
}

async fn parse_json<T: serde::de::DeserializeOwned>(resp: reqwest::Response) -> Result<T> {
    let status = resp.status();
    if status.is_success() {
        return resp.json().await.context("decoding json response");
    }
    let e = extract_error(resp).await?;
    match status {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Err(anyhow!("auth failed: {e}")),
        StatusCode::UNPROCESSABLE_ENTITY | StatusCode::BAD_REQUEST => {
            Err(anyhow!("request rejected: {e}"))
        }
        StatusCode::NOT_FOUND => Err(anyhow!("not found: {e}")),
        _ => Err(anyhow!("server error ({status}): {e}")),
    }
}

async fn extract_error(resp: reqwest::Response) -> Result<String> {
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if let Ok(parsed) = serde_json::from_str::<ErrorResponse>(&text) {
        Ok(parsed.error.message)
    } else if text.is_empty() {
        Ok(format!("http {status}"))
    } else {
        Ok(text)
    }
}
