//! Thin HTTP client that talks to the RustClip server.

use anyhow::{Context, Result, anyhow};
use reqwest::{Client, StatusCode};
use rustclip_shared::rest::{
    BlobUploadResponse, EnrollRequest, EnrollResponse, ErrorResponse, LoginRequest, LoginResponse,
    MeResponse, RefreshResponse,
};
use std::time::Duration;
use uuid::Uuid;

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

    /// Rotate the device token and extend its TTL. The new plaintext
    /// token comes back in the response and must replace the stored
    /// one in the keychain.
    pub async fn refresh(&self, token: &str) -> Result<RefreshResponse> {
        let url = format!("{}/api/v1/auth/refresh", self.base_url);
        let resp = self.http.post(&url).bearer_auth(token).send().await?;
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

    /// Upload an already-encrypted blob under a client-chosen id. Binding
    /// the id client-side lets the outgoing clip_event AEAD include it
    /// as AAD, so the server cannot swap `blob_id` in-flight to point
    /// at a different blob owned by the same user.
    pub async fn upload_blob(
        &self,
        token: &str,
        blob_id: Uuid,
        ciphertext: Vec<u8>,
    ) -> Result<BlobUploadResponse> {
        let url = format!("{}/api/v1/blobs", self.base_url);
        let resp = self
            .http
            .post(&url)
            .bearer_auth(token)
            .header("content-type", "application/octet-stream")
            .header("x-rustclip-blob-id", blob_id.to_string())
            .body(ciphertext)
            .send()
            .await?;
        parse_json(resp).await
    }

    pub async fn download_blob(&self, token: &str, blob_id: Uuid) -> Result<Vec<u8>> {
        let url = format!("{}/api/v1/blobs/{}", self.base_url, blob_id);
        let resp = self.http.get(&url).bearer_auth(token).send().await?;
        if !resp.status().is_success() {
            let e = extract_error(resp).await?;
            return Err(anyhow!(e));
        }
        let bytes = resp.bytes().await.context("reading blob body")?;
        Ok(bytes.to_vec())
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
