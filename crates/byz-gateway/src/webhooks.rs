//! Webhook dispatch for trust verdict events.
//!
//! Operators configure BYZ_WEBHOOK_URL + BYZ_WEBHOOK_SECRET to receive
//! real-time notifications whenever a trust-check completes.
//! Each POST is signed with HMAC-SHA256 so the receiver can verify origin.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
pub struct WebhookConfig {
    pub url: String,
    pub secret: String,
}

impl WebhookConfig {
    pub fn from_env() -> Option<Self> {
        let url = std::env::var("BYZ_WEBHOOK_URL").ok()?;
        let secret = std::env::var("BYZ_WEBHOOK_SECRET").ok()?;
        Some(Self { url, secret })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEvent {
    pub event_type: String,
    pub agent_did: String,
    pub verdict: String,
    pub request_id: String,
    pub timestamp: String,
    pub payload: Value,
}

#[derive(Clone)]
pub struct WebhookDispatcher {
    pub config: Option<WebhookConfig>,
    pub http: reqwest::Client,
}

impl WebhookDispatcher {
    pub fn from_env() -> Self {
        Self {
            config: WebhookConfig::from_env(),
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .expect("webhook http client"),
        }
    }

    /// Fire-and-forget dispatch — signs and POSTs the event asynchronously.
    /// Retries up to 3 attempts (delays: 1s, 5s) before logging a dead-letter error.
    pub async fn dispatch(&self, event: WebhookEvent) {
        let cfg = match &self.config {
            Some(c) => c.clone(),
            None => return, // no webhook configured
        };

        let body = match serde_json::to_string(&event) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, "webhook serialization failed");
                return;
            }
        };

        // HMAC-SHA256 signature over the raw JSON body
        let signature = {
            let mut mac = HmacSha256::new_from_slice(cfg.secret.as_bytes())
                .expect("HMAC key init");
            mac.update(body.as_bytes());
            let result = mac.finalize();
            format!("sha256={}", hex::encode(result.into_bytes()))
        };

        let url = cfg.url.clone();
        let event_type = event.event_type.clone();
        let http = self.http.clone();

        tokio::spawn(async move {
            let result = dispatch_with_retry(&http, &url, &body, &signature, &event_type).await;
            if let Err(last_err) = result {
                tracing::error!(
                    webhook_url = %url,
                    event_type = %event_type,
                    payload = %body,
                    attempts = 3,
                    error = %last_err,
                    "webhook delivery failed after all retries — dead-letter logged above"
                );
            }
        });
    }
}

/// Attempt to POST the webhook payload, retrying up to 3 times (delays: 1s, 5s between attempts).
/// Each attempt has a 5-second timeout enforced by the reqwest client.
async fn dispatch_with_retry(
    http: &reqwest::Client,
    url: &str,
    payload: &str,
    sig: &str,
    event_type: &str,
) -> Result<(), String> {
    let delays_ms = [0u64, 1_000, 5_000];
    let mut last_err = String::new();

    for (attempt, delay_ms) in delays_ms.iter().enumerate() {
        if *delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(*delay_ms)).await;
        }

        let send_result = http
            .post(url)
            .header("Content-Type", "application/json")
            .header("X-Byzantium-Signature", sig)
            .body(payload.to_owned())
            .send()
            .await;

        match send_result {
            Ok(resp) if resp.status().is_success() => {
                tracing::info!(
                    status = resp.status().as_u16(),
                    url = %url,
                    attempt = attempt + 1,
                    event_type = %event_type,
                    "webhook dispatched"
                );
                return Ok(());
            }
            Ok(resp) => {
                last_err = format!("HTTP {}", resp.status());
                tracing::warn!(
                    attempt = attempt + 1,
                    status = resp.status().as_u16(),
                    url = %url,
                    "webhook attempt failed"
                );
            }
            Err(e) => {
                last_err = e.to_string();
                tracing::warn!(
                    attempt = attempt + 1,
                    error = %e,
                    url = %url,
                    "webhook attempt failed"
                );
            }
        }
    }

    Err(last_err)
}
