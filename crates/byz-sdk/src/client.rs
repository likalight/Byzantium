use byz_common::{
    LiabilityReceipt, PassToken, SpendMandate, TrustCheckRequest, TrustCheckResponse,
    TrustVerdict,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::SdkError;

pub type ByzResult<T> = Result<T, SdkError>;

/// Request to create a spend mandate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateMandateRequest {
    pub mandate: SpendMandate,
}

/// Request to create a liability receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateReceiptRequest {
    pub receipt: LiabilityReceipt,
}

/// Byzantium SDK client.
///
/// Authenticates with a Bearer API key obtained from `POST /v1/keys`.
/// All methods return `ByzResult<T>`.
///
/// # Example
/// ```no_run
/// # use byz_sdk::client::ByzantiumClient;
/// # tokio_test::block_on(async {
/// let client = ByzantiumClient::new("https://api.byzantium.io", "byz_key_abc123");
/// let ok = client.health().await.unwrap();
/// assert!(ok);
/// # });
/// ```
#[derive(Clone)]
pub struct ByzantiumClient {
    base_url: String,
    api_key: String,
    http: reqwest::Client,
}

impl ByzantiumClient {
    /// Create a new client pointing at `base_url`, authenticating with `api_key`.
    pub fn new(base_url: &str, api_key: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key: api_key.to_string(),
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("reqwest client"),
        }
    }

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.api_key)
    }

    /// POST /v1/trust-check — evaluate whether an agent action is compliant.
    pub async fn trust_check(&self, req: &TrustCheckRequest) -> ByzResult<TrustCheckResponse> {
        let resp = self
            .http
            .post(format!("{}/v1/trust-check", self.base_url))
            .header("authorization", self.auth_header())
            .json(req)
            .send()
            .await?;

        self.handle_response::<TrustCheckResponse>(resp).await
    }

    /// Trust-check shortcut: returns the PassToken on PASS, or `SdkError::TrustBlocked` on BLOCK/FLAG.
    pub async fn require_pass(&self, req: &TrustCheckRequest) -> ByzResult<PassToken> {
        let resp = self.trust_check(req).await?;
        match resp.verdict {
            TrustVerdict::Pass => resp
                .token
                .ok_or_else(|| SdkError::ApiError {
                    status: 200,
                    message: "gateway returned PASS but no token".to_string(),
                }),
            other => Err(SdkError::TrustBlocked {
                verdict: other,
                request_id: resp.request_id,
            }),
        }
    }

    /// POST /v1/mandates — register a spend mandate with the gateway.
    pub async fn create_mandate(&self, req: &CreateMandateRequest) -> ByzResult<SpendMandate> {
        let resp = self
            .http
            .post(format!("{}/v1/mandates", self.base_url))
            .header("authorization", self.auth_header())
            .json(req)
            .send()
            .await?;

        self.handle_response::<SpendMandate>(resp).await
    }

    /// POST /v1/receipts — submit a liability receipt.
    pub async fn create_receipt(&self, req: &CreateReceiptRequest) -> ByzResult<LiabilityReceipt> {
        let resp = self
            .http
            .post(format!("{}/v1/receipts", self.base_url))
            .header("authorization", self.auth_header())
            .json(req)
            .send()
            .await?;

        self.handle_response::<LiabilityReceipt>(resp).await
    }

    /// GET /health — liveness check. Returns true if the gateway is up.
    pub async fn health(&self) -> ByzResult<bool> {
        let resp = self
            .http
            .get(format!("{}/health", self.base_url))
            .send()
            .await?;

        Ok(resp.status().is_success())
    }

    /// Shared response handler: extracts body or converts API/rate-limit errors.
    async fn handle_response<T: serde::de::DeserializeOwned>(
        &self,
        resp: reqwest::Response,
    ) -> ByzResult<T> {
        let status = resp.status();

        if status.as_u16() == 429 {
            // Parse Retry-After header if present (in milliseconds or seconds)
            let retry_after_ms = resp
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .map(|secs| secs * 1000)
                .unwrap_or(1000);
            return Err(SdkError::RateLimited { retry_after_ms });
        }

        if !status.is_success() {
            // Try to extract error message from JSON body
            let body_bytes = resp.bytes().await.unwrap_or_default();
            let message = serde_json::from_slice::<serde_json::Value>(&body_bytes)
                .ok()
                .and_then(|v| v["error"].as_str().map(|s| s.to_string()))
                .unwrap_or_else(|| format!("HTTP {}", status.as_u16()));

            return Err(SdkError::ApiError {
                status: status.as_u16(),
                message,
            });
        }

        resp.json::<T>().await.map_err(|e| SdkError::NetworkError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use byz_common::{AgentDid, ActionType, TrustVerdict};

    fn client() -> ByzantiumClient {
        ByzantiumClient::new("http://localhost:8080", "byz_key_test")
    }

    #[test]
    fn trust_blocked_error_display() {
        let err = SdkError::TrustBlocked {
            verdict: TrustVerdict::Block { reason: "daily cap exceeded".to_string() },
            request_id: Uuid::nil(),
        };
        let s = err.to_string();
        assert!(s.contains("blocked"));
    }

    #[test]
    fn api_error_display() {
        let err = SdkError::ApiError {
            status: 401,
            message: "invalid or missing API key".to_string(),
        };
        assert!(err.to_string().contains("401"));
        assert!(err.to_string().contains("invalid or missing API key"));
    }

    #[test]
    fn rate_limited_display() {
        let err = SdkError::RateLimited { retry_after_ms: 5000 };
        assert!(err.to_string().contains("5000ms"));
    }

    #[test]
    fn network_error_display() {
        let err = SdkError::NetworkError("connection refused".to_string());
        assert!(err.to_string().contains("connection refused"));
    }

    #[test]
    fn client_base_url_strips_trailing_slash() {
        let c = ByzantiumClient::new("https://api.example.com/", "key");
        assert_eq!(c.base_url, "https://api.example.com");
    }

    #[test]
    fn auth_header_format() {
        let c = client();
        assert_eq!(c.auth_header(), "Bearer byz_key_test");
    }
}
