use byz_common::{
    ActionType, AgentDid, AssetClass, Currency, KycTier, LiabilityReceipt, LimitAttestation,
    PassToken, SpendMandate, TrustCheckRequest, TrustCheckResponse, TrustVerdict,
};
use serde::{Deserialize, Serialize};

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
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let client = ByzantiumClient::new("https://api.byzantium.io", "byz_key_abc123");
/// let ok = client.health().await?;
/// assert!(ok);
/// # Ok(())
/// # }
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
            TrustVerdict::Pass => resp.token.ok_or_else(|| SdkError::ApiError {
                status: 200,
                message: "gateway returned PASS but no token".to_string(),
            }),
            other => Err(SdkError::TrustBlocked {
                verdict: other,
                request_id: resp.request_id,
            }),
        }
    }

    // -- Underwriting ---------------------------------------------------------

    /// POST /v1/principals - bind an agent to a KYC'd principal.
    ///
    /// Nothing can be underwritten before this. Standing is the gate, and the
    /// principal is where limits consolidate, so registering more agents divides
    /// a ceiling rather than multiplying it.
    pub async fn register_principal(
        &self,
        req: &RegisterPrincipalRequest,
    ) -> ByzResult<serde_json::Value> {
        let resp = self
            .http
            .post(format!("{}/v1/principals", self.base_url))
            .header("authorization", self.auth_header())
            .json(req)
            .send()
            .await?;
        self.handle_response::<serde_json::Value>(resp).await
    }

    /// POST /v1/limits/issue - underwrite the agent and return a portable limit.
    ///
    /// The response carries the reason trail behind every control that shaped
    /// the number, including on a refusal.
    pub async fn issue_limit(&self, req: &IssueLimitRequest) -> ByzResult<IssueLimitResponse> {
        let resp = self
            .http
            .post(format!("{}/v1/limits/issue", self.base_url))
            .header("authorization", self.auth_header())
            .json(req)
            .send()
            .await?;
        self.handle_response::<IssueLimitResponse>(resp).await
    }

    /// Issue a limit and return the attestation, or fail if it was refused.
    pub async fn require_limit(&self, req: &IssueLimitRequest) -> ByzResult<LimitAttestation> {
        let resp = self.issue_limit(req).await?;
        resp.attestation.ok_or_else(|| SdkError::ApiError {
            status: 200,
            message: resp
                .refusal
                .unwrap_or_else(|| "no limit was issued".to_string()),
        })
    }

    /// POST /v1/limits/verify - present an attestation for one draw.
    ///
    /// The chain it is presented on need never have seen this agent: the gateway
    /// checks a signature, converts into the unit of account, applies the
    /// asset-class haircut, and nets against recorded exposure.
    pub async fn verify_limit(&self, req: &VerifyLimitRequest) -> ByzResult<VerifyLimitResponse> {
        let resp = self
            .http
            .post(format!("{}/v1/limits/verify", self.base_url))
            .header("authorization", self.auth_header())
            .json(req)
            .send()
            .await?;
        self.handle_response::<VerifyLimitResponse>(resp).await
    }

    /// POST /v1/limits/settle - resolve a committed draw.
    ///
    /// Settling consumes window capacity; failing releases the exposure. Either
    /// way the outcome reaches the scorer, which closes the feedback loop.
    pub async fn settle_draw(&self, req: &SettleDrawRequest) -> ByzResult<serde_json::Value> {
        let resp = self
            .http
            .post(format!("{}/v1/limits/settle", self.base_url))
            .header("authorization", self.auth_header())
            .json(req)
            .send()
            .await?;
        self.handle_response::<serde_json::Value>(resp).await
    }

    /// POST /v1/limits/revoke - kill outstanding attestations early.
    pub async fn revoke_limits(&self, body: &serde_json::Value) -> ByzResult<serde_json::Value> {
        let resp = self
            .http
            .post(format!("{}/v1/limits/revoke", self.base_url))
            .header("authorization", self.auth_header())
            .json(body)
            .send()
            .await?;
        self.handle_response::<serde_json::Value>(resp).await
    }

    /// POST /v1/provenance - submit runtime-signed execution traces.
    ///
    /// The runtime signs, not the agent. Events that fail verification are
    /// reported rather than silently dropped, because a low acceptance rate is
    /// usually a misconfigured runtime rather than a misbehaving agent.
    pub async fn submit_provenance(
        &self,
        body: &serde_json::Value,
    ) -> ByzResult<serde_json::Value> {
        let resp = self
            .http
            .post(format!("{}/v1/provenance", self.base_url))
            .header("authorization", self.auth_header())
            .json(body)
            .send()
            .await?;
        self.handle_response::<serde_json::Value>(resp).await
    }

    /// POST /v1/runtimes - register a trusted runtime signing key.
    pub async fn register_runtime(
        &self,
        runtime_id: &str,
        public_key_hex: &str,
    ) -> ByzResult<serde_json::Value> {
        let body = serde_json::json!({
            "runtime_id": runtime_id,
            "public_key_hex": public_key_hex,
        });
        let resp = self
            .http
            .post(format!("{}/v1/runtimes", self.base_url))
            .header("authorization", self.auth_header())
            .json(&body)
            .send()
            .await?;
        self.handle_response::<serde_json::Value>(resp).await
    }

    /// POST /v1/mandates - register a spend mandate with the gateway.
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

        resp.json::<T>()
            .await
            .map_err(|e| SdkError::NetworkError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use byz_common::TrustVerdict;
    use uuid::Uuid;

    fn client() -> ByzantiumClient {
        ByzantiumClient::new("http://localhost:8080", "byz_key_test")
    }

    #[test]
    fn trust_blocked_error_display() {
        let err = SdkError::TrustBlocked {
            verdict: TrustVerdict::Block {
                reason: "daily cap exceeded".to_string(),
            },
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
        let err = SdkError::RateLimited {
            retry_after_ms: 5000,
        };
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

// ------------------------- Underwriting request types ------------------------

/// Bind an agent to a KYC'd principal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterPrincipalRequest {
    pub agent_did: AgentDid,
    pub principal_ref: String,
    pub kyc_tier: KycTier,
    pub sanctions_clear: bool,
    #[serde(default)]
    pub jurisdiction: String,
    #[serde(default)]
    pub entity_age_days: u32,
}

/// Ask for a limit, scoped to where it may be presented.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueLimitRequest {
    pub agent_did: AgentDid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ccy: Option<Currency>,
    #[serde(default)]
    pub chains: Vec<String>,
    #[serde(default)]
    pub asset_classes: Vec<AssetClass>,
    #[serde(default)]
    pub counterparty_classes: Vec<String>,
    #[serde(default)]
    pub action_types: Vec<ActionType>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueLimitResponse {
    pub issued: bool,
    pub attestation: Option<LimitAttestation>,
    pub tier: String,
    pub score: u32,
    /// Every control that shaped the limit, in order.
    pub reasons: Vec<String>,
    #[serde(default)]
    pub refusal: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrawInput {
    pub amount_minor: u64,
    pub currency: Currency,
    pub asset_class: AssetClass,
    pub chain: String,
    pub action_type: ActionType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counterparty_class: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyLimitRequest {
    pub attestation: LimitAttestation,
    pub draw: DrawInput,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyLimitResponse {
    pub permitted: bool,
    /// The draw in the attestation's unit of account, after the haircut.
    pub effective_minor: u64,
    pub effective_ccy: String,
    pub window_used_minor: u64,
    pub fee_minor: u64,
    #[serde(default)]
    pub refusal: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettleDrawRequest {
    pub agent_did: AgentDid,
    pub amount_minor: u64,
    pub currency: Currency,
    /// False releases the exposure instead of consuming window capacity.
    pub settled: bool,
}
