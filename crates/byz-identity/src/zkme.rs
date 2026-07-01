//! zkMe integration — KYC/KYB attestation verification.
//!
//! Byzantium delegates human identity verification to zkMe.
//! This module verifies that an operator or agent holds a valid zkMe attestation
//! before issuing a Byzantium credential.
//!
//! API: https://docs.zk.me/zkme-dex-api/api-reference

use byz_common::{ByzResult, ByzantiumError};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkMeAttestation {
    pub operator_id: String,
    pub kyb_verified: bool,
    pub jurisdiction: Option<String>,
    pub verified_at: chrono::DateTime<chrono::Utc>,
    /// zkMe-issued proof (opaque to Byzantium; verified by calling zkMe API)
    pub proof: String,
}

#[derive(Debug, Deserialize)]
struct ZkMeVerifyResponse {
    success: bool,
    #[serde(rename = "isVerified")]
    is_verified: Option<bool>,
    jurisdiction: Option<String>,
    message: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ZkMeClient {
    api_url: String,
    api_key: String,
    http: reqwest::Client,
}

impl ZkMeClient {
    pub fn new(api_url: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self {
            api_url: api_url.into(),
            api_key: api_key.into(),
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("zkme http client"),
        }
    }

    pub fn from_env() -> Option<Self> {
        let key = std::env::var("ZKME_API_KEY").ok()?;
        let url = std::env::var("ZKME_API_URL")
            .unwrap_or_else(|_| "https://nest-api.zk.me".to_string());
        Some(Self::new(url, key))
    }

    /// Verify an operator's KYB attestation with zkMe.
    /// The `proof` is the zkMe-issued attestation token (from their SDK).
    pub async fn verify_operator_kyb(
        &self,
        operator_id: &str,
        proof: &str,
    ) -> ByzResult<ZkMeAttestation> {
        let body = serde_json::json!({
            "appId": operator_id,
            "accessToken": proof,
        });

        let resp = self
            .http
            .post(format!("{}/api/v1/access/token/userinfo", self.api_url))
            .header("apikey", &self.api_key)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| ByzantiumError::Internal(format!("zkMe network error: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(ByzantiumError::Internal(format!(
                "zkMe API returned {status}: {body}"
            )));
        }

        let zkme_resp: ZkMeVerifyResponse = resp
            .json()
            .await
            .map_err(|e| ByzantiumError::Internal(format!("zkMe parse error: {e}")))?;

        if !zkme_resp.success || !zkme_resp.is_verified.unwrap_or(false) {
            return Err(ByzantiumError::CredentialInvalid);
        }

        Ok(ZkMeAttestation {
            operator_id: operator_id.to_string(),
            kyb_verified: true,
            jurisdiction: zkme_resp.jurisdiction,
            verified_at: chrono::Utc::now(),
            proof: proof.to_string(),
        })
    }

    /// Verify a user's KYC attestation (individual, not business).
    pub async fn verify_user_kyc(
        &self,
        user_address: &str,
        access_token: &str,
    ) -> ByzResult<ZkMeAttestation> {
        let body = serde_json::json!({
            "userAddress": user_address,
            "accessToken": access_token,
        });

        let resp = self
            .http
            .post(format!("{}/api/v1/access/token/verify", self.api_url))
            .header("apikey", &self.api_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| ByzantiumError::Internal(format!("zkMe KYC network error: {e}")))?;

        if !resp.status().is_success() {
            return Err(ByzantiumError::CredentialInvalid);
        }

        let zkme_resp: ZkMeVerifyResponse = resp
            .json()
            .await
            .map_err(|e| ByzantiumError::Internal(format!("zkMe KYC parse: {e}")))?;

        if !zkme_resp.success || !zkme_resp.is_verified.unwrap_or(false) {
            return Err(ByzantiumError::CredentialInvalid);
        }

        Ok(ZkMeAttestation {
            operator_id: user_address.to_string(),
            kyb_verified: false, // KYC, not KYB
            jurisdiction: zkme_resp.jurisdiction,
            verified_at: chrono::Utc::now(),
            proof: access_token.to_string(),
        })
    }
}
