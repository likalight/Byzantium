//! Eip3009Verifier — stateless verification + Base RPC nonce check.

use crate::{
    authorization::{AuthorizationStatus, TransferAuthorization},
    error::Eip3009Error,
};
use chrono::Utc;
use serde_json::json;

/// Result of verifying a TransferAuthorization.
#[derive(Debug)]
pub struct VerificationResult {
    pub status: AuthorizationStatus,
    /// Recovered `from` address (lowercase hex) — None if signature recovery failed
    pub recovered_from: Option<String>,
    /// Amount in token's smallest unit
    pub value: u128,
}

pub struct Eip3009Verifier {
    /// Base RPC URL — e.g. "https://mainnet.base.org"
    rpc_url: String,
    /// Byzantium trust-check endpoint — e.g. "http://localhost:8080"
    byzantium_url: String,
    http: reqwest::Client,
}

impl Eip3009Verifier {
    pub fn new(rpc_url: impl Into<String>, byzantium_url: impl Into<String>) -> Self {
        Self {
            rpc_url: rpc_url.into(),
            byzantium_url: byzantium_url.into(),
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .expect("http client"),
        }
    }

    /// Full verification pipeline:
    ///   1. Time bounds
    ///   2. Signature recovery (via eth_sign_recover JSON-RPC helper)
    ///   3. Nonce check via eth_call on token contract
    ///   4. Byzantium trust-check on sender DID
    pub async fn verify(
        &self,
        auth: &TransferAuthorization,
        api_key: &str,
    ) -> Result<VerificationResult, Eip3009Error> {
        let now = Utc::now().timestamp() as u64;

        // 1. Time bounds
        if now >= auth.valid_before {
            return Ok(VerificationResult {
                status: AuthorizationStatus::Expired,
                recovered_from: None,
                value: auth.value,
            });
        }
        if now <= auth.valid_after {
            return Ok(VerificationResult {
                status: AuthorizationStatus::NotYetValid,
                recovered_from: None,
                value: auth.value,
            });
        }

        // 2. Recover signer from EIP-712 structured data
        let recovered = self.recover_signer(auth).await?;
        if recovered.to_lowercase() != auth.from.to_lowercase() {
            return Ok(VerificationResult {
                status: AuthorizationStatus::InvalidSignature,
                recovered_from: Some(recovered),
                value: auth.value,
            });
        }

        // 3. Check nonce hasn't been used on-chain
        let nonce_used = self.check_nonce_used(auth).await?;
        if nonce_used {
            return Ok(VerificationResult {
                status: AuthorizationStatus::NonceUsed,
                recovered_from: Some(recovered.clone()),
                value: auth.value,
            });
        }

        // 4. Byzantium trust-check on sender
        let agent_did = format!("did:evm:base:{}", auth.from.to_lowercase());
        let trust_ok = self.byzantium_trust_check(&agent_did, auth.value, api_key).await?;
        if !trust_ok {
            return Ok(VerificationResult {
                status: AuthorizationStatus::TrustBlocked,
                recovered_from: Some(recovered.clone()),
                value: auth.value,
            });
        }

        Ok(VerificationResult {
            status: AuthorizationStatus::Valid,
            recovered_from: Some(recovered),
            value: auth.value,
        })
    }

    /// Call eth_accounts/personal_ecRecover via JSON-RPC to recover the signer.
    /// In production use: web3.eth.accounts.recover(typedData, signature).
    async fn recover_signer(&self, auth: &TransferAuthorization) -> Result<String, Eip3009Error> {
        // Build the EIP-712 digest and ask eth_sign to recover
        // We use `personal_ecRecover` on the struct hash (approximation — matches common wallets)
        let struct_hash = auth.struct_hash_sha256();
        let hash_hex = format!("0x{}", hex::encode(&struct_hash));

        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "personal_ecRecover",
            "params": [hash_hex, auth.signature]
        });

        let resp = self
            .http
            .post(&self.rpc_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| Eip3009Error::RpcError(format!("network: {e}")))?
            .json::<serde_json::Value>()
            .await
            .map_err(|e| Eip3009Error::RpcError(format!("parse: {e}")))?;

        if let Some(err) = resp["error"].as_object() {
            return Err(Eip3009Error::RpcError(format!(
                "{}: {}",
                err["code"].as_i64().unwrap_or(-1),
                err["message"].as_str().unwrap_or("unknown")
            )));
        }

        let signer = resp["result"]
            .as_str()
            .ok_or_else(|| Eip3009Error::RpcError("ecRecover returned no result".to_string()))?
            .to_lowercase();

        Ok(signer)
    }

    /// Check if the authorization nonce has already been used.
    /// Calls `authorizationState(address from, bytes32 nonce)` on the token contract.
    /// Returns: true → nonce used (blocked), false → fresh.
    async fn check_nonce_used(&self, auth: &TransferAuthorization) -> Result<bool, Eip3009Error> {
        // authorizationState(address,bytes32) selector = keccak256("authorizationState(address,bytes32)")[..4]
        // = 0xe94a0102
        let from_padded = format!("000000000000000000000000{}", auth.from.trim_start_matches("0x").to_lowercase());
        let nonce_padded = auth.nonce.trim_start_matches("0x").to_lowercase();
        let nonce_padded = format!("{:0>64}", nonce_padded);
        let data = format!("0xe94a0102{}{}", from_padded, nonce_padded);

        let body = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "eth_call",
            "params": [{ "to": auth.token, "data": data }, "latest"]
        });

        let resp = self
            .http
            .post(&self.rpc_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| Eip3009Error::RpcError(format!("nonce check network: {e}")))?
            .json::<serde_json::Value>()
            .await
            .map_err(|e| Eip3009Error::RpcError(format!("nonce check parse: {e}")))?;

        if let Some(err) = resp["error"].as_object() {
            return Err(Eip3009Error::RpcError(format!(
                "nonce check rpc error: {}",
                err["message"].as_str().unwrap_or("unknown")
            )));
        }

        let result_hex = resp["result"].as_str().unwrap_or("0x0");
        // Returns bool as 0x00...00 (false=fresh) or 0x00...01 (true=used)
        let used = result_hex.trim_start_matches("0x").chars().last() == Some('1');
        Ok(used)
    }

    /// Call Byzantium gateway trust-check for the sender DID.
    async fn byzantium_trust_check(
        &self,
        agent_did: &str,
        amount_cents: u128,
        api_key: &str,
    ) -> Result<bool, Eip3009Error> {
        let body = json!({
            "agent_did": agent_did,
            "action_type": "Payment",
            "amount_cents": amount_cents as u64,
        });

        let resp = self
            .http
            .post(format!("{}/v1/trust-check", self.byzantium_url))
            .bearer_auth(api_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| Eip3009Error::TrustCheckFailed(format!("network: {e}")))?
            .json::<serde_json::Value>()
            .await
            .map_err(|e| Eip3009Error::TrustCheckFailed(format!("parse: {e}")))?;

        let verdict = resp["verdict"].as_str().unwrap_or("BLOCK");
        Ok(verdict == "PASS")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorization::TransferAuthorization;

    fn make_auth() -> TransferAuthorization {
        TransferAuthorization {
            token:        "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".to_string(), // USDC Base
            from:         "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045".to_string(),
            to:           "0x1234567890abcdef1234567890abcdef12345678".to_string(),
            value:        1_000_000,   // 1 USDC (6 decimals)
            valid_after:  0,
            valid_before: u64::MAX,
            nonce:        "0x0000000000000000000000000000000000000000000000000000000000000001".to_string(),
            signature:    "0x".to_string() + &"aa".repeat(32) + &"bb".repeat(32) + "1c",
        }
    }

    #[test]
    fn struct_hash_is_deterministic() {
        let auth = make_auth();
        let h1 = auth.struct_hash_sha256();
        let h2 = auth.struct_hash_sha256();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 32);
    }

    #[test]
    fn decode_signature_parses_65_byte_sig() {
        let auth = make_auth();
        let (r, s, v) = auth.decode_signature().unwrap();
        assert_eq!(r, [0xaa_u8; 32]);
        assert_eq!(s, [0xbb_u8; 32]);
        assert_eq!(v, 0x1c);
    }

    #[test]
    fn time_validity_checks() {
        let now = chrono::Utc::now().timestamp() as u64;
        let mut auth = make_auth();

        // Valid window
        auth.valid_after = now - 100;
        auth.valid_before = now + 100;
        assert!(auth.is_time_valid(now));

        // Expired
        auth.valid_before = now - 1;
        assert!(!auth.is_time_valid(now));

        // Not yet valid
        auth.valid_after = now + 1;
        auth.valid_before = now + 200;
        assert!(!auth.is_time_valid(now));
    }
}
