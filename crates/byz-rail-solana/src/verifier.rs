//! SolanaVerifier — fetches and verifies SPL token transfers via Solana JSON-RPC.

use crate::{
    error::SolanaRailError,
    transfer::{SolanaTransferProof, TransferStatus},
};
use serde_json::json;

/// Parsed post-balance entry from getTransaction
#[derive(Debug)]
struct TokenBalance {
    account_index: usize,
    mint: String,
    amount: u64,
}

pub struct VerificationResult {
    pub status: TransferStatus,
    pub fee_lamports: Option<u64>,
    pub slot: Option<u64>,
}

pub struct SolanaVerifier {
    rpc_url: String,
    byzantium_url: String,
    http: reqwest::Client,
}

impl SolanaVerifier {
    pub fn new(rpc_url: impl Into<String>, byzantium_url: impl Into<String>) -> Self {
        let rpc_url = rpc_url.into();
        Self {
            rpc_url,
            byzantium_url: byzantium_url.into(),
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("http client"),
        }
    }

    pub fn for_cluster(cluster: &str, byzantium_url: impl Into<String>) -> Self {
        let rpc_url = match cluster {
            "mainnet-beta" => "https://api.mainnet-beta.solana.com",
            "devnet"       => "https://api.devnet.solana.com",
            "testnet"      => "https://api.testnet.solana.com",
            other          => other, // custom RPC URL passthrough
        };
        Self::new(rpc_url, byzantium_url)
    }

    /// Full verification pipeline for an SPL transfer.
    pub async fn verify(
        &self,
        proof: &SolanaTransferProof,
        api_key: &str,
    ) -> Result<VerificationResult, SolanaRailError> {
        // 1. Fetch the transaction
        let tx = self.get_transaction(&proof.signature).await?;

        // 2. Check finalization and success
        let meta = tx["result"]["meta"].as_object()
            .ok_or(SolanaRailError::TransactionNotFound(proof.signature.clone()))?;

        if meta.get("err").and_then(|e| e.as_null()).is_none()
            && meta["err"] != serde_json::Value::Null
        {
            return Ok(VerificationResult {
                status: TransferStatus::TransactionFailed,
                fee_lamports: None,
                slot: None,
            });
        }

        let slot = tx["result"]["slot"].as_u64();
        let fee = meta["fee"].as_u64();

        // 3. Extract post-token-balances and verify SPL transfer
        let post_balances = meta
            .get("postTokenBalances")
            .and_then(|b| b.as_array())
            .ok_or(SolanaRailError::NotSplTransfer)?;

        // Find the recipient's token account balance change
        let account_keys = tx["result"]["transaction"]["message"]["accountKeys"]
            .as_array()
            .ok_or(SolanaRailError::NotSplTransfer)?;

        let recipient_index = account_keys
            .iter()
            .position(|k| k.as_str() == Some(&proof.to_wallet));

        let recipient_balance = post_balances.iter().find(|b| {
            b["accountIndex"].as_u64().map(|i| i as usize) == recipient_index
                && b["mint"].as_str() == Some(&proof.mint)
        });

        let actual_amount = recipient_balance
            .and_then(|b| b["uiTokenAmount"]["amount"].as_str())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);

        // Verify mint
        let actual_mint = recipient_balance
            .and_then(|b| b["mint"].as_str())
            .unwrap_or("");

        if actual_mint != proof.mint {
            return Ok(VerificationResult {
                status: TransferStatus::MintMismatch,
                fee_lamports: fee,
                slot,
            });
        }

        // Verify sender appears in signers (index 0 = fee payer / signer)
        let actual_sender = account_keys
            .first()
            .and_then(|k| k.as_str())
            .unwrap_or("");

        if actual_sender != proof.from_wallet {
            return Ok(VerificationResult {
                status: TransferStatus::SenderMismatch,
                fee_lamports: fee,
                slot,
            });
        }

        // Amount check — post-balance may be cumulative; use the pre/post diff
        let pre_balances = meta
            .get("preTokenBalances")
            .and_then(|b| b.as_array());

        let pre_amount: u64 = pre_balances
            .and_then(|pbs| {
                pbs.iter().find(|b| {
                    b["accountIndex"].as_u64().map(|i| i as usize) == recipient_index
                })
            })
            .and_then(|b| b["uiTokenAmount"]["amount"].as_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let received = actual_amount.saturating_sub(pre_amount);
        if received != proof.amount {
            return Ok(VerificationResult {
                status: TransferStatus::AmountMismatch,
                fee_lamports: fee,
                slot,
            });
        }

        // 4. Byzantium trust-check on sender DID
        let sender_did = format!("did:sol:{}", proof.from_wallet);
        let trust_ok = self.byzantium_trust_check(&sender_did, proof.amount, api_key).await?;
        if !trust_ok {
            return Ok(VerificationResult {
                status: TransferStatus::TrustBlocked,
                fee_lamports: fee,
                slot,
            });
        }

        tracing::info!(
            sig = %proof.signature,
            from = %proof.from_wallet,
            amount = proof.amount,
            mint = %proof.mint,
            "Solana SPL transfer verified"
        );

        Ok(VerificationResult {
            status: TransferStatus::Verified,
            fee_lamports: fee,
            slot,
        })
    }

    async fn get_transaction(&self, signature: &str) -> Result<serde_json::Value, SolanaRailError> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getTransaction",
            "params": [
                signature,
                { "encoding": "json", "maxSupportedTransactionVersion": 0 }
            ]
        });

        let resp = self
            .http
            .post(&self.rpc_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| SolanaRailError::RpcError(format!("network: {e}")))?
            .json::<serde_json::Value>()
            .await
            .map_err(|e| SolanaRailError::RpcError(format!("parse: {e}")))?;

        if resp["result"].is_null() {
            return Err(SolanaRailError::TransactionNotFound(signature.to_string()));
        }

        if let Some(err) = resp["error"].as_object() {
            return Err(SolanaRailError::RpcError(format!(
                "{}: {}",
                err["code"].as_i64().unwrap_or(-1),
                err["message"].as_str().unwrap_or("unknown")
            )));
        }

        Ok(resp)
    }

    async fn byzantium_trust_check(
        &self,
        agent_did: &str,
        amount: u64,
        api_key: &str,
    ) -> Result<bool, SolanaRailError> {
        let body = json!({
            "agent_did": agent_did,
            "action_type": "Payment",
            "amount_cents": amount,
        });

        let resp = self
            .http
            .post(format!("{}/v1/trust-check", self.byzantium_url))
            .bearer_auth(api_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| SolanaRailError::TrustCheckFailed(format!("network: {e}")))?
            .json::<serde_json::Value>()
            .await
            .map_err(|e| SolanaRailError::TrustCheckFailed(format!("parse: {e}")))?;

        let verdict = resp["verdict"].as_str().unwrap_or("BLOCK");
        Ok(verdict == "PASS")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transfer::{SolanaTransferProof, USDC_MINT_MAINNET};

    #[test]
    fn cluster_rpc_url_mapping() {
        let v = SolanaVerifier::for_cluster("mainnet-beta", "http://localhost:8080");
        assert!(v.rpc_url.contains("mainnet-beta"));

        let v = SolanaVerifier::for_cluster("devnet", "http://localhost:8080");
        assert!(v.rpc_url.contains("devnet"));

        let custom = "https://my-rpc.example.com";
        let v = SolanaVerifier::for_cluster(custom, "http://localhost:8080");
        assert_eq!(v.rpc_url, custom);
    }

    fn make_proof() -> SolanaTransferProof {
        SolanaTransferProof {
            signature: "5hG3j9kX2mNv8pQr4tUw6yZa1bCd3eF7gHiJkLmNoPqRsTuVwXyZ2aBcDeF4gH".to_string(),
            from_wallet: "HN7cABqLq46Es1jh92dQQisAq662SmxELLLsHHe4YWrH".to_string(),
            to_wallet:   "7xKXtg2CW87d9T1mq9hPn5eqFQFXKJJVGGBJqKdXrGx".to_string(),
            mint: USDC_MINT_MAINNET.to_string(),
            amount: 1_000_000,
            cluster: "mainnet-beta".to_string(),
        }
    }

    #[test]
    fn proof_fields_accessible() {
        let proof = make_proof();
        assert_eq!(proof.mint, USDC_MINT_MAINNET);
        assert_eq!(proof.amount, 1_000_000);
    }
}
