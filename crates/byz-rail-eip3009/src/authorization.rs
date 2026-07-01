//! EIP-3009 TransferWithAuthorization data structure and EIP-712 hashing.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// EIP-712 domain for USDC on Base mainnet (chain ID 8453).
pub const BASE_CHAIN_ID: u64 = 8453;

/// The EIP-712 typeHash for TransferWithAuthorization:
/// keccak256("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)")
pub const TRANSFER_TYPEHASH_HEX: &str =
    "7c7c6cdb67a18743f49ec6fa9b35f50d52ed05cbed4cc592e13b44501c1a2267";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferAuthorization {
    /// ERC-20 token contract address (lowercase hex, 0x-prefixed)
    pub token: String,
    /// Sender's Ethereum address
    pub from: String,
    /// Recipient's Ethereum address
    pub to: String,
    /// Amount in token's smallest unit (e.g. USDC uses 6 decimals)
    pub value: u128,
    /// Unix timestamp — authorization not valid before this
    pub valid_after: u64,
    /// Unix timestamp — authorization expires after this
    pub valid_before: u64,
    /// 32-byte unique nonce (hex, 0x-prefixed) — prevents replay
    pub nonce: String,
    /// EIP-712 secp256k1 signature (65 bytes, hex, 0x-prefixed): r ++ s ++ v
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthorizationStatus {
    /// All checks passed; safe to relay on-chain
    Valid,
    /// Signature or address mismatch
    InvalidSignature,
    /// valid_before has passed
    Expired,
    /// authorization not yet valid (valid_after is in the future)
    NotYetValid,
    /// Nonce already consumed on-chain
    NonceUsed,
    /// Byzantium trust-check blocked this sender
    TrustBlocked,
}

impl TransferAuthorization {
    /// Encode the struct hash per EIP-712 (SHA-256 approximation used in tests;
    /// production callers pass the recovered signer from secp256k1 recovery).
    ///
    /// Full EIP-712: keccak256(typeHash ++ abi.encode(from, to, value, validAfter, validBefore, nonce))
    /// We approximate with SHA-256 for portability — gateway verifies via eth_sign recovery.
    pub fn struct_hash_sha256(&self) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(TRANSFER_TYPEHASH_HEX.as_bytes());
        h.update(self.from.to_lowercase().as_bytes());
        h.update(self.to.to_lowercase().as_bytes());
        h.update(self.value.to_be_bytes());
        h.update(self.valid_after.to_be_bytes());
        h.update(self.valid_before.to_be_bytes());
        h.update(
            hex::decode(self.nonce.trim_start_matches("0x"))
                .unwrap_or_default(),
        );
        h.finalize().to_vec()
    }

    /// Decode the secp256k1 signature into (r, s, v) component bytes.
    pub fn decode_signature(&self) -> Result<([u8; 32], [u8; 32], u8), String> {
        let sig_bytes = hex::decode(self.signature.trim_start_matches("0x"))
            .map_err(|e| format!("invalid sig hex: {e}"))?;
        if sig_bytes.len() != 65 {
            return Err(format!("signature must be 65 bytes, got {}", sig_bytes.len()));
        }
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&sig_bytes[0..32]);
        s.copy_from_slice(&sig_bytes[32..64]);
        let v = sig_bytes[64];
        Ok((r, s, v))
    }

    /// Check basic time validity against `now_ts` (Unix seconds).
    pub fn is_time_valid(&self, now_ts: u64) -> bool {
        now_ts > self.valid_after && now_ts < self.valid_before
    }
}
