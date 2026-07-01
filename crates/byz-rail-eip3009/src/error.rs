use thiserror::Error;

#[derive(Debug, Error)]
pub enum Eip3009Error {
    #[error("invalid authorization signature: {0}")]
    InvalidSignature(String),

    #[error("authorization expired (valid_before = {0})")]
    Expired(u64),

    #[error("authorization not yet valid (valid_after = {0})")]
    NotYetValid(u64),

    #[error("nonce already used: {0}")]
    NonceUsed(String),

    #[error("from address mismatch: recovered {recovered}, expected {expected}")]
    FromMismatch { recovered: String, expected: String },

    #[error("invalid hex encoding: {0}")]
    InvalidHex(String),

    #[error("Base RPC error: {0}")]
    RpcError(String),

    #[error("Byzantium trust-check rejected: {0}")]
    TrustCheckFailed(String),
}
