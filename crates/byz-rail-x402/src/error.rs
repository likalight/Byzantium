use thiserror::Error;

#[derive(Debug, Error)]
pub enum X402Error {
    #[error("payment proof missing or malformed: {0}")]
    MissingProof(String),
    #[error("payment expired")]
    Expired,
    #[error("payment nonce mismatch — possible replay attack")]
    NonceMismatch,
    #[error("payment amount too low: expected {expected}, got {got}")]
    InsufficientAmount { expected: u64, got: u64 },
    #[error("signature verification failed: {0}")]
    BadSignature(String),
    #[error("trust-check failed: {0}")]
    TrustCheckFailed(String),
    #[error("Byzantium gateway error: {0}")]
    Gateway(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("network error: {0}")]
    Network(String),
}
