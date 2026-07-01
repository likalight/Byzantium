use thiserror::Error;

#[derive(Debug, Error)]
pub enum ByzantiumError {
    #[error("agent not found: {0}")]
    AgentNotFound(String),

    #[error("mandate not found: {0}")]
    MandateNotFound(String),

    #[error("mandate expired or not yet active")]
    MandateInactive,

    #[error("mandate violation: {0}")]
    MandateViolation(String),

    #[error("counterparty not in whitelist")]
    CounterpartyNotWhitelisted,

    #[error("amount {amount} exceeds per-tx cap {cap}")]
    AmountExceedsCap { amount: u64, cap: u64 },

    #[error("action type not permitted by mandate")]
    ActionTypeNotPermitted,

    #[error("reputation below threshold: score {score} < threshold {threshold}")]
    ReputationBelowThreshold { score: u32, threshold: u32 },

    #[error("invalid ML-DSA signature")]
    InvalidSignature,

    #[error("credential invalid or expired")]
    CredentialInvalid,

    #[error("credential attribute not found: {0}")]
    CredentialAttributeNotFound(String),

    #[error("proof verification failed")]
    ProofVerificationFailed,

    #[error("Merkle proof invalid")]
    MerkleProofInvalid,

    #[error("database error: {0}")]
    Database(String),

    #[error("cache error: {0}")]
    Cache(String),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("anchor error: {0}")]
    Anchor(String),

    #[error("TEE enclave error: {0}")]
    Tee(String),

    #[error("internal error: {0}")]
    Internal(String),

    #[error("not supported: {0}")]
    NotSupported(String),
}

pub type ByzResult<T> = Result<T, ByzantiumError>;
