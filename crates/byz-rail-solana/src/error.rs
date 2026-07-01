use thiserror::Error;

#[derive(Debug, Error)]
pub enum SolanaRailError {
    #[error("transaction not found or not finalized: {0}")]
    TransactionNotFound(String),

    #[error("transaction failed on-chain")]
    TransactionFailed,

    #[error("not an SPL token transfer")]
    NotSplTransfer,

    #[error("mint mismatch: expected {expected}, got {actual}")]
    MintMismatch { expected: String, actual: String },

    #[error("amount mismatch: expected {expected}, got {actual}")]
    AmountMismatch { expected: u64, actual: u64 },

    #[error("sender mismatch: expected {expected}, got {actual}")]
    SenderMismatch { expected: String, actual: String },

    #[error("recipient mismatch: expected {expected}, got {actual}")]
    RecipientMismatch { expected: String, actual: String },

    #[error("Solana RPC error: {0}")]
    RpcError(String),

    #[error("Byzantium trust-check blocked sender: {0}")]
    TrustCheckFailed(String),
}
