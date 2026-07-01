use thiserror::Error;

#[derive(Debug, Error)]
pub enum A2AError {
    #[error("missing agent DID in message: {0}")]
    MissingDid(String),
    #[error("trust-check failed for sender {did}: {reason}")]
    SenderBlocked { did: String, reason: String },
    #[error("trust-check failed for recipient {did}: {reason}")]
    RecipientBlocked { did: String, reason: String },
    #[error("cross-agent trust score too low: {score:.2} < {threshold:.2}")]
    CrossTrustTooLow { score: f64, threshold: f64 },
    #[error("Byzantium gateway error: {0}")]
    Gateway(String),
    #[error("A2A message parse error: {0}")]
    Parse(String),
    #[error("network error: {0}")]
    Network(String),
}
