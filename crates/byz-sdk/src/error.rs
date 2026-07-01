use byz_common::TrustVerdict;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum SdkError {
    #[error("trust check blocked: {verdict:?} (request_id={request_id})")]
    TrustBlocked {
        verdict: TrustVerdict,
        request_id: Uuid,
    },

    #[error("api error {status}: {message}")]
    ApiError { status: u16, message: String },

    #[error("network error: {0}")]
    NetworkError(String),

    #[error("rate limited — retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },
}

impl From<reqwest::Error> for SdkError {
    fn from(e: reqwest::Error) -> Self {
        SdkError::NetworkError(e.to_string())
    }
}
