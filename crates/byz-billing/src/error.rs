use thiserror::Error;

#[derive(Debug, Error)]
pub enum BillingError {
    #[error("stripe API error: {0}")]
    Stripe(String),
    #[error("usage record error: {0}")]
    Usage(String),
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
}
