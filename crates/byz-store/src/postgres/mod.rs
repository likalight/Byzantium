mod agent;
mod api_keys;
mod batch;
mod mandate;
mod receipt;

pub use agent::AgentRepository;
pub use api_keys::{ApiKeyRepository, ApiKeyRow};
pub use batch::BatchRepository;
pub use mandate::MandateRepository;
pub use receipt::{ReceiptRepository, ReceiptRow};
pub use sqlx::PgPool;

pub type Db = std::sync::Arc<PgPool>;
