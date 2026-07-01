use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use chrono::Utc;
use tracing::{info, warn};
use crate::{StripeClient, error::BillingError};

#[derive(Debug, Clone)]
pub struct KeyUsage {
    pub trust_checks: u64,
    pub stripe_subscription_item_id: Option<String>,
}

pub struct UsageMeter {
    stripe: Option<Arc<StripeClient>>,
    counters: Arc<Mutex<HashMap<String, KeyUsage>>>,
}

impl UsageMeter {
    pub fn new(stripe: Option<StripeClient>) -> Self {
        Self {
            stripe: stripe.map(Arc::new),
            counters: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Called on every trust check — increments counter for this API key.
    pub async fn record(&self, api_key: &str) {
        let mut map = self.counters.lock().await;
        map.entry(api_key.to_string())
            .or_insert(KeyUsage { trust_checks: 0, stripe_subscription_item_id: None })
            .trust_checks += 1;
    }

    /// Register the Stripe subscription item id for an API key.
    pub async fn register_key(&self, api_key: &str, stripe_sub_item_id: &str) {
        let mut map = self.counters.lock().await;
        let entry = map.entry(api_key.to_string())
            .or_insert(KeyUsage { trust_checks: 0, stripe_subscription_item_id: None });
        entry.stripe_subscription_item_id = Some(stripe_sub_item_id.to_string());
    }

    /// Flush all counters to Stripe and reset. Call this from a background job every hour.
    pub async fn flush(&self) -> Vec<BillingError> {
        let mut map = self.counters.lock().await;
        let now = Utc::now().timestamp();
        let mut errors = vec![];

        for (key, usage) in map.iter_mut() {
            if usage.trust_checks == 0 { continue; }
            let qty = usage.trust_checks;

            if let (Some(stripe), Some(ref sub_item)) = (&self.stripe, &usage.stripe_subscription_item_id) {
                match stripe.report_usage(sub_item, qty, now).await {
                    Ok(_) => {
                        info!(api_key = %key, quantity = qty, "usage flushed to Stripe");
                        usage.trust_checks = 0;
                    }
                    Err(e) => {
                        warn!(api_key = %key, error = %e, "failed to flush usage to Stripe");
                        errors.push(e);
                    }
                }
            } else {
                // No Stripe configured — just log
                info!(api_key = %key, quantity = qty, "usage (no Stripe configured)");
                usage.trust_checks = 0;
            }
        }
        errors
    }

    /// Get current unbilled count for an API key.
    pub async fn current_usage(&self, api_key: &str) -> u64 {
        self.counters.lock().await
            .get(api_key)
            .map(|u| u.trust_checks)
            .unwrap_or(0)
    }
}
