use byz_billing::UsageMeter;
use std::sync::Arc;

pub async fn run_billing_flush(meter: Arc<UsageMeter>) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
    loop {
        interval.tick().await;
        let errors = meter.flush().await;
        if !errors.is_empty() {
            tracing::warn!(error_count = errors.len(), "billing flush had errors");
        }
    }
}
