use axum::{extract::State, Json};
use serde_json::{json, Value};
use crate::state::AppState;

pub async fn get_usage(
    State(state): State<AppState>,
) -> Json<Value> {
    // In a real system you'd get the API key from the auth context.
    // For now return aggregate usage.
    let count = state.usage_meter.current_usage("default").await;
    Json(json!({
        "trust_checks_unbilled": count,
        "billing_period": "current_hour",
        "stripe_configured": std::env::var("STRIPE_SECRET_KEY").is_ok(),
    }))
}
