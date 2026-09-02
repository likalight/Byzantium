pub mod a2a;
pub mod audit;
pub mod identity;
pub mod keys;
pub mod limits;
pub mod mandate;
pub mod payments;
pub mod provenance;
pub mod receipt;
pub mod trust;
pub mod usage;
pub mod x402;

use axum::{
    middleware,
    routing::{delete, get, post},
    Router,
};

use crate::{
    middleware::{
        auth::require_api_key, rate_limit::per_key_rate_limit, request_id::propagate_request_id,
    },
    state::AppState,
};

pub fn router(state: AppState) -> Router {
    // Protected routes — require Bearer API key + per-key rate limiting
    let protected = Router::new()
        .route("/v1/trust-check", post(trust::trust_check))
        .route("/v1/mandates", post(mandate::create_mandate))
        .route("/v1/mandates/:id", get(mandate::get_mandate))
        .route("/v1/mandates/:id/revoke", post(mandate::revoke_mandate))
        .route("/v1/receipts", post(receipt::create_receipt))
        .route("/v1/receipts/:id/proof", get(receipt::inclusion_proof))
        .route("/v1/batches/:id/seal", post(receipt::seal_batch))
        .route("/v1/agents", post(identity::register_agent))
        .route("/v1/agents/:did", get(identity::get_agent))
        .route(
            "/v1/agents/:did/deactivate",
            post(identity::deactivate_agent),
        )
        .route("/v1/audit/receipts", get(audit::list_receipts))
        .route("/v1/audit/batches/:id", get(audit::get_batch_proof))
        .route(
            "/v1/payments/eip3009/verify",
            post(payments::verify_eip3009),
        )
        .route("/v1/payments/solana/verify", post(payments::verify_solana))
        .route("/v1/payments/x402/verify", post(x402::verify_x402))
        .route("/v1/a2a/check", post(a2a::check_a2a))
        .route("/v1/keys", post(keys::create_key).get(keys::list_keys))
        .route("/v1/keys/:id", delete(keys::revoke_key))
        .route("/v1/usage", get(usage::get_usage))
        // ── Underwriting: issue a portable limit, and honor one on presentation ──
        .route("/v1/principals", post(limits::register_principal))
        .route("/v1/limits/issue", post(limits::issue_limit))
        .route("/v1/limits/verify", post(limits::verify_limit))
        .route("/v1/limits/settle", post(limits::settle_draw))
        .route("/v1/limits/revoke", post(limits::revoke_limits))
        // ── Provenance: runtime-signed execution evidence ────────────────────────
        .route("/v1/runtimes", post(provenance::register_runtime))
        .route("/v1/runtimes/revoke", post(provenance::revoke_runtime))
        .route("/v1/provenance", post(provenance::submit_provenance))
        .route("/v1/provenance/:did", get(provenance::get_provenance))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            per_key_rate_limit,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_api_key,
        ));

    // Public routes — no auth, no rate limit
    let public = Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        // Relying parties need the issuer's public keys to verify an
        // attestation, and needing a prior key exchange to do so would defeat
        // the point of a portable credential.
        .route("/v1/issuer-keys", get(issuer_keys));

    // The walkthrough is served from the gateway so it is same-origin — a page
    // opened from the filesystem could not reach these endpoints without
    // relaxing CORS. It is unauthenticated by nature, so it stays off unless
    // asked for.
    let public = if state.config.gateway.demo_enabled {
        public.route("/demo", get(demo_page))
    } else {
        public
    };

    Router::new()
        .merge(protected)
        .merge(public)
        .layer(middleware::from_fn(propagate_request_id))
        .with_state(state)
}

/// The public keys this issuer signs with, plus recently retired ones.
///
/// Retired keys stay listed until everything they signed has expired, because
/// dropping one while credentials are still in flight invalidates them.
async fn issuer_keys(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> axum::Json<serde_json::Value> {
    let ks = state.keystore.read().await;
    axum::Json(serde_json::json!({
        "issuer": "did:web:byzantium",
        "keys": ks.published(),
    }))
}

/// A watchable walkthrough of the whole system, for showing someone.
///
/// It drives the same endpoints an integrator would, from the browser, so what is
/// on screen is the real gateway answering rather than a recording.
async fn demo_page() -> axum::response::Response {
    use axum::response::IntoResponse;
    (
        axum::http::StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
        include_str!("../demo.html"),
    )
        .into_response()
}

async fn health(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    let mut checks = serde_json::Map::new();
    let mut all_ok = true;

    if let Some(ref store) = state.store {
        // Check PostgreSQL
        match sqlx::query("SELECT 1").execute(store.pool.as_ref()).await {
            Ok(_) => {
                checks.insert("postgres".into(), serde_json::json!("ok"));
            }
            Err(e) => {
                checks.insert(
                    "postgres".into(),
                    serde_json::json!({"status": "error", "detail": e.to_string()}),
                );
                all_ok = false;
            }
        }
        // Check Redis
        match store.proof_cache.ping().await {
            Ok(_) => {
                checks.insert("redis".into(), serde_json::json!("ok"));
            }
            Err(e) => {
                checks.insert(
                    "redis".into(),
                    serde_json::json!({"status": "error", "detail": e.to_string()}),
                );
                all_ok = false;
            }
        }
    } else {
        checks.insert("postgres".into(), serde_json::json!("not_configured"));
        checks.insert("redis".into(), serde_json::json!("not_configured"));
    }

    let status_code = if all_ok {
        axum::http::StatusCode::OK
    } else {
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    };

    (
        status_code,
        axum::Json(serde_json::json!({
            "status": if all_ok { "ok" } else { "degraded" },
            "service": "byzantium-gateway",
            "version": env!("CARGO_PKG_VERSION"),
            "checks": checks,
        })),
    )
}

async fn metrics(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    if let Some(ref required_token) = state.config.gateway.metrics_token {
        let provided = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        if provided != Some(required_token.as_str()) {
            return (
                axum::http::StatusCode::UNAUTHORIZED,
                [(axum::http::header::CONTENT_TYPE, "text/plain")],
                "Unauthorized",
            )
                .into_response();
        }
    }
    (
        axum::http::StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        state.metrics.render(),
    )
        .into_response()
}
