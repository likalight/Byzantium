use anyhow::Result;
use axum::extract::DefaultBodyLimit;
use axum::http::HeaderValue;
use byz_common::config::Config;
use opentelemetry_otlp::WithExportConfig as _;
use tower_http::{cors::{AllowOrigin, CorsLayer}, timeout::TimeoutLayer, trace::TraceLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use byz_gateway::jobs;
use byz_gateway::routes;
use byz_gateway::state::AppState;
use byz_gateway::tee_client;

/// Initialise the OTLP trace exporter.
///
/// Returns `None` when `OTEL_EXPORTER_OTLP_ENDPOINT` is not set so that
/// callers can skip adding the OTel layer without changing the log-format path.
fn init_telemetry(service_name: &str) -> Option<opentelemetry_sdk::trace::Tracer> {
    let endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok()?;

    let tracer = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(
            opentelemetry_otlp::new_exporter()
                .tonic()
                .with_endpoint(&endpoint),
        )
        .with_trace_config(
            opentelemetry_sdk::trace::Config::default().with_resource(
                opentelemetry_sdk::Resource::new(vec![
                    opentelemetry::KeyValue::new("service.name", service_name.to_string()),
                    opentelemetry::KeyValue::new(
                        "service.version",
                        env!("CARGO_PKG_VERSION").to_string(),
                    ),
                ]),
            ),
        )
        .install_batch(opentelemetry_sdk::runtime::Tokio)
        .ok()?;

    Some(tracer)
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();

    // Build the base subscriber (env-filter + JSON formatting).
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| "byzantium=info".into());

    let fmt_layer = tracing_subscriber::fmt::layer().json();

    // Attempt to wire up OTel; it is purely opt-in via the env var.
    let otel_layer = init_telemetry("byzantium-gateway")
        .map(tracing_opentelemetry::OpenTelemetryLayer::new);

    // `tracing_subscriber` requires both branches to have the same concrete
    // type, which we achieve with `Option`'s `Layer` impl through
    // `tracing_subscriber::layer::OptionLayer`.
    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer)
        .with(otel_layer)
        .init();

    let config = Config::from_env();

    if config.gateway.rate_limit_per_min == 0 {
        panic!("BYZ_RATE_LIMIT_PER_MIN must be > 0 (got 0 — this would allow unlimited requests)");
    }

    let addr = format!("{}:{}", config.gateway.host, config.gateway.port);
    let timeout_ms = config.gateway.trust_check_timeout_ms;

    let mut state = AppState::new(config.clone());

    // Wire TEE client if BYZ_TEE_ENABLED=true
    if let Some(mut tee) = tee_client::TeeClient::from_env() {
        tracing::info!("TEE mode enabled — mandate and reputation calls go to SGX enclaves");
        // Fetch and pin enclave public keys via attestation (MRENCLAVE check if env var set)
        match tee.fetch_and_pin_keys().await {
            Ok(()) => tracing::info!("TEE attestation keys pinned successfully"),
            Err(e) => {
                // Fatal: if MRENCLAVE env var is set, a mismatch means possible MITM
                tracing::error!(error = %e, "TEE attestation failed");
                return Err(anyhow::anyhow!("TEE attestation failed: {e}"));
            }
        }
        state = state.with_tee(tee);
    }

    match byz_store::Store::connect(&config).await {
        Ok(store) => {
            // Ensure Neo4j constraint is idempotent at startup
            if let Err(e) = store.reputation_graph.ensure_schema().await {
                tracing::warn!(error = %e, "neo4j schema init failed — continuing");
            }
            tracing::info!("connected to persistent store (PostgreSQL + Redis + Neo4j)");
            state = state.with_store(store);
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "persistent store unavailable — in-memory fallback active. \
                 Set DATABASE_URL, REDIS_URL, NEO4J_URI to enable persistence."
            );
        }
    }

    // Spawn background jobs
    jobs::proof_refresh::spawn(state.clone());
    jobs::anchor_flush::spawn(state.clone());
    tokio::spawn(jobs::billing_flush::run_billing_flush(state.usage_meter.clone()));

    if config.gateway.api_keys.is_empty() {
        tracing::warn!(
            "BYZ_API_KEYS is not set — all authenticated routes are open. \
             Set BYZ_API_KEYS=key1,key2 before accepting production traffic."
        );
    } else {
        tracing::info!(key_count = config.gateway.api_keys.len(), "API key auth enabled");
    }

    let cors = if state.config.gateway.cors_origins.iter().any(|o| o == "*") {
        CorsLayer::permissive()
    } else {
        let origins: Vec<HeaderValue> = state.config.gateway.cors_origins
            .iter()
            .filter_map(|o| o.parse().ok())
            .collect();
        CorsLayer::new().allow_origin(AllowOrigin::list(origins))
    };

    let shutdown_state = state.clone();
    let app = routes::router(state)
        .layer(TraceLayer::new_for_http())
        .layer(DefaultBodyLimit::max(1 * 1024 * 1024)) // 1MB request body limit
        .layer(cors)
        .layer(TimeoutLayer::new(std::time::Duration::from_millis(timeout_ms + 50)));

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(addr = %addr, "Byzantium gateway started");

    // Graceful shutdown on SIGTERM or SIGINT
    let serve = axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            shutdown_signal().await;
            tracing::info!("shutdown signal received — flushing receipt batches");
            flush_batches_on_shutdown(&shutdown_state).await;
            // Flush the OTel pipeline before process exit so no spans are lost.
            opentelemetry::global::shutdown_tracer_provider();
            tracing::info!("shutdown complete");
        });
    serve.await?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

async fn flush_batches_on_shutdown(state: &AppState) {
    let Some(ref store) = state.store else {
        tracing::debug!("no persistent store — nothing to flush");
        return;
    };

    let batcher = state.batcher.read().await;
    let pending = batcher.pending_sealed_batches();

    if pending.is_empty() {
        tracing::info!("no sealed batches to flush");
        return;
    }

    tracing::info!(count = pending.len(), "flushing sealed batches to PostgreSQL");
    for batch in &pending {
        if let Err(e) = store.batches.insert(batch).await {
            tracing::error!(
                batch_root = %batch.merkle_root,
                error = %e,
                "failed to flush batch on shutdown — batch root logged for manual recovery"
            );
        } else {
            tracing::info!(batch_root = %batch.merkle_root, "batch flushed");
        }
    }
}
