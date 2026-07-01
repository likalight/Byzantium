//! End-to-end integration tests for byz-gateway.
//!
//! These tests start a real in-memory gateway bound to a random port (port 0)
//! and hit real HTTP routes with reqwest. No external database is needed — the
//! gateway runs in full in-memory mode when no store is wired up.

use byz_common::config::{
    Config, DatabaseConfig, GatewayConfig, ImmudbConfig, Neo4jConfig, RedisConfig,
    ReputationConfig, ZkMeConfig,
};
use byz_gateway::routes;
use byz_gateway::state::AppState;
use reqwest::Client;
use serde_json::{json, Value};
use uuid::Uuid;

/// Build a minimal in-memory `Config` with the given API key.
///
/// Constructing `Config` directly avoids all env-var races between parallel
/// tests — each test server gets its own isolated config.
fn test_config(api_key: &str) -> Config {
    Config {
        gateway: GatewayConfig {
            host: "127.0.0.1".to_string(),
            port: 0,
            trust_check_timeout_ms: 500,
            api_keys: vec![api_key.to_string()],
            rate_limit_per_min: 1000,
            proof_refresh_secs: 60,
            cors_origins: vec!["http://localhost:3000".to_string()],
            metrics_token: None,
        },
        database: DatabaseConfig {
            url: "postgres://unused:unused@localhost/unused".to_string(),
            max_connections: 1,
        },
        redis: RedisConfig {
            url: "redis://localhost/0".to_string(),
            proof_cache_ttl_secs: 300,
        },
        neo4j: Neo4jConfig {
            uri: "bolt://localhost:7687".to_string(),
            username: "neo4j".to_string(),
            password: "unused".to_string(),
        },
        immudb: ImmudbConfig {
            host: "localhost".to_string(),
            port: 3322,
            username: "immudb".to_string(),
            password: "immudb".to_string(),
            database: "unused".to_string(),
        },
        reputation: ReputationConfig {
            default_threshold: 600,
            score_refresh_interval_secs: 3600,
        },
        zkme: ZkMeConfig {
            api_url: "https://api.zkme.io".to_string(),
            api_key: String::new(),
        },
    }
}

/// Spin up a gateway on a random port and return (base_url, api_key).
///
/// Each test gets an isolated in-memory server — no shared state, no env vars.
async fn start_test_server() -> (String, String) {
    let api_key = format!("test-key-{}", Uuid::new_v4());
    let config = test_config(&api_key);
    let state = AppState::new(config);
    let router = routes::router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind to random port");
    let addr = listener.local_addr().expect("local_addr");
    let base_url = format!("http://{}", addr);

    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("server error");
    });

    (base_url, api_key)
}

fn client() -> Client {
    Client::new()
}

// ── tests ─────────────────────────────────────────────────────────────────────

/// GET /health — no auth required, must return {"status":"ok"}.
#[tokio::test]
async fn health_returns_ok() {
    let (base_url, _) = start_test_server().await;

    let res = client()
        .get(format!("{}/health", base_url))
        .send()
        .await
        .expect("request");

    assert_eq!(res.status(), 200);

    let body: Value = res.json().await.expect("json body");
    assert_eq!(body["status"], "ok");
    assert_eq!(body["service"], "byzantium-gateway");
}

/// GET /health must respond with an X-Request-Id header added by the middleware.
#[tokio::test]
async fn health_has_request_id_header() {
    let (base_url, _) = start_test_server().await;

    let res = client()
        .get(format!("{}/health", base_url))
        .send()
        .await
        .expect("request");

    assert_eq!(res.status(), 200);
    assert!(
        res.headers().contains_key("x-request-id"),
        "X-Request-Id header must be present on all responses"
    );
}

/// POST /v1/trust-check without a Bearer token must return 401.
#[tokio::test]
async fn trust_check_requires_auth() {
    let (base_url, _) = start_test_server().await;

    let res = client()
        .post(format!("{}/v1/trust-check", base_url))
        .json(&json!({
            "agent_did": "did:key:z6Mktest",
            "action_type": "payment",
            "rail_id": "test-rail"
        }))
        .send()
        .await
        .expect("request");

    assert_eq!(res.status(), 401, "unauthenticated request must be rejected");
}

/// POST /v1/trust-check with a valid key but no mandate returns BLOCK verdict.
/// The engine returns BLOCK when no mandate is found for the agent.
#[tokio::test]
async fn trust_check_block_when_no_mandate() {
    let (base_url, api_key) = start_test_server().await;

    let res = client()
        .post(format!("{}/v1/trust-check", base_url))
        .bearer_auth(&api_key)
        .json(&json!({
            "agent_did": "did:key:z6MkNoMandate",
            "action_type": "payment",
            "rail_id": "test-rail"
        }))
        .send()
        .await
        .expect("request");

    assert_eq!(res.status(), 200);

    let body: Value = res.json().await.expect("json body");
    // No mandate registered → engine returns BLOCK
    assert_eq!(
        body["verdict"]["verdict"], "BLOCK",
        "agent without mandate should receive BLOCK verdict; got: {body}"
    );
}

/// POST /v1/trust-check for a new agent WITH a mandate: mandate passes but
/// reputation score (500, neutral default) is below threshold (600) → FLAG.
#[tokio::test]
async fn trust_check_flag_when_reputation_below_threshold() {
    let (base_url, api_key) = start_test_server().await;

    let agent_did = format!("did:key:z6MkRepAgent-{}", Uuid::new_v4());

    // Create a mandate for this agent first.
    let mandate_res = client()
        .post(format!("{}/v1/mandates", base_url))
        .bearer_auth(&api_key)
        .json(&json!({
            "agent_did": agent_did,
            "operator_id": "operator-test",
            "counterparty_whitelist": [],
            "allowed_action_types": ["payment"],
            "per_tx_cap_cents": 10000,
            "daily_cap_cents": 100000,
            "valid_days": 30
        }))
        .send()
        .await
        .expect("mandate request");

    assert_eq!(mandate_res.status(), 200, "mandate creation must succeed");

    // Trust check — new agent starts at score 500, threshold is 600 → FLAG.
    let res = client()
        .post(format!("{}/v1/trust-check", base_url))
        .bearer_auth(&api_key)
        .json(&json!({
            "agent_did": agent_did,
            "action_type": "payment",
            "rail_id": "test-rail"
        }))
        .send()
        .await
        .expect("trust-check request");

    assert_eq!(res.status(), 200);

    let body: Value = res.json().await.expect("json body");
    assert_eq!(
        body["verdict"]["verdict"], "FLAG",
        "new agent with default reputation should be flagged; got: {body}"
    );
}

/// POST /v1/mandates, then GET /v1/mandates/:id — full round-trip.
#[tokio::test]
async fn create_mandate_and_retrieve() {
    let (base_url, api_key) = start_test_server().await;

    let agent_did = format!("did:key:z6MkMandate-{}", Uuid::new_v4());

    // Create
    let create_res = client()
        .post(format!("{}/v1/mandates", base_url))
        .bearer_auth(&api_key)
        .json(&json!({
            "agent_did": agent_did,
            "operator_id": "test-operator",
            "counterparty_whitelist": ["acme-corp"],
            "allowed_action_types": ["payment", "api_call"],
            "per_tx_cap_cents": 5000,
            "daily_cap_cents": 50000,
            "valid_days": 7
        }))
        .send()
        .await
        .expect("create request");

    assert_eq!(create_res.status(), 200, "mandate creation must return 200");

    let create_body: Value = create_res.json().await.expect("create json");
    let mandate_id = create_body["mandate_id"]
        .as_str()
        .expect("mandate_id field must be a string UUID");

    assert!(
        Uuid::parse_str(mandate_id).is_ok(),
        "mandate_id must be a valid UUID"
    );
    assert_eq!(create_body["agent_did"], agent_did);

    // Retrieve
    let get_res = client()
        .get(format!("{}/v1/mandates/{}", base_url, mandate_id))
        .bearer_auth(&api_key)
        .send()
        .await
        .expect("get request");

    assert_eq!(get_res.status(), 200, "mandate GET must return 200");

    let get_body: Value = get_res.json().await.expect("get json");

    // SpendMandate.agent_did serialises as a newtype struct → {"0": "did:..."}
    // Accept either shape to be robust against potential serde changes.
    let serialised_did = get_body["agent_did"].clone();
    let did_matches = serialised_did == agent_did
        || serialised_did.get("0").map(|v| v == &json!(agent_did)).unwrap_or(false);
    assert!(
        did_matches,
        "retrieved mandate agent_did must match {agent_did}; got: {get_body}"
    );

    assert_eq!(get_body["per_tx_cap_cents"], 5000);
    assert_eq!(get_body["daily_cap_cents"], 50000);
}

/// GET /v1/mandates/:id for an unknown UUID must return 404.
#[tokio::test]
async fn get_missing_mandate_returns_404() {
    let (base_url, api_key) = start_test_server().await;

    let unknown_id = Uuid::new_v4();

    let res = client()
        .get(format!("{}/v1/mandates/{}", base_url, unknown_id))
        .bearer_auth(&api_key)
        .send()
        .await
        .expect("request");

    assert_eq!(res.status(), 404);
}

/// POST /v1/receipts creates and returns a signed LiabilityReceipt.
#[tokio::test]
async fn receipt_create_returns_signed_receipt() {
    let (base_url, api_key) = start_test_server().await;

    let mandate_id = Uuid::new_v4(); // in-memory: no FK validation

    let res = client()
        .post(format!("{}/v1/receipts", base_url))
        .bearer_auth(&api_key)
        .json(&json!({
            "agent_did": "did:key:z6MkReceiptAgent",
            "action_type": "payment",
            "counterparty": null,
            "amount_cents": 1000,
            "outcome": "success",
            "mandate_id": mandate_id,
            "rail_id": "test-rail"
        }))
        .send()
        .await
        .expect("request");

    assert_eq!(res.status(), 200, "receipt creation must succeed");

    let body: Value = res.json().await.expect("json body");
    assert!(
        body["id"].as_str().and_then(|s| Uuid::parse_str(s).ok()).is_some(),
        "receipt id must be a UUID; got: {body}"
    );
    assert_eq!(body["action_type"], "payment");
    assert_eq!(body["amount_cents"], 1000);
}

/// GET /v1/receipts/:id/proof for an unbatched receipt returns 404 in in-memory mode.
/// The proof endpoint requires a persistent store to look up the batch.
#[tokio::test]
async fn inclusion_proof_for_unbatched_receipt_returns_404() {
    let (base_url, api_key) = start_test_server().await;

    // Create a receipt so we have a real receipt_id to query.
    let mandate_id = Uuid::new_v4();
    let create_res = client()
        .post(format!("{}/v1/receipts", base_url))
        .bearer_auth(&api_key)
        .json(&json!({
            "agent_did": "did:key:z6MkProofAgent",
            "action_type": "api_call",
            "counterparty": null,
            "amount_cents": null,
            "outcome": "success",
            "mandate_id": mandate_id,
            "rail_id": "test-rail"
        }))
        .send()
        .await
        .expect("create receipt");

    assert_eq!(create_res.status(), 200);
    let receipt: Value = create_res.json().await.expect("receipt json");
    let receipt_id = receipt["id"].as_str().expect("receipt id");

    // Proof endpoint requires store — in-memory mode returns 404.
    let proof_res = client()
        .get(format!("{}/v1/receipts/{}/proof", base_url, receipt_id))
        .bearer_auth(&api_key)
        .send()
        .await
        .expect("proof request");

    assert_eq!(
        proof_res.status(),
        404,
        "unbatched receipt proof must return 404 in in-memory mode"
    );
}

// ── DB-backed test helper (only compiled with `--features integration-db`) ────

/// Spin up a gateway on a random port wired to a real PostgreSQL + Redis store.
///
/// Reads `DATABASE_URL` and `REDIS_URL` from the environment (set by the
/// `integration-db` CI job).  Panics if either env var is missing or if the
/// store fails to connect — both are hard failures in the CI environment.
#[cfg(feature = "integration-db")]
async fn start_test_server_with_db() -> (String, String) {
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set for integration-db tests");
    let redis_url = std::env::var("REDIS_URL")
        .expect("REDIS_URL must be set for integration-db tests");

    let api_key = format!("ci-db-key-{}", Uuid::new_v4());

    // Build a Config that points at the real services.
    let mut config = test_config(&api_key);
    config.database.url = database_url;
    config.redis.url = redis_url;

    let store = byz_store::Store::connect(&config)
        .await
        .expect("byz_store::Store::connect failed — check DATABASE_URL / REDIS_URL");

    let state = AppState::new(config).with_store(store);
    let router = routes::router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind to random port");
    let addr = listener.local_addr().expect("local_addr");
    let base_url = format!("http://{}", addr);

    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("server error");
    });

    (base_url, api_key)
}

// ── DB-backed integration tests ───────────────────────────────────────────────

/// GET /health with a live DB returns {"status":"ok"} with postgres + redis checks.
#[cfg(feature = "integration-db")]
#[tokio::test]
async fn db_health_returns_ok() {
    let (base_url, _) = start_test_server_with_db().await;

    let res = client()
        .get(format!("{}/health", base_url))
        .send()
        .await
        .expect("request");

    assert_eq!(res.status(), 200);

    let body: Value = res.json().await.expect("json body");
    assert_eq!(body["status"], "ok", "DB-backed health check must be ok; got: {body}");
    assert_eq!(body["checks"]["postgres"], "ok");
    assert_eq!(body["checks"]["redis"], "ok");
}

/// POST /v1/trust-check with a real DB store returns a structured verdict.
#[cfg(feature = "integration-db")]
#[tokio::test]
async fn db_trust_check_returns_verdict() {
    let (base_url, api_key) = start_test_server_with_db().await;
    let agent_did = format!("did:key:z6MkDb-{}", Uuid::new_v4());

    let res = client()
        .post(format!("{}/v1/trust-check", base_url))
        .bearer_auth(&api_key)
        .json(&json!({
            "agent_did": agent_did,
            "action_type": "payment",
            "rail_id": "db-test-rail"
        }))
        .send()
        .await
        .expect("request");

    assert_eq!(res.status(), 200);

    let body: Value = res.json().await.expect("json body");
    let verdict = body["verdict"]["verdict"].as_str().expect("verdict field");
    assert!(
        matches!(verdict, "PASS" | "FLAG" | "BLOCK"),
        "verdict must be PASS, FLAG, or BLOCK; got: {verdict}"
    );
}

/// POST /v1/batches/:id/seal force-seals the current batch and returns the Merkle root.
#[tokio::test]
async fn seal_batch_returns_merkle_root() {
    let (base_url, api_key) = start_test_server().await;

    // Add a receipt so the batch has content.
    let mandate_id = Uuid::new_v4();
    let receipt_res = client()
        .post(format!("{}/v1/receipts", base_url))
        .bearer_auth(&api_key)
        .json(&json!({
            "agent_did": "did:key:z6MkSealAgent",
            "action_type": "payment",
            "counterparty": null,
            "amount_cents": 500,
            "outcome": "success",
            "mandate_id": mandate_id,
            "rail_id": "test-rail"
        }))
        .send()
        .await
        .expect("receipt");
    assert_eq!(receipt_res.status(), 200);

    let seal_id = Uuid::new_v4(); // path param is present but unused by handler
    let res = client()
        .post(format!("{}/v1/batches/{}/seal", base_url, seal_id))
        .bearer_auth(&api_key)
        .send()
        .await
        .expect("seal request");

    assert_eq!(res.status(), 200, "seal must succeed");

    let body: Value = res.json().await.expect("seal json");
    assert!(
        body["batch_id"].as_str().and_then(|s| Uuid::parse_str(s).ok()).is_some(),
        "batch_id must be a UUID; got: {body}"
    );
    assert!(
        body["merkle_root"].as_str().map(|s| !s.is_empty()).unwrap_or(false),
        "merkle_root must be non-empty; got: {body}"
    );
    assert_eq!(body["receipt_count"], 1);
}
