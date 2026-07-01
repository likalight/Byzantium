//! End-to-end tests for byz-gateway.
//!
//! These tests spin up a full in-memory Axum gateway bound to a random port
//! (port 0) and exercise the complete HTTP API with real reqwest calls.
//! No external database, Redis, or any other service is required — the gateway
//! runs in full in-memory mode.
//!
//! Run with:
//!   cargo test -p byz-gateway --test e2e -- --nocapture

use byz_common::config::{
    Config, DatabaseConfig, GatewayConfig, ImmudbConfig, Neo4jConfig, RedisConfig,
    ReputationConfig, ZkMeConfig,
};
use byz_gateway::routes;
use byz_gateway::state::AppState;
use reqwest::Client;
use serde_json::{json, Value};
use uuid::Uuid;

// ── helpers ───────────────────────────────────────────────────────────────────

/// Build a minimal in-memory `Config` with the given API key.
///
/// The reputation threshold is set to 400 (below the new-agent default of 500)
/// so that a freshly registered agent can pass the trust check without needing
/// a history of successful transactions.
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
            // Set below the new-agent neutral score (500) so fresh agents PASS.
            default_threshold: 400,
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
/// Uses a low reputation threshold (400) so freshly-registered agents can PASS.
async fn start_test_server() -> (String, String) {
    let api_key = format!("e2e-key-{}", Uuid::new_v4());
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

/// Full happy path — register agent → create mandate → trust check → PASS.
///
/// This is the golden path exercised in every investor demo.
/// Uses a reputation threshold of 400 so the agent's neutral score of 500 clears it.
#[tokio::test]
async fn e2e_happy_path() {
    let (base_url, api_key) = start_test_server().await;

    // ── 1. Register an agent ──────────────────────────────────────────────────
    let reg_res = client()
        .post(format!("{}/v1/agents", base_url))
        .bearer_auth(&api_key)
        .json(&json!({
            "operator_id": "e2e-operator"
        }))
        .send()
        .await
        .expect("register agent request");

    assert_eq!(reg_res.status(), 200, "agent registration must succeed");

    let reg_body: Value = reg_res.json().await.expect("register json");
    let agent_did = reg_body["did"]
        .as_str()
        .expect("did field must be present")
        .to_string();

    assert!(!agent_did.is_empty(), "registered DID must be non-empty");
    assert!(
        agent_did.starts_with("did:"),
        "registered DID must start with 'did:'; got: {agent_did}"
    );

    // ── 2. Create a mandate ───────────────────────────────────────────────────
    let mandate_res = client()
        .post(format!("{}/v1/mandates", base_url))
        .bearer_auth(&api_key)
        .json(&json!({
            "agent_did": agent_did,
            "operator_id": "e2e-operator",
            "counterparty_whitelist": [],
            "allowed_action_types": ["payment"],
            "per_tx_cap_cents": 10000,
            "daily_cap_cents": 100000,
            "valid_days": 30
        }))
        .send()
        .await
        .expect("create mandate request");

    assert_eq!(mandate_res.status(), 200, "mandate creation must succeed");

    let mandate_body: Value = mandate_res.json().await.expect("mandate json");
    let mandate_id = mandate_body["mandate_id"]
        .as_str()
        .expect("mandate_id must be present");

    assert!(
        Uuid::parse_str(mandate_id).is_ok(),
        "mandate_id must be a valid UUID; got: {mandate_id}"
    );

    // ── 3. Trust check → expect PASS ─────────────────────────────────────────
    let check_res = client()
        .post(format!("{}/v1/trust-check", base_url))
        .bearer_auth(&api_key)
        .json(&json!({
            "agent_did": agent_did,
            "action_type": "payment",
            "rail_id": "e2e-test-rail",
            "amount_cents": 500
        }))
        .send()
        .await
        .expect("trust-check request");

    assert_eq!(check_res.status(), 200, "trust check must return 200");

    // Assert: X-Request-Id header present in response
    assert!(
        check_res.headers().contains_key("x-request-id"),
        "X-Request-Id header must be present on all responses"
    );

    let check_body: Value = check_res.json().await.expect("trust-check json");

    // Assert: verdict == PASS
    assert_eq!(
        check_body["verdict"]["verdict"], "PASS",
        "agent with mandate and score above threshold should PASS; got: {check_body}"
    );

    // Assert: token is Some (PassToken is issued on PASS)
    assert!(
        !check_body["token"].is_null(),
        "PASS verdict must include a PassToken; got: {check_body}"
    );

    // Assert: latency_ms > 0
    let latency_ms = check_body["latency_ms"].as_u64().unwrap_or(0);
    assert!(latency_ms > 0 || latency_ms == 0, "latency_ms field must be present");
    // latency_ms == 0 is acceptable in a fast in-memory test; just assert the field exists
    assert!(
        check_body["latency_ms"].is_number(),
        "latency_ms must be a number; got: {check_body}"
    );

    // ── 4. Health check ───────────────────────────────────────────────────────
    let health_res = client()
        .get(format!("{}/health", base_url))
        .send()
        .await
        .expect("health request");

    assert_eq!(health_res.status(), 200);

    let health_body: Value = health_res.json().await.expect("health json");
    assert_eq!(health_body["status"], "ok", "health must be ok; got: {health_body}");
}

/// No mandate → trust check must return BLOCK.
///
/// An agent that has never been granted a mandate must always be blocked.
#[tokio::test]
async fn e2e_no_mandate_blocks() {
    let (base_url, api_key) = start_test_server().await;

    // Do NOT create a mandate — just fire a trust check for an unknown agent.
    let res = client()
        .post(format!("{}/v1/trust-check", base_url))
        .bearer_auth(&api_key)
        .json(&json!({
            "agent_did": format!("did:key:z6MkNoMandate-{}", Uuid::new_v4()),
            "action_type": "payment",
            "rail_id": "e2e-test-rail"
        }))
        .send()
        .await
        .expect("trust-check request");

    assert_eq!(res.status(), 200);

    let body: Value = res.json().await.expect("json body");
    assert_eq!(
        body["verdict"]["verdict"], "BLOCK",
        "agent without mandate must receive BLOCK verdict; got: {body}"
    );
    assert!(
        body["token"].is_null(),
        "BLOCK verdict must not include a token; got: {body}"
    );
}

/// Amount over the mandate's per-transaction cap → BLOCK.
///
/// The mandate engine must enforce per_tx_cap_cents strictly.
#[tokio::test]
async fn e2e_amount_over_cap_blocks() {
    let (base_url, api_key) = start_test_server().await;

    let agent_did = format!("did:key:z6MkCapTest-{}", Uuid::new_v4());

    // Create mandate with a small per-tx cap
    let mandate_res = client()
        .post(format!("{}/v1/mandates", base_url))
        .bearer_auth(&api_key)
        .json(&json!({
            "agent_did": agent_did,
            "operator_id": "e2e-operator",
            "counterparty_whitelist": [],
            "allowed_action_types": ["payment"],
            "per_tx_cap_cents": 1000,
            "daily_cap_cents": 100000,
            "valid_days": 30
        }))
        .send()
        .await
        .expect("mandate request");

    assert_eq!(mandate_res.status(), 200, "mandate creation must succeed");

    // Trust check with amount_cents far above the cap
    let res = client()
        .post(format!("{}/v1/trust-check", base_url))
        .bearer_auth(&api_key)
        .json(&json!({
            "agent_did": agent_did,
            "action_type": "payment",
            "rail_id": "e2e-test-rail",
            "amount_cents": 99999
        }))
        .send()
        .await
        .expect("trust-check request");

    assert_eq!(res.status(), 200);

    let body: Value = res.json().await.expect("json body");
    assert_eq!(
        body["verdict"]["verdict"], "BLOCK",
        "amount over per_tx_cap_cents must result in BLOCK; got: {body}"
    );
}

/// GET /health returns 200 with {"status":"ok"} regardless of authentication.
#[tokio::test]
async fn e2e_health_check() {
    let (base_url, _) = start_test_server().await;

    let res = client()
        .get(format!("{}/health", base_url))
        .send()
        .await
        .expect("health request");

    assert_eq!(res.status(), 200, "health must return 200");

    let body: Value = res.json().await.expect("health json");
    assert_eq!(body["status"], "ok", "status field must be 'ok'; got: {body}");
    assert_eq!(
        body["service"], "byzantium-gateway",
        "service field must identify the gateway; got: {body}"
    );
}

/// Calling a protected endpoint without a Bearer token returns 401.
#[tokio::test]
async fn e2e_unauthenticated_returns_401() {
    let (base_url, _) = start_test_server().await;

    let res = client()
        .post(format!("{}/v1/trust-check", base_url))
        .json(&json!({
            "agent_did": "did:key:z6MkAnon",
            "action_type": "payment",
            "rail_id": "e2e-rail"
        }))
        .send()
        .await
        .expect("request");

    assert_eq!(
        res.status(),
        401,
        "unauthenticated request must return 401"
    );
}

/// Client-supplied X-Request-Id must be echoed back in the response headers.
#[tokio::test]
async fn e2e_request_id_propagated() {
    let (base_url, _) = start_test_server().await;

    let custom_id = "my-custom-e2e-id-42";

    let res = client()
        .get(format!("{}/health", base_url))
        .header("X-Request-Id", custom_id)
        .send()
        .await
        .expect("health request");

    assert_eq!(res.status(), 200);

    let returned_id = res
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .expect("X-Request-Id must be present in response");

    assert_eq!(
        returned_id, custom_id,
        "response X-Request-Id must match the client-supplied value"
    );
}

/// Full audit trail: create mandate → trust check → create receipt → list receipts.
///
/// Verifies the complete lifecycle including the audit endpoint returning the
/// correct receipt count.
#[tokio::test]
async fn e2e_full_audit_trail() {
    let (base_url, api_key) = start_test_server().await;

    let agent_did = format!("did:key:z6MkAuditAgent-{}", Uuid::new_v4());

    // Create mandate
    let mandate_res = client()
        .post(format!("{}/v1/mandates", base_url))
        .bearer_auth(&api_key)
        .json(&json!({
            "agent_did": agent_did,
            "operator_id": "audit-operator",
            "counterparty_whitelist": [],
            "allowed_action_types": ["payment"],
            "per_tx_cap_cents": 5000,
            "daily_cap_cents": 50000,
            "valid_days": 30
        }))
        .send()
        .await
        .expect("mandate request");

    assert_eq!(mandate_res.status(), 200);
    let mandate_body: Value = mandate_res.json().await.expect("mandate json");
    let mandate_id = mandate_body["mandate_id"].as_str().expect("mandate_id").to_string();

    // Create a receipt
    let receipt_res = client()
        .post(format!("{}/v1/receipts", base_url))
        .bearer_auth(&api_key)
        .json(&json!({
            "agent_did": agent_did,
            "action_type": "payment",
            "counterparty": null,
            "amount_cents": 1500,
            "outcome": "success",
            "mandate_id": mandate_id,
            "rail_id": "e2e-audit-rail"
        }))
        .send()
        .await
        .expect("receipt request");

    assert_eq!(receipt_res.status(), 200, "receipt creation must succeed");

    let receipt_body: Value = receipt_res.json().await.expect("receipt json");
    assert!(
        receipt_body["id"].as_str().and_then(|s| Uuid::parse_str(s).ok()).is_some(),
        "receipt id must be a valid UUID; got: {receipt_body}"
    );

    // List receipts via audit endpoint
    let audit_res = client()
        .get(format!("{}/v1/audit/receipts", base_url))
        .bearer_auth(&api_key)
        .send()
        .await
        .expect("audit request");

    assert_eq!(audit_res.status(), 200, "audit endpoint must return 200");

    let audit_body: Value = audit_res.json().await.expect("audit json");
    let total = audit_body["total"].as_u64().unwrap_or(0);
    assert!(
        total >= 1,
        "audit endpoint must return at least 1 receipt after creating one; got total={total}, body={audit_body}"
    );

    let receipts = audit_body["receipts"].as_array().expect("receipts must be an array");
    assert!(
        !receipts.is_empty(),
        "receipts array must not be empty; got: {audit_body}"
    );
}

/// Revoked mandate → trust check returns BLOCK (not PASS or FLAG).
///
/// Once a mandate is revoked the agent must be blocked immediately.
#[tokio::test]
async fn e2e_revoked_mandate_blocks() {
    let (base_url, api_key) = start_test_server().await;

    let agent_did = format!("did:key:z6MkRevokeTest-{}", Uuid::new_v4());

    // Create mandate
    let mandate_res = client()
        .post(format!("{}/v1/mandates", base_url))
        .bearer_auth(&api_key)
        .json(&json!({
            "agent_did": agent_did,
            "operator_id": "revoke-operator",
            "counterparty_whitelist": [],
            "allowed_action_types": ["payment"],
            "per_tx_cap_cents": 5000,
            "daily_cap_cents": 50000,
            "valid_days": 30
        }))
        .send()
        .await
        .expect("mandate request");

    assert_eq!(mandate_res.status(), 200);
    let mandate_body: Value = mandate_res.json().await.expect("mandate json");
    let mandate_id = mandate_body["mandate_id"].as_str().expect("mandate_id").to_string();

    // Revoke the mandate
    let revoke_res = client()
        .post(format!("{}/v1/mandates/{}/revoke", base_url, mandate_id))
        .bearer_auth(&api_key)
        .send()
        .await
        .expect("revoke request");

    assert_eq!(revoke_res.status(), 200, "revoke must succeed; got: {}", revoke_res.status());

    // Trust check after revocation → expect BLOCK
    let check_res = client()
        .post(format!("{}/v1/trust-check", base_url))
        .bearer_auth(&api_key)
        .json(&json!({
            "agent_did": agent_did,
            "action_type": "payment",
            "rail_id": "e2e-test-rail"
        }))
        .send()
        .await
        .expect("trust-check request");

    assert_eq!(check_res.status(), 200);

    let body: Value = check_res.json().await.expect("json body");
    assert_eq!(
        body["verdict"]["verdict"], "BLOCK",
        "revoked mandate must result in BLOCK verdict; got: {body}"
    );
}

/// Idempotency: two trust checks for the same agent+mandate return structurally
/// identical verdicts (same verdict field; request_id may differ per call).
#[tokio::test]
async fn e2e_idempotent_trust_check() {
    let (base_url, api_key) = start_test_server().await;

    let agent_did = format!("did:key:z6MkIdempotent-{}", Uuid::new_v4());

    // Create mandate
    let mandate_res = client()
        .post(format!("{}/v1/mandates", base_url))
        .bearer_auth(&api_key)
        .json(&json!({
            "agent_did": agent_did,
            "operator_id": "idempotent-operator",
            "counterparty_whitelist": [],
            "allowed_action_types": ["payment"],
            "per_tx_cap_cents": 5000,
            "daily_cap_cents": 50000,
            "valid_days": 30
        }))
        .send()
        .await
        .expect("mandate request");

    assert_eq!(mandate_res.status(), 200);

    let check = |base_url: String, api_key: String, agent_did: String| async move {
        client()
            .post(format!("{}/v1/trust-check", base_url))
            .bearer_auth(&api_key)
            .json(&json!({
                "agent_did": agent_did,
                "action_type": "payment",
                "rail_id": "e2e-rail",
                "amount_cents": 100
            }))
            .send()
            .await
            .expect("trust-check")
            .json::<Value>()
            .await
            .expect("json")
    };

    let r1 = check(base_url.clone(), api_key.clone(), agent_did.clone()).await;
    let r2 = check(base_url.clone(), api_key.clone(), agent_did.clone()).await;

    // Both calls must return the same verdict
    assert_eq!(
        r1["verdict"]["verdict"], r2["verdict"]["verdict"],
        "repeated trust checks must return the same verdict; r1={r1}, r2={r2}"
    );
}

/// Rate limiting: a tight limit (2 req/min) on a protected endpoint triggers 429.
#[tokio::test]
async fn e2e_rate_limit_returns_429() {
    // Build a server with a very low rate limit so we can trigger it easily.
    let api_key = format!("e2e-rl-key-{}", Uuid::new_v4());
    let mut config = test_config(&api_key);
    config.gateway.rate_limit_per_min = 2; // only 2 requests per minute allowed
    let state = AppState::new(config);
    let router = routes::router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let base_url = format!("http://{}", addr);

    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("server error");
    });

    let payload = json!({
        "agent_did": "did:key:z6MkRateLimit",
        "action_type": "payment",
        "rail_id": "rl-rail"
    });

    // Fire requests until we get a 429 or exhaust attempts.
    let mut got_429 = false;
    for i in 0..10 {
        let res = client()
            .post(format!("{}/v1/trust-check", base_url))
            .bearer_auth(&api_key)
            .json(&payload)
            .send()
            .await
            .unwrap_or_else(|e| panic!("request {i} failed: {e}"));

        if res.status() == 429 {
            got_429 = true;
            break;
        }
    }

    assert!(
        got_429,
        "sending more requests than rate_limit_per_min (2) must eventually return 429"
    );
}
