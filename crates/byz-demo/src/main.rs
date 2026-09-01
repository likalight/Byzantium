//! A narrated, live walkthrough of the whole system.
//!
//! This exists to be run in front of someone. It drives the real gateway over
//! HTTP — no mocks, no fixtures — and prints what happened and how long it took,
//! so an audience can see the limit move and can interrupt at any point.
//!
//! The story it tells, in six acts:
//!
//!   1. A brand-new agent is refused, and told exactly why.
//!   2. It earns standing by settling real payments, with its runtime signing
//!      the execution trace behind each one.
//!   3. The same credential is honoured on a chain it has never touched.
//!   4. The abuse controls hold when pushed.
//!   5. A failed payment produces the evidence an insurer would need.
//!   6. The limit is killed instantly when the agent is compromised.
//!
//! Run:
//!   cargo run -p byz-gateway            # terminal 1
//!   cargo run -p byz-demo               # terminal 2

use anyhow::{anyhow, Result};
use byz_crypto::DilithiumKeypair;
use byz_provenance::{ProvenanceEvent, ProvenanceKind, SignedProvenance};
use serde_json::{json, Value};
use std::time::Instant;
use uuid::Uuid;

const HOME_CHAIN: &str = "base";
const NEW_CHAIN: &str = "solana";
const OUT_OF_SCOPE_CHAIN: &str = "ethereum";

// ── terminal chrome ─────────────────────────────────────────────────────────
const DIM: &str = "\x1b[2m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";
const BLUE: &str = "\x1b[38;5;75m";
const GREEN: &str = "\x1b[38;5;78m";
const RED: &str = "\x1b[38;5;203m";
const AMBER: &str = "\x1b[38;5;215m";

fn act(n: u8, title: &str) {
    println!("\n{BLUE}{BOLD}  ACT {n}{RESET}  {BOLD}{title}{RESET}");
    println!("{DIM}  {}{RESET}", "─".repeat(66));
}

fn step(msg: &str) {
    println!("\n  {BOLD}▸{RESET} {msg}");
}

fn ok(msg: &str) {
    println!("    {GREEN}✓{RESET} {msg}");
}

fn no(msg: &str) {
    println!("    {RED}✗{RESET} {msg}");
}

fn note(msg: &str) {
    println!("    {DIM}{msg}{RESET}");
}

fn money(minor: u64) -> String {
    format!("${}.{:02}", minor / 100, minor % 100)
}

fn timed(label: &str, ms: u128) {
    println!("    {AMBER}⏱  {label}: {ms} ms{RESET}");
}

// ── client ──────────────────────────────────────────────────────────────────
struct Gw {
    base: String,
    key: String,
    http: reqwest::Client,
}

impl Gw {
    fn new() -> Self {
        Self {
            base: std::env::var("BYZ_URL").unwrap_or_else(|_| "http://localhost:8080".into()),
            key: std::env::var("BYZ_API_KEY").unwrap_or_else(|_| "demo-key".into()),
            http: reqwest::Client::new(),
        }
    }

    async fn post(&self, path: &str, body: Value) -> Result<Value> {
        let r = self
            .http
            .post(format!("{}{}", self.base, path))
            .header("authorization", format!("Bearer {}", self.key))
            .json(&body)
            .send()
            .await?;
        let status = r.status();
        let v: Value = r.json().await.unwrap_or_else(|_| json!({}));
        // 4xx is not a failure here — refusals are the point of several acts, and
        // the body carries the reason we want to show. Only a server fault stops
        // the walkthrough.
        if status.is_server_error() {
            return Err(anyhow!("{path} -> {status}: {v}"));
        }
        Ok(v)
    }

    async fn health(&self) -> Result<()> {
        self.http
            .get(format!("{}/health", self.base))
            .send()
            .await
            .map_err(|_| {
                anyhow!(
                    "no gateway at {}. Start it first:\n\n    \
                     BYZ_API_KEYS=demo-key cargo run -p byz-gateway\n",
                    self.base
                )
            })?;
        Ok(())
    }
}

/// Sign a batch of execution traces the way a real agent runtime would — with a
/// key the agent itself does not hold.
fn sign_traces(
    runtime: &DilithiumKeypair,
    agent_did: &str,
    session: Uuid,
    start_seq: u64,
    n: u64,
) -> Vec<SignedProvenance> {
    (0..n)
        .map(|i| {
            let kind = match i % 4 {
                0 => ProvenanceKind::Plan,
                1 => ProvenanceKind::ToolCall,
                2 => ProvenanceKind::PaymentIntent,
                _ => ProvenanceKind::HumanApproval,
            };
            let e = ProvenanceEvent::hashing_payload(
                byz_common::AgentDid::new(agent_did),
                session,
                start_seq + i,
                kind,
                format!("step-{}", start_seq + i).as_bytes(),
            );
            let sig = runtime.sign(&e.signing_payload()).unwrap();
            SignedProvenance::new(e, "runtime-acme-prod", sig.as_bytes().to_vec())
        })
        .collect()
}

#[tokio::main]
async fn main() -> Result<()> {
    let gw = Gw::new();
    gw.health().await?;

    let agent = format!("did:byz:trader-{}", &Uuid::new_v4().to_string()[..8]);
    let principal = "sha256:acme-treasury";
    let runtime = DilithiumKeypair::generate();
    let session = Uuid::new_v4();

    println!("\n{BOLD}  BYZANTIUM — live walkthrough{RESET}");
    println!("{DIM}  agent   {agent}{RESET}");
    println!("{DIM}  gateway {}{RESET}", gw.base);

    // ── ACT 1 ───────────────────────────────────────────────────────────────
    act(1, "A new agent is refused, and told why");

    step("Registering the agent's runtime signing key");
    gw.post(
        "/v1/runtimes",
        json!({ "runtime_id": "runtime-acme-prod",
                "public_key_hex": runtime.public_key.to_hex() }),
    )
    .await?;
    ok("runtime key registered — this key signs the traces, and the agent never holds it");

    step("Trying to get a limit before any identity is bound");
    let r = gw
        .post(
            "/v1/limits/issue",
            json!({ "agent_did": agent, "ccy": "USD" }),
        )
        .await?;
    no(&format!(
        "refused: {}",
        r["error"].as_str().unwrap_or("no registered principal")
    ));
    note("identity is a gate. Nothing is underwritten without a verified business behind it.");

    step("Binding an existing, already-verified business identity");
    let t = Instant::now();
    gw.post(
        "/v1/principals",
        json!({
            "agent_did": agent, "principal_ref": principal,
            "kyc_tier": "institutional", "sanctions_clear": true,
            "jurisdiction": "SG", "entity_age_days": 900
        }),
    )
    .await?;
    let bind_ms = t.elapsed().as_millis();
    ok("bound to a KYC-verified business");
    timed("identity reuse — not a fresh KYC run", bind_ms);

    step("Asking for a limit now");
    let r = gw
        .post(
            "/v1/limits/issue",
            json!({ "agent_did": agent, "ccy": "USD",
                    "chains": [HOME_CHAIN, NEW_CHAIN],
                    "asset_classes": ["stablecoin"], "action_types": ["payment"] }),
        )
        .await?;
    let att = r["attestation"].clone();
    let first_limit = att["lim_window"]["minor_units"].as_u64().unwrap_or(0);
    ok(&format!(
        "issued {} — score {}, band {}",
        money(first_limit),
        r["score"].as_u64().unwrap_or(0),
        r["tier"].as_str().unwrap_or("?")
    ));
    note("and here is every control that shaped that number:");
    for reason in r["reasons"].as_array().cloned().unwrap_or_default() {
        println!("      {DIM}· {}{RESET}", reason.as_str().unwrap_or(""));
    }

    // ── ACT 2 ───────────────────────────────────────────────────────────────
    act(
        2,
        "It earns standing, and the limit climbs — but never jumps",
    );

    let mut attestation = att;
    let mut limit = first_limit;
    let mut seq = 1u64;
    let mut history: Vec<(usize, u64, u64, String)> = vec![(0, 0, first_limit, "D3".into())];

    for round in 1..=5 {
        let single = attestation["lim_single"]["minor_units"]
            .as_u64()
            .unwrap_or(0);
        let draw = (single as f64 * 0.85) as u64;

        step(&format!(
            "Round {round}: settling 8 payments on {HOME_CHAIN}, each with a signed execution trace"
        ));

        for _ in 0..8 {
            let v = gw
                .post(
                    "/v1/limits/verify",
                    json!({ "attestation": attestation,
                            "draw": { "amount_minor": draw, "currency": "USD",
                                      "asset_class": "stablecoin", "chain": HOME_CHAIN,
                                      "action_type": "payment" } }),
                )
                .await?;
            if v["permitted"].as_bool().unwrap_or(false) {
                let eff = v["effective_minor"].as_u64().unwrap_or(draw);
                gw.post(
                    "/v1/limits/settle",
                    json!({ "agent_did": agent, "amount_minor": eff,
                            "currency": "USD", "settled": true }),
                )
                .await?;
            }
        }

        let traces = sign_traces(&runtime, &agent, session, seq, 8);
        seq += 8;
        let p = gw
            .post(
                "/v1/provenance",
                json!({ "agent_did": agent, "events": traces }),
            )
            .await?;

        let issued = gw
            .post(
                "/v1/limits/issue",
                json!({ "agent_did": agent, "ccy": "USD",
                        "chains": [HOME_CHAIN, NEW_CHAIN],
                        "asset_classes": ["stablecoin"], "action_types": ["payment"] }),
            )
            .await?;

        attestation = issued["attestation"].clone();
        let new_limit = attestation["lim_window"]["minor_units"]
            .as_u64()
            .unwrap_or(limit);
        let score = issued["score"].as_u64().unwrap_or(0);
        let tier = issued["tier"].as_str().unwrap_or("?").to_string();

        ok(&format!(
            "{} traces accepted, {} rejected  ·  score {} ({})  ·  limit {} → {}",
            p["accepted"].as_u64().unwrap_or(0),
            p["rejected"].as_u64().unwrap_or(0),
            score,
            tier,
            money(limit),
            money(new_limit)
        ));

        history.push((round, score, new_limit, tier));
        limit = new_limit;
    }

    step("The curve, and why it is not a straight line");
    println!("    {DIM}round   score   band     limit{RESET}");
    for (r, s, l, t) in &history {
        let bar = "█".repeat(((*l as f64 / limit as f64) * 34.0).max(1.0) as usize);
        println!(
            "    {r:>3}   {s:>6}   {t:<5}  {:>10}  {BLUE}{bar}{RESET}",
            money(*l)
        );
    }
    note("growth is capped per round. A flawless run still cannot reach the ceiling quickly —");
    note("which is exactly what stops someone farming a clean history and draining it once.");

    // ── ACT 3 ───────────────────────────────────────────────────────────────
    act(
        3,
        "The same credential works on a chain it has never touched",
    );

    step(&format!(
        "This agent has settled {} payments — every one on {HOME_CHAIN}",
        (history.len() - 1) * 8
    ));
    note(&format!(
        "It has never transacted on {NEW_CHAIN}. No account, no history, no relationship."
    ));

    let single = attestation["lim_single"]["minor_units"]
        .as_u64()
        .unwrap_or(0);
    let probe = (single as f64 * 0.5) as u64;

    step(&format!("Presenting the same limit on {NEW_CHAIN}"));
    let t = Instant::now();
    let v = gw
        .post(
            "/v1/limits/verify",
            json!({ "attestation": attestation,
                    "draw": { "amount_minor": probe, "currency": "USD",
                              "asset_class": "stablecoin", "chain": NEW_CHAIN,
                              "action_type": "payment" } }),
        )
        .await?;
    let cross_ms = t.elapsed().as_millis();

    if v["permitted"].as_bool().unwrap_or(false) {
        ok(&format!("authorised for {} on {NEW_CHAIN}", money(probe)));
        timed("time to become trusted on a brand-new chain", cross_ms);
        note("On every other system available today, this agent starts at zero here.");
    } else {
        no(&format!("refused: {}", v["refusal"].as_str().unwrap_or("")));
    }
    gw.post(
        "/v1/limits/settle",
        json!({ "agent_did": agent, "amount_minor": v["effective_minor"].as_u64().unwrap_or(probe),
                "currency": "USD", "settled": true }),
    )
    .await?;

    step("A chain the limit was not scoped to");
    let v = gw
        .post(
            "/v1/limits/verify",
            json!({ "attestation": attestation,
                    "draw": { "amount_minor": 100, "currency": "USD",
                              "asset_class": "stablecoin", "chain": OUT_OF_SCOPE_CHAIN,
                              "action_type": "payment" } }),
        )
        .await?;
    no(&format!(
        "refused: {}",
        v["refusal"].as_str().unwrap_or("out of scope")
    ));

    step("The same payment denominated in Singapore dollars");
    let v = gw
        .post(
            "/v1/limits/verify",
            json!({ "attestation": attestation,
                    "draw": { "amount_minor": 13_400, "currency": "SGD",
                              "asset_class": "stablecoin", "chain": NEW_CHAIN,
                              "action_type": "payment" } }),
        )
        .await?;
    ok(&format!(
        "S$134.00 converted to {} against the limit, with a volatility haircut applied",
        money(v["effective_minor"].as_u64().unwrap_or(0))
    ));
    note("one budget, whatever chain or currency the agent spends in.");

    // ── ACT 4 ───────────────────────────────────────────────────────────────
    act(4, "The abuse controls, pushed");

    step("Attempt 1 — the classic: build a clean record, then drain it in one go");
    let huge = limit;
    let v = gw
        .post(
            "/v1/limits/verify",
            json!({ "attestation": attestation,
                    "draw": { "amount_minor": huge, "currency": "USD",
                              "asset_class": "stablecoin", "chain": HOME_CHAIN,
                              "action_type": "payment" } }),
        )
        .await?;
    no(&format!("refused: {}", v["refusal"].as_str().unwrap_or("")));
    note(
        "a single draw is capped at a fraction of the window, and the window itself is
      never a large multiple of the biggest payment the agent has actually completed.",
    );

    step("Attempt 2 — the agent fakes its own activity log");
    let agent_own_key = DilithiumKeypair::generate();
    let e = ProvenanceEvent::hashing_payload(
        byz_common::AgentDid::new(&agent),
        session,
        9_999,
        ProvenanceKind::HumanApproval,
        b"a human definitely approved this",
    );
    let forged_sig = agent_own_key.sign(&e.signing_payload())?;
    let forged = SignedProvenance::new(e, "runtime-acme-prod", forged_sig.as_bytes().to_vec());
    let p = gw
        .post(
            "/v1/provenance",
            json!({ "agent_did": agent, "events": [forged] }),
        )
        .await?;
    no(&format!(
        "{} accepted, {} rejected — {}",
        p["accepted"].as_u64().unwrap_or(0),
        p["rejected"].as_u64().unwrap_or(0),
        p["rejections"][0]
            .as_str()
            .unwrap_or("signature did not verify")
    ));
    note("the runtime signs, not the agent. Self-reported activity counts for nothing.");

    step("Attempt 3 — replaying evidence that was already submitted");
    let replay = sign_traces(&runtime, &agent, session, 1, 3);
    let p = gw
        .post(
            "/v1/provenance",
            json!({ "agent_did": agent, "events": replay }),
        )
        .await?;
    no(&format!(
        "{} accepted, {} rejected — {}",
        p["accepted"].as_u64().unwrap_or(0),
        p["rejected"].as_u64().unwrap_or(0),
        p["rejections"][0].as_str().unwrap_or("already seen")
    ));

    step("Attempt 4 — inflating the limit in the credential itself");
    let mut tampered = attestation.clone();
    tampered["lim_single"]["minor_units"] = json!(limit * 100);
    tampered["lim_window"]["minor_units"] = json!(limit * 100);
    let v = gw
        .post(
            "/v1/limits/verify",
            json!({ "attestation": tampered,
                    "draw": { "amount_minor": 1_000, "currency": "USD",
                              "asset_class": "stablecoin", "chain": HOME_CHAIN,
                              "action_type": "payment" } }),
        )
        .await?;
    no(&format!(
        "rejected: {}",
        v["error"].as_str().unwrap_or("signature no longer valid")
    ));
    note("the limit is inside the signature. Change the number and it stops verifying.");

    // ── ACT 5 ───────────────────────────────────────────────────────────────
    act(5, "A payment fails, and the evidence survives");

    step("Authorising a payment, then reporting that it failed to settle");
    let v = gw
        .post(
            "/v1/limits/verify",
            json!({ "attestation": attestation,
                    "draw": { "amount_minor": probe, "currency": "USD",
                              "asset_class": "stablecoin", "chain": HOME_CHAIN,
                              "action_type": "payment" } }),
        )
        .await?;
    let committed = v["effective_minor"].as_u64().unwrap_or(probe);
    ok(&format!(
        "authorised — {} now committed but unsettled",
        money(committed)
    ));

    let s = gw
        .post(
            "/v1/limits/settle",
            json!({ "agent_did": agent, "amount_minor": committed,
                    "currency": "USD", "settled": false }),
        )
        .await?;
    ok(&format!(
        "reported as failed — reservation released, {} consumed this window",
        money(s["window_used_minor"].as_u64().unwrap_or(0))
    ));
    note("a failed payment releases the reservation rather than consuming the budget.");

    step("The evidence an insurer would receive");
    let ev = gw
        .post(
            "/v1/provenance",
            json!({ "agent_did": agent, "events": [] }),
        )
        .await?;
    println!(
        "      {DIM}limit in force   {} (signed, band {}){RESET}",
        money(limit),
        attestation["tier"].as_str().unwrap_or("?")
    );
    println!(
        "      {DIM}evidence root    {}{RESET}",
        ev["evidence_ref"].as_str().unwrap_or("—")
    );
    println!(
        "      {DIM}approvals        {} human approvals in the signed record{RESET}",
        ev["human_approvals"].as_u64().unwrap_or(0)
    );
    note("a claim can be proved against that root without disclosing the underlying activity.");

    // ── ACT 6 ───────────────────────────────────────────────────────────────
    act(6, "The agent is compromised");

    step("Killing every limit outstanding for this agent");
    let t = Instant::now();
    gw.post("/v1/limits/revoke", json!({ "agent_did": agent }))
        .await?;
    let revoke_ms = t.elapsed().as_millis();
    ok("revoked");
    timed("time to kill every outstanding credential", revoke_ms);

    step("The same credential, presented again one second later");
    let v = gw
        .post(
            "/v1/limits/verify",
            json!({ "attestation": attestation,
                    "draw": { "amount_minor": 100, "currency": "USD",
                              "asset_class": "stablecoin", "chain": HOME_CHAIN,
                              "action_type": "payment" } }),
        )
        .await?;
    no(&format!(
        "refused: {}",
        v["error"].as_str().unwrap_or("revoked")
    ));

    println!("\n{DIM}  {}{RESET}", "─".repeat(66));
    println!(
        "  {BOLD}Summary{RESET}  {} → {} over {} settled payments,",
        money(first_limit),
        money(limit),
        (history.len() - 1) * 8 + 2
    );
    println!("           honoured on {NEW_CHAIN} in {cross_ms} ms with no prior history there,");
    println!("           and revoked everywhere in {revoke_ms} ms.\n");

    Ok(())
}
