//! End-to-end: an agent earns standing on one chain and spends it on another.
//!
//! This is the claim the whole system makes, exercised without a network: build
//! attested history, underwrite it once, then present the resulting credential
//! against a chain that has never seen this agent before. Nothing bridges — the
//! destination verifies a signature.

use byz_common::{
    ActionType, AgentDid, AssetClass, Currency, DrawRequest, ExposureSnapshot, FxTable, KycTier,
    LimitScope, Money, PrincipalStanding, ReceiptOutcome,
};
use byz_crypto::DilithiumKeypair;
use byz_mandate::{ExposureLedger, InMemoryExposureLedger, MandateBuilder};
use byz_provenance::{
    ProvenanceBundle, ProvenanceEvent, ProvenanceKind, ProvenanceVerifier, RuntimeRegistry,
    SignedProvenance,
};
use byz_reputation::{ReputationService, ScoringEvent};
use byz_underwrite::{
    AttestationIssuer, PreviousLimit, Underwriter, UnderwritingConfig, UnderwritingInput,
};
use chrono::{Duration, Utc};
use uuid::Uuid;

const HOME_CHAIN: &str = "base";
const DESTINATION_CHAIN: &str = "solana";
const UNSCOPED_CHAIN: &str = "ethereum";

struct World {
    did: AgentDid,
    reputation: ReputationService,
    ledger: InMemoryExposureLedger,
    issuer: AttestationIssuer,
    runtime_kp: DilithiumKeypair,
    runtimes: RuntimeRegistry,
    fx: FxTable,
}

fn world() -> World {
    let did = AgentDid::new("did:byz:trader-01");
    let runtime_kp = DilithiumKeypair::generate();
    let mut runtimes = RuntimeRegistry::new();
    runtimes.register("runtime-1", runtime_kp.public_key.clone());

    let mut reputation = ReputationService::new(400);
    reputation.bind_principal(&did, "sha256:acme");

    World {
        did,
        reputation,
        ledger: InMemoryExposureLedger::new(),
        issuer: AttestationIssuer::new("did:web:byzantium", DilithiumKeypair::generate()),
        runtime_kp,
        runtimes,
        fx: FxTable::default(),
    }
}

/// Settle `count` clean transfers on the home chain, each with a runtime-signed
/// execution trace behind it.
fn build_history(w: &mut World, count: i64, per_tx_cents: u64) -> ProvenanceBundle {
    let now = Utc::now();
    let session = Uuid::new_v4();
    let mut signed = Vec::new();

    for i in 0..count {
        w.reputation.ingest(
            ScoringEvent::new(w.did.clone(), ReceiptOutcome::Success, false)
                .with_amount(Money::usd_cents(per_tx_cents))
                .with_counterparty(format!("merchant-{}", i % 30))
                .with_asset_class(AssetClass::Stablecoin)
                .at(now - Duration::hours(i)),
        );

        let event = ProvenanceEvent::hashing_payload(
            w.did.clone(),
            session,
            (i + 1) as u64,
            ProvenanceKind::PaymentIntent,
            format!("draw-{i}").as_bytes(),
        )
        .at(now - Duration::hours(i));
        let sig = w.runtime_kp.sign(&event.signing_payload()).unwrap();
        signed.push(SignedProvenance::new(
            event,
            "runtime-1",
            sig.as_bytes().to_vec(),
        ));
    }

    let mut verifier = ProvenanceVerifier::new(&w.runtimes, w.did.clone());
    let (verified, rejected) = verifier.verify_batch(&signed);
    assert!(
        rejected.is_empty(),
        "runtime-signed traces were rejected: {rejected:?}"
    );

    ProvenanceBundle::build(w.did.clone(), verified, 0).unwrap()
}

fn standing() -> PrincipalStanding {
    PrincipalStanding {
        principal_ref: "sha256:acme".to_string(),
        kyc_tier: KycTier::Institutional,
        sanctions_clear: true,
        jurisdiction: "SG".to_string(),
        entity_age_days: 900,
        agent_count: 1,
    }
}

fn underwrite(w: &World, previous: Option<PreviousLimit>) -> byz_underwrite::UnderwritingDecision {
    let input = UnderwritingInput {
        agent_did: w.did.clone(),
        reputation: w.reputation.detail(&w.did),
        standing: standing(),
        exposure: w.ledger.snapshot(&w.did, Currency::Usd),
        previous,
        ccy: Currency::Usd,
        scope: LimitScope::any()
            .with_chains(vec![HOME_CHAIN.into(), DESTINATION_CHAIN.into()])
            .with_asset_classes(vec![AssetClass::Stablecoin])
            .with_action_types(vec![ActionType::Payment]),
    };
    Underwriter::new(UnderwritingConfig::default()).underwrite(&input)
}

fn draw(w: &World, amount: Money, chain: &str, class: AssetClass, ccy: Currency) -> DrawRequest {
    let effective = w.fx.convert_with_haircut(&amount, ccy, class).unwrap();
    let exposure = w.ledger.snapshot(&w.did, ccy);
    DrawRequest {
        amount: effective,
        asset_class: class,
        chain: chain.to_string(),
        action_type: ActionType::Payment,
        counterparty_class: None,
        window_used: exposure.total_committed().unwrap(),
    }
}

#[test]
fn a_limit_earned_on_one_chain_is_honored_on_another() {
    let mut w = world();
    let bundle = build_history(&mut w, 80, 250_000);

    let decision = underwrite(&w, None);
    assert!(
        decision.is_issued(),
        "underwriting refused: {:?}",
        decision.explain()
    );

    let attestation = w
        .issuer
        .issue_with_evidence(
            &decision,
            &w.reputation.detail(&w.did),
            "sha256:acme",
            "sha256:mandate",
            3600,
            Some(bundle.evidence_ref()),
        )
        .unwrap();

    // The destination has never seen this agent. All it does is check a signature.
    AttestationIssuer::verify(&attestation, w.issuer.public_key())
        .expect("destination chain could not verify the attestation");

    let d = draw(
        &w,
        Money::usd_cents(attestation.lim_single.minor_units / 2),
        DESTINATION_CHAIN,
        AssetClass::Stablecoin,
        Currency::Usd,
    );
    assert!(
        attestation.permits(&d, Utc::now()).is_ok(),
        "a limit earned on {HOME_CHAIN} was not honored on {DESTINATION_CHAIN}"
    );

    // The evidence commitment is the provenance root, not a restatement of the score.
    assert_eq!(attestation.ev, bundle.evidence_ref());
    assert!(attestation.ev.starts_with("sha256:"));
}

#[test]
fn a_chain_outside_the_scope_is_refused() {
    let mut w = world();
    build_history(&mut w, 80, 250_000);
    let decision = underwrite(&w, None);
    let att = w
        .issuer
        .issue(
            &decision,
            &w.reputation.detail(&w.did),
            "sha256:acme",
            "m",
            3600,
        )
        .unwrap();

    let d = draw(
        &w,
        Money::usd_cents(1_000),
        UNSCOPED_CHAIN,
        AssetClass::Stablecoin,
        Currency::Usd,
    );
    assert!(att.permits(&d, Utc::now()).is_err());
}

#[test]
fn a_foreign_currency_draw_converts_and_takes_a_haircut() {
    let mut w = world();
    build_history(&mut w, 80, 250_000);
    let decision = underwrite(&w, None);
    let att = w
        .issuer
        .issue(
            &decision,
            &w.reputation.detail(&w.did),
            "sha256:acme",
            "m",
            3600,
        )
        .unwrap();

    // 1,340.00 SGD is about 1,000.00 USD at the default rate.
    let sgd = Money::new(134_000, Currency::Sgd);
    let effective =
        w.fx.convert_with_haircut(&sgd, Currency::Usd, AssetClass::Stablecoin)
            .unwrap();

    assert_eq!(effective.currency, Currency::Usd);
    assert!(
        effective.minor_units > 100_000,
        "haircut was not applied: {effective}"
    );
    assert!(
        effective.minor_units < 101_000,
        "haircut was implausibly large: {effective}"
    );

    let d = DrawRequest {
        amount: effective,
        asset_class: AssetClass::Stablecoin,
        chain: DESTINATION_CHAIN.to_string(),
        action_type: ActionType::Payment,
        counterparty_class: None,
        window_used: Money::zero(Currency::Usd),
    };
    assert!(att.permits(&d, Utc::now()).is_ok());
}

#[test]
fn a_volatile_asset_consumes_more_of_the_window_than_a_stablecoin() {
    let w = world();
    let amount = Money::usd_cents(100_000);
    let stable =
        w.fx.convert_with_haircut(&amount, Currency::Usd, AssetClass::Stablecoin)
            .unwrap();
    let volatile =
        w.fx.convert_with_haircut(&amount, Currency::Usd, AssetClass::Volatile)
            .unwrap();
    assert!(volatile.minor_units > stable.minor_units);
}

#[test]
fn exposure_accumulates_across_chains_against_one_window() {
    // The point of a single unit of account: draws on different chains are not
    // separate budgets.
    let mut w = world();
    build_history(&mut w, 80, 250_000);
    let decision = underwrite(&w, None);
    let att = w
        .issuer
        .issue(
            &decision,
            &w.reputation.detail(&w.did),
            "sha256:acme",
            "m",
            3600,
        )
        .unwrap();

    let window = att.lim_window.minor_units;
    // Below the single cap, since the stablecoin haircut widens what a draw
    // actually consumes — asking for exactly the cap is already over it.
    let per_draw = Money::usd_cents(att.lim_single.minor_units * 9 / 10);
    let effective =
        w.fx.convert_with_haircut(&per_draw, Currency::Usd, AssetClass::Stablecoin)
            .unwrap();

    // Fill the window with draws alternating between the two chains.
    let mut draws = 0;
    loop {
        let chain = if draws % 2 == 0 {
            HOME_CHAIN
        } else {
            DESTINATION_CHAIN
        };
        let d = draw(&w, per_draw, chain, AssetClass::Stablecoin, Currency::Usd);
        if att.permits(&d, Utc::now()).is_err() {
            break;
        }
        w.ledger.record_commit(&w.did, effective);
        w.ledger.record_settled(&w.did, effective);
        draws += 1;
        assert!(draws < 1_000, "window never filled");
    }

    let used = w
        .ledger
        .snapshot(&w.did, Currency::Usd)
        .window_used
        .minor_units;
    assert!(draws > 1, "only {draws} draws fit before refusal");
    assert!(
        used > window / 2,
        "stopped at {used} of a {window} window — the chains were not sharing it"
    );

    // The refusal is about the shared window, not about the chain.
    let d = draw(
        &w,
        per_draw,
        DESTINATION_CHAIN,
        AssetClass::Stablecoin,
        Currency::Usd,
    );
    assert!(
        matches!(
            att.permits(&d, Utc::now()),
            Err(byz_common::DrawRefusal::ExceedsWindow { .. })
        ),
        "expected a window refusal, got {:?}",
        att.permits(&d, Utc::now())
    );
}

#[test]
fn an_agent_with_no_kyc_gets_nothing_however_good_its_history() {
    let mut w = world();
    build_history(&mut w, 200, 500_000);

    let decision = Underwriter::default().underwrite(&UnderwritingInput {
        agent_did: w.did.clone(),
        reputation: w.reputation.detail(&w.did),
        standing: PrincipalStanding::unverified("sha256:acme"),
        exposure: ExposureSnapshot::empty(w.did.clone(), Currency::Usd),
        previous: None,
        ccy: Currency::Usd,
        scope: LimitScope::any(),
    });
    assert!(!decision.is_issued());
    assert_eq!(decision.lim_window.minor_units, 0);
}

#[test]
fn forged_provenance_never_reaches_the_evidence_bundle() {
    let mut w = world();
    let session = Uuid::new_v4();

    // The agent signs its own trace with a key it controls.
    let agent_kp = DilithiumKeypair::generate();
    let event = ProvenanceEvent::new(
        w.did.clone(),
        session,
        1,
        ProvenanceKind::HumanApproval,
        "sha256:fabricated",
    );
    let sig = agent_kp.sign(&event.signing_payload()).unwrap();
    let forged = SignedProvenance::new(event, "runtime-1", sig.as_bytes().to_vec());

    let mut verifier = ProvenanceVerifier::new(&w.runtimes, w.did.clone());
    let (verified, rejected) = verifier.verify_batch(&[forged]);
    assert!(verified.is_empty());
    assert_eq!(rejected.len(), 1);

    let bundle = ProvenanceBundle::build(w.did.clone(), verified, rejected.len()).unwrap();
    assert!(bundle.is_empty());
    assert_eq!(bundle.evidence_ref(), "sha256:empty");
    let _ = &mut w;
}

#[test]
fn the_issued_mandate_matches_the_attestation() {
    // Enforcement and issuance must agree on the same numbers, or the mandate
    // silently overrides the limit that was underwritten.
    let mut w = world();
    build_history(&mut w, 80, 250_000);
    let decision = underwrite(&w, None);

    let mandate = MandateBuilder::from_decision(&decision, "acme", vec!["merchant-1".into()])
        .expect("mandate could not be built from the decision");

    assert_eq!(mandate.per_tx_cap_cents, decision.lim_single.minor_units);
    assert_eq!(mandate.daily_cap_cents, decision.lim_window.minor_units);
    assert!(mandate.allows_action(&ActionType::Payment));
    assert!(mandate.allows_counterparty("merchant-1"));
    assert!(mandate.mandate_root.is_some());
}

#[test]
fn reissue_cannot_step_straight_to_the_ceiling() {
    let mut w = world();
    build_history(&mut w, 40, 100_000);
    let first = underwrite(&w, None);
    assert!(first.is_issued());

    // A large amount of additional clean history arrives.
    build_history(&mut w, 300, 5_000_000);
    let second = underwrite(
        &w,
        Some(PreviousLimit {
            lim_window: first.lim_window,
            issued_at: Utc::now() - Duration::days(30),
        }),
    );

    let ceiling = first.lim_window.minor_units as f64 * 1.5 + 50_000.0;
    assert!(
        second.lim_window.minor_units as f64 <= ceiling,
        "limit jumped from {} to {} in one window",
        first.lim_window.minor_units,
        second.lim_window.minor_units
    );
    assert!(
        second.lim_window.minor_units > first.lim_window.minor_units,
        "limit did not grow at all"
    );
}
