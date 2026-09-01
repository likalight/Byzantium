//! The limit-attestation extension to TAP.
//!
//! One header, one rule: `Limit-Attestation` carries a base64url-encoded
//! [`LimitAttestation`], and it must be in the signature's covered components.
//!
//! A merchant integrating this checks two signatures answering two questions:
//!
//! | Signature | Question | Answered by |
//! |---|---|---|
//! | TAP HTTP Message Signature | did this request really come from this agent? | the agent's key |
//! | Attestation signature | who stands behind this limit, and what is it? | the issuer's key |
//!
//! TAP alone establishes identity, which is why a merchant today can tell a
//! legitimate agent from a bot but still has no basis for setting a ceiling. The
//! second signature is the missing half.

use base64::Engine as _;
use byz_common::{DrawRequest, LimitAttestation};
use byz_crypto::DilithiumPublicKey;
use byz_underwrite::AttestationIssuer;
use thiserror::Error;

use crate::signature::{CoveredComponent, HttpMessage, TapError, TapVerifier};

/// The extension header. Lowercase, as component identifiers are.
pub const LIMIT_ATTESTATION_HEADER: &str = "limit-attestation";

#[derive(Debug, Error)]
pub enum TapExtensionError {
    #[error("no limit attestation on the request")]
    Missing,
    #[error("limit attestation is not valid base64")]
    NotBase64,
    #[error("limit attestation is not valid JSON: {0}")]
    NotJson(String),
    #[error("limit attestation is present but not covered by the signature")]
    NotCovered,
    #[error("limit attestation signature is invalid: {0}")]
    BadAttestation(String),
    #[error(transparent)]
    Tap(#[from] TapError),
    #[error("draw is outside the attested limit: {0}")]
    DrawRefused(String),
}

/// Attach an attestation to a request. Call before signing, and include
/// [`LIMIT_ATTESTATION_HEADER`] in the covered components.
pub fn attach_limit_attestation(
    msg: &mut HttpMessage,
    attestation: &LimitAttestation,
) -> Result<(), TapExtensionError> {
    let json =
        serde_json::to_vec(attestation).map_err(|e| TapExtensionError::NotJson(e.to_string()))?;
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json);
    msg.set_header(LIMIT_ATTESTATION_HEADER, encoded);
    Ok(())
}

/// Read the attestation off a request without verifying anything about it.
pub fn extract_limit_attestation(msg: &HttpMessage) -> Result<LimitAttestation, TapExtensionError> {
    let raw = msg
        .header(LIMIT_ATTESTATION_HEADER)
        .ok_or(TapExtensionError::Missing)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(raw)
        .map_err(|_| TapExtensionError::NotBase64)?;
    serde_json::from_slice(&bytes).map_err(|e| TapExtensionError::NotJson(e.to_string()))
}

/// The component list a TAP verifier should require when this extension is in use.
pub fn required_components() -> Vec<CoveredComponent> {
    vec![CoveredComponent::new(LIMIT_ATTESTATION_HEADER)]
}

/// Full merchant-side check: TAP signature, then attestation signature, then the
/// draw against the attested limit.
///
/// Refusing an uncovered attestation is not pedantry. A header outside the
/// covered list can be rewritten by anything on the network path, so an
/// uncovered `Limit-Attestation` is an attacker-chosen limit.
pub fn verify_request_with_limit(
    verifier: &TapVerifier,
    msg: &HttpMessage,
    label: &str,
    issuer_key: &DilithiumPublicKey,
    draw: &DrawRequest,
) -> Result<LimitAttestation, TapExtensionError> {
    verifier.verify(msg, label)?;

    // The verifier only enforces coverage if it was configured to. Check here
    // too, so a misconfigured verifier cannot silently accept a swapped limit.
    let covered = msg
        .header("signature-input")
        .map(|s| s.contains(LIMIT_ATTESTATION_HEADER))
        .unwrap_or(false);
    if !covered {
        return Err(TapExtensionError::NotCovered);
    }

    let attestation = extract_limit_attestation(msg)?;
    AttestationIssuer::verify(&attestation, issuer_key)
        .map_err(|e| TapExtensionError::BadAttestation(e.to_string()))?;

    attestation
        .permits(draw, chrono::Utc::now())
        .map_err(|r| TapExtensionError::DrawRefused(r.describe()))?;

    Ok(attestation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::TapSigner;
    use byz_common::{
        ActionType, AgentDid, AssetClass, Currency, ExposureSnapshot, KycTier, LimitScope, Money,
        PrincipalStanding, ReceiptOutcome,
    };
    use byz_crypto::DilithiumKeypair;
    use byz_reputation_shim::build_attestation;

    /// Small helper module so the test reads as a merchant integration rather
    /// than as underwriting setup.
    mod byz_reputation_shim {
        use super::*;
        use byz_underwrite::{Underwriter, UnderwritingInput};

        pub fn build_attestation(
            issuer: &AttestationIssuer,
            chains: Vec<String>,
        ) -> LimitAttestation {
            let did = AgentDid::new("did:byz:agent");
            let mut svc = byz_reputation::ReputationService::new(400);
            svc.bind_principal(&did, "sha256:acme");
            let now = chrono::Utc::now();
            for i in 0..60 {
                svc.ingest(
                    byz_reputation::ScoringEvent::new(did.clone(), ReceiptOutcome::Success, false)
                        .with_amount(Money::usd_cents(400_000))
                        .with_counterparty(format!("cp-{}", i % 25))
                        .at(now - chrono::Duration::hours(i)),
                );
            }
            let rep = svc.detail(&did);
            let decision = Underwriter::default().underwrite(&UnderwritingInput {
                agent_did: did.clone(),
                reputation: rep.clone(),
                standing: PrincipalStanding {
                    principal_ref: "sha256:acme".into(),
                    kyc_tier: KycTier::Institutional,
                    sanctions_clear: true,
                    jurisdiction: "SG".into(),
                    entity_age_days: 900,
                    agent_count: 1,
                },
                exposure: ExposureSnapshot::empty(did, Currency::Usd),
                previous: None,
                ccy: Currency::Usd,
                scope: LimitScope::any()
                    .with_chains(chains)
                    .with_asset_classes(vec![AssetClass::Stablecoin])
                    .with_action_types(vec![ActionType::Payment]),
            });
            issuer
                .issue(&decision, &rep, "sha256:acme", "sha256:m", 3600)
                .unwrap()
        }
    }

    struct Setup {
        verifier: TapVerifier,
        issuer_key: DilithiumPublicKey,
        attestation: LimitAttestation,
        signer: TapSigner,
    }

    fn setup() -> Setup {
        let issuer = AttestationIssuer::new("did:web:byzantium", DilithiumKeypair::generate());
        let attestation = build_attestation(&issuer, vec!["base".into(), "solana".into()]);

        let agent_kp = DilithiumKeypair::generate();
        let signer = TapSigner::new("agent-key-1", agent_kp.clone());

        let mut verifier = TapVerifier::new();
        verifier.register_key("agent-key-1", agent_kp.public_key.clone());
        verifier.require_component(CoveredComponent::new(LIMIT_ATTESTATION_HEADER));

        Setup {
            verifier,
            issuer_key: issuer.public_key().clone(),
            attestation,
            signer,
        }
    }

    fn request(s: &Setup, cover_attestation: bool) -> HttpMessage {
        let mut msg = HttpMessage::new("POST", "https://merchant.example/checkout")
            .with_body(br#"{"sku":"widget-9"}"#.to_vec());
        attach_limit_attestation(&mut msg, &s.attestation).unwrap();

        let mut components: Vec<CoveredComponent> =
            vec!["@method".into(), "@target-uri".into(), "@authority".into()];
        if cover_attestation {
            components.push(CoveredComponent::new(LIMIT_ATTESTATION_HEADER));
        }
        s.signer.sign(&mut msg, &components, "sig1").unwrap();
        msg
    }

    fn draw(amount: u64, chain: &str) -> DrawRequest {
        DrawRequest {
            amount: Money::usd_cents(amount),
            asset_class: AssetClass::Stablecoin,
            chain: chain.to_string(),
            action_type: ActionType::Payment,
            counterparty_class: None,
            window_used: Money::zero(Currency::Usd),
        }
    }

    #[test]
    fn attestation_roundtrips_through_the_header() {
        let s = setup();
        let mut msg = HttpMessage::new("POST", "https://x/y");
        attach_limit_attestation(&mut msg, &s.attestation).unwrap();
        let back = extract_limit_attestation(&msg).unwrap();
        assert_eq!(back.sub, s.attestation.sub);
        assert_eq!(back.lim_window, s.attestation.lim_window);
    }

    #[test]
    fn a_merchant_accepts_a_signed_covered_attestation() {
        let s = setup();
        let msg = request(&s, true);
        let att = verify_request_with_limit(
            &s.verifier,
            &msg,
            "sig1",
            &s.issuer_key,
            &draw(1_000, "base"),
        )
        .expect("merchant rejected a well-formed request");
        assert_eq!(att.sub.as_str(), "did:byz:agent");
    }

    #[test]
    fn an_uncovered_attestation_is_refused() {
        // The whole reason coverage is mandatory.
        let s = setup();
        let msg = request(&s, false);
        let err = verify_request_with_limit(
            &s.verifier,
            &msg,
            "sig1",
            &s.issuer_key,
            &draw(1_000, "base"),
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                TapExtensionError::Tap(TapError::ComponentNotCovered(_))
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn swapping_in_a_larger_limit_breaks_the_tap_signature() {
        let s = setup();
        let mut msg = request(&s, true);

        // Attacker on the path inflates the limit a hundredfold.
        let mut inflated = s.attestation.clone();
        inflated.lim_single = Money::usd_cents(inflated.lim_single.minor_units * 100);
        inflated.lim_window = Money::usd_cents(inflated.lim_window.minor_units * 100);
        attach_limit_attestation(&mut msg, &inflated).unwrap();

        let err = verify_request_with_limit(
            &s.verifier,
            &msg,
            "sig1",
            &s.issuer_key,
            &draw(1_000, "base"),
        )
        .unwrap_err();
        assert!(
            matches!(err, TapExtensionError::Tap(TapError::BadSignature)),
            "got {err:?}"
        );
    }

    #[test]
    fn a_forged_attestation_fails_the_issuer_check() {
        // Signed correctly by the agent, but the attestation itself is fake.
        let s = setup();
        let rogue_issuer =
            AttestationIssuer::new("did:web:not-byzantium", DilithiumKeypair::generate());
        let fake = build_attestation(&rogue_issuer, vec!["base".into()]);

        let mut msg = HttpMessage::new("POST", "https://merchant.example/checkout")
            .with_body(br#"{"sku":"widget-9"}"#.to_vec());
        attach_limit_attestation(&mut msg, &fake).unwrap();
        s.signer
            .sign(
                &mut msg,
                &[
                    "@method".into(),
                    "@target-uri".into(),
                    CoveredComponent::new(LIMIT_ATTESTATION_HEADER),
                ],
                "sig1",
            )
            .unwrap();

        let err = verify_request_with_limit(
            &s.verifier,
            &msg,
            "sig1",
            &s.issuer_key,
            &draw(1_000, "base"),
        )
        .unwrap_err();
        assert!(
            matches!(err, TapExtensionError::BadAttestation(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn a_draw_beyond_the_limit_is_refused_at_the_merchant() {
        let s = setup();
        let msg = request(&s, true);
        let too_big = s.attestation.lim_single.minor_units + 1;
        let err = verify_request_with_limit(
            &s.verifier,
            &msg,
            "sig1",
            &s.issuer_key,
            &draw(too_big, "base"),
        )
        .unwrap_err();
        assert!(
            matches!(err, TapExtensionError::DrawRefused(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn a_chain_outside_the_attested_scope_is_refused() {
        let s = setup();
        let msg = request(&s, true);
        let err = verify_request_with_limit(
            &s.verifier,
            &msg,
            "sig1",
            &s.issuer_key,
            &draw(1_000, "ethereum"),
        )
        .unwrap_err();
        assert!(
            matches!(err, TapExtensionError::DrawRefused(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn a_request_with_no_attestation_is_refused_when_required() {
        let s = setup();
        let mut msg = HttpMessage::new("POST", "https://merchant.example/checkout");
        s.signer
            .sign(&mut msg, &["@method".into(), "@target-uri".into()], "sig1")
            .unwrap();
        let err =
            verify_request_with_limit(&s.verifier, &msg, "sig1", &s.issuer_key, &draw(10, "base"))
                .unwrap_err();
        assert!(matches!(
            err,
            TapExtensionError::Tap(TapError::ComponentNotCovered(_))
        ));
    }
}
