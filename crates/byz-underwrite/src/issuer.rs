//! Signing and verification of limit attestations.
//!
//! The attestation carries a hash of the evidence bundle, never the evidence.
//! Agent logs and memory are commercially sensitive and frequently the
//! principal's own intellectual property — "send us your traces" is a non-starter
//! for any serious operator. A dispute is reconstructed by recomputing the hash
//! from the retained inputs, which keeps the audit property without ever
//! publishing what was audited.

use byz_common::{
    AgentDid, ByzResult, ByzantiumError, Currency, LimitAttestation, LimitScope, Money, RiskTier,
};
use byz_crypto::{sha256_hex, DilithiumKeypair, DilithiumPublicKey, DilithiumSignature};
use byz_reputation::ReputationDetail;
use chrono::{Duration, Utc};
use serde_json::json;

use crate::engine::{DecisionReason, UnderwritingDecision};
use crate::guarantor::{BureauGuarantor, Guarantor};

pub struct AttestationIssuer {
    issuer_did: String,
    keypair: DilithiumKeypair,
    /// Who stands behind the limits this issuer signs. Defaults to the bureau
    /// model: attest, and let the relying party carry the loss.
    guarantor: Box<dyn Guarantor>,
}

impl AttestationIssuer {
    pub fn new(issuer_did: impl Into<String>, keypair: DilithiumKeypair) -> Self {
        Self {
            issuer_did: issuer_did.into(),
            keypair,
            guarantor: Box::new(BureauGuarantor),
        }
    }

    /// Put a risk-bearer behind the limits. The attestation format does not
    /// change, which is the point: moving from bureau to underwritten is a
    /// deployment decision rather than a re-architecture.
    pub fn with_guarantor(mut self, guarantor: Box<dyn Guarantor>) -> Self {
        self.guarantor = guarantor;
        self
    }

    pub fn guarantor_name(&self) -> &str {
        self.guarantor.name()
    }

    pub fn issuer_did(&self) -> &str {
        &self.issuer_did
    }

    pub fn public_key(&self) -> &DilithiumPublicKey {
        &self.keypair.public_key
    }

    /// Canonical hash over everything that fed the decision. Deterministic, so
    /// the same inputs always reproduce the same `ev` value.
    pub fn evidence_hash(rep: &ReputationDetail, reasons: &[DecisionReason]) -> String {
        let canonical = json!({
            "agent_did": rep.agent_did.as_str(),
            "score": rep.score,
            "compliance_rate_bps": (rep.compliance_rate * 10_000.0).round() as u64,
            "violation_rate_bps": (rep.violation_rate * 10_000.0).round() as u64,
            "total_actions": rep.total_actions,
            "weighted_settled_minor": rep.weighted_settled_minor.to_string(),
            "lifetime_settled_minor": rep.lifetime_settled_minor.to_string(),
            "largest_single_minor": rep.largest_single_minor,
            "distinct_counterparties": rep.distinct_counterparties,
            "principal_ref": rep.principal_ref,
            "penalties": rep.penalties,
            "reasons": reasons,
        });
        let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
        format!("sha256:{}", sha256_hex(&bytes))
    }

    /// Turn an issued decision into a signed, short-lived attestation.
    ///
    /// The evidence hash is derived from the underwriting inputs. Use
    /// [`issue_with_evidence`](Self::issue_with_evidence) when a provenance
    /// bundle already commits to the execution history.
    pub fn issue(
        &self,
        decision: &UnderwritingDecision,
        rep: &ReputationDetail,
        principal_ref: impl Into<String>,
        mandate_hash: impl Into<String>,
        ttl_secs: u64,
    ) -> ByzResult<LimitAttestation> {
        self.issue_with_evidence(decision, rep, principal_ref, mandate_hash, ttl_secs, None)
    }

    /// As [`issue`](Self::issue), but binds an externally computed evidence
    /// commitment — normally a provenance bundle's Merkle root, which covers the
    /// runtime-signed traces behind the decision rather than only its summary.
    pub fn issue_with_evidence(
        &self,
        decision: &UnderwritingDecision,
        rep: &ReputationDetail,
        principal_ref: impl Into<String>,
        mandate_hash: impl Into<String>,
        ttl_secs: u64,
        evidence_ref: Option<String>,
    ) -> ByzResult<LimitAttestation> {
        if !decision.is_issued() {
            return Err(ByzantiumError::MandateViolation(
                "cannot issue an attestation for a refused underwriting decision".to_string(),
            ));
        }

        let now = Utc::now();
        let mut attestation = LimitAttestation {
            sub: decision.agent_did.clone(),
            prn: principal_ref.into(),
            iss: self.issuer_did.clone(),
            tier: decision.tier,
            lim_single: decision.lim_single,
            lim_window: decision.lim_window,
            window_secs: decision.window_secs,
            ccy: decision.ccy,
            scope: decision.scope.clone(),
            fee_bps: decision.tier.fee_bps(),
            collateral_bps: decision.tier.collateral_bps(),
            nbf: now,
            exp: now + Duration::seconds(ttl_secs as i64),
            ev: evidence_ref.unwrap_or_else(|| Self::evidence_hash(rep, &decision.reasons)),
            mandate_hash: mandate_hash.into(),
            guarantee: Some(self.guarantor.assess(decision)),
            collateral_required: Some(decision.collateral_required),
            signature: None,
            issuer_pubkey: Some(self.keypair.public_key.to_hex()),
        };

        let payload = attestation.signing_payload()?;
        let sig = self.keypair.sign(&payload)?;
        attestation.signature = Some(sig.as_bytes().to_vec());
        Ok(attestation)
    }

    /// Verify a presented attestation against a known issuer key.
    ///
    /// This is the whole integration surface for a destination chain: check the
    /// signature, then check validity. Nothing bridges, so adding a chain costs
    /// one verifier rather than a message-passing dependency.
    pub fn verify(
        attestation: &LimitAttestation,
        issuer_key: &DilithiumPublicKey,
    ) -> ByzResult<()> {
        let sig_bytes = attestation
            .signature
            .as_ref()
            .ok_or(ByzantiumError::InvalidSignature)?;
        let payload = attestation.signing_payload()?;
        let sig = DilithiumSignature(sig_bytes.clone());
        byz_crypto::dilithium::verify(&payload, &sig, issuer_key)?;

        if !attestation.is_valid_at(Utc::now()) {
            return Err(ByzantiumError::MandateInactive);
        }
        Ok(())
    }

    /// Verify using the public key carried on the attestation itself.
    ///
    /// Only meaningful when the caller has independently established that the key
    /// belongs to a trusted issuer — a self-described key proves nothing on its
    /// own. Kept separate from [`verify`] so that check cannot be skipped by
    /// accident.
    pub fn verify_self_described(attestation: &LimitAttestation) -> ByzResult<()> {
        let hex = attestation
            .issuer_pubkey
            .as_ref()
            .ok_or_else(|| ByzantiumError::Crypto("attestation carries no issuer key".into()))?;
        let key = DilithiumPublicKey::from_hex(hex)?;
        Self::verify(attestation, &key)
    }
}

/// An attestation with no limits, used to represent a refusal on the wire.
pub fn refusal_attestation(
    agent_did: &AgentDid,
    issuer_did: &str,
    ccy: Currency,
) -> LimitAttestation {
    let now = Utc::now();
    LimitAttestation {
        sub: agent_did.clone(),
        prn: String::new(),
        iss: issuer_did.to_string(),
        tier: RiskTier::D3,
        lim_single: Money::zero(ccy),
        lim_window: Money::zero(ccy),
        window_secs: 0,
        ccy,
        scope: LimitScope::any(),
        fee_bps: RiskTier::D3.fee_bps(),
        collateral_bps: RiskTier::D3.collateral_bps(),
        nbf: now,
        exp: now,
        ev: String::new(),
        mandate_hash: String::new(),
        guarantee: Some(byz_common::Guarantee::bureau(ccy)),
        collateral_required: Some(Money::zero(ccy)),
        signature: None,
        issuer_pubkey: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{PreviousLimit, Underwriter, UnderwritingConfig, UnderwritingInput};
    use byz_common::{ExposureSnapshot, KycTier, PrincipalStanding, ReceiptOutcome};
    use byz_reputation::{ReputationService, ScoringEvent};

    fn setup() -> (AgentDid, ReputationDetail, UnderwritingDecision) {
        let did = AgentDid::new("did:byz:agent");
        let mut svc = ReputationService::new(400);
        svc.bind_principal(&did, "sha256:prn");
        let now = Utc::now();
        for i in 0..60 {
            svc.ingest(
                ScoringEvent::new(did.clone(), ReceiptOutcome::Success, false)
                    .with_amount(Money::usd_cents(400_000))
                    .with_counterparty(format!("cp-{}", i % 25))
                    .at(now - Duration::hours(i)),
            );
        }
        let rep = svc.detail(&did);

        let input = UnderwritingInput {
            agent_did: did.clone(),
            reputation: rep.clone(),
            standing: PrincipalStanding {
                principal_ref: "sha256:prn".to_string(),
                kyc_tier: KycTier::Institutional,
                sanctions_clear: true,
                jurisdiction: "SG".to_string(),
                entity_age_days: 900,
                agent_count: 1,
            },
            exposure: ExposureSnapshot::empty(did.clone(), Currency::Usd),
            previous: None,
            ccy: Currency::Usd,
            scope: LimitScope::any().with_chains(vec!["base".into(), "solana".into()]),
        };
        let decision = Underwriter::new(UnderwritingConfig::default()).underwrite(&input);
        (did, rep, decision)
    }

    #[test]
    fn issued_attestation_verifies() {
        let (_did, rep, decision) = setup();
        let issuer = AttestationIssuer::new("did:web:byzantium", DilithiumKeypair::generate());
        let att = issuer
            .issue(&decision, &rep, "sha256:prn", "sha256:mandate", 3600)
            .unwrap();

        assert!(AttestationIssuer::verify(&att, issuer.public_key()).is_ok());
        assert!(AttestationIssuer::verify_self_described(&att).is_ok());
        assert_eq!(att.fee_bps, decision.tier.fee_bps());
        assert!(att.ev.starts_with("sha256:"));
    }

    #[test]
    fn tampering_with_a_limit_breaks_the_signature() {
        let (_did, rep, decision) = setup();
        let issuer = AttestationIssuer::new("did:web:byzantium", DilithiumKeypair::generate());
        let mut att = issuer
            .issue(&decision, &rep, "sha256:prn", "sha256:mandate", 3600)
            .unwrap();

        att.lim_window = Money::usd_cents(att.lim_window.minor_units * 1_000);
        assert!(
            AttestationIssuer::verify(&att, issuer.public_key()).is_err(),
            "an inflated limit still verified"
        );
    }

    #[test]
    fn a_different_issuer_key_does_not_verify() {
        let (_did, rep, decision) = setup();
        let issuer = AttestationIssuer::new("did:web:byzantium", DilithiumKeypair::generate());
        let att = issuer
            .issue(&decision, &rep, "sha256:prn", "sha256:mandate", 3600)
            .unwrap();
        let impostor = DilithiumKeypair::generate();
        assert!(AttestationIssuer::verify(&att, &impostor.public_key).is_err());
    }

    #[test]
    fn expired_attestation_is_rejected() {
        let (_did, rep, decision) = setup();
        let issuer = AttestationIssuer::new("did:web:byzantium", DilithiumKeypair::generate());
        // Zero TTL: signed correctly, but already outside its validity window.
        let att = issuer
            .issue(&decision, &rep, "sha256:prn", "sha256:m", 0)
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(AttestationIssuer::verify(&att, issuer.public_key()).is_err());
    }

    #[test]
    fn refused_decision_cannot_be_issued() {
        let (did, rep, _) = setup();
        let refused = Underwriter::default().underwrite(&UnderwritingInput {
            agent_did: did.clone(),
            reputation: rep.clone(),
            standing: PrincipalStanding::unverified("sha256:prn"),
            exposure: ExposureSnapshot::empty(did, Currency::Usd),
            previous: None,
            ccy: Currency::Usd,
            scope: LimitScope::any(),
        });
        let issuer = AttestationIssuer::new("did:web:byzantium", DilithiumKeypair::generate());
        assert!(issuer
            .issue(&refused, &rep, "sha256:prn", "m", 3600)
            .is_err());
    }

    #[test]
    fn evidence_hash_is_deterministic_and_input_sensitive() {
        let (_did, rep, decision) = setup();
        let h1 = AttestationIssuer::evidence_hash(&rep, &decision.reasons);
        let h2 = AttestationIssuer::evidence_hash(&rep, &decision.reasons);
        assert_eq!(h1, h2);

        let mut altered = rep.clone();
        altered.score += 1;
        assert_ne!(
            h1,
            AttestationIssuer::evidence_hash(&altered, &decision.reasons)
        );
    }

    #[test]
    fn reissue_after_growth_is_rate_limited_end_to_end() {
        let (did, rep, first) = setup();
        let issuer = AttestationIssuer::new("did:web:byzantium", DilithiumKeypair::generate());
        let att1 = issuer.issue(&first, &rep, "sha256:prn", "m", 3600).unwrap();

        // Same agent, far more history, but the previous limit bounds the step.
        let mut svc = ReputationService::new(400);
        svc.bind_principal(&did, "sha256:prn");
        let now = Utc::now();
        for i in 0..300 {
            svc.ingest(
                ScoringEvent::new(did.clone(), ReceiptOutcome::Success, false)
                    .with_amount(Money::usd_cents(5_000_000))
                    .with_counterparty(format!("cp-{}", i % 60))
                    .at(now - Duration::hours(i)),
            );
        }
        let rep2 = svc.detail(&did);
        let second = Underwriter::default().underwrite(&UnderwritingInput {
            agent_did: did.clone(),
            reputation: rep2.clone(),
            standing: PrincipalStanding {
                principal_ref: "sha256:prn".to_string(),
                kyc_tier: KycTier::Institutional,
                sanctions_clear: true,
                jurisdiction: "SG".to_string(),
                entity_age_days: 900,
                agent_count: 1,
            },
            exposure: ExposureSnapshot::empty(did.clone(), Currency::Usd),
            previous: Some(PreviousLimit {
                lim_window: att1.lim_window,
                issued_at: att1.nbf,
            }),
            ccy: Currency::Usd,
            scope: LimitScope::any(),
        });

        let ceiling = att1.lim_window.minor_units as f64 * 1.5 + 50_000.0;
        assert!(
            second.lim_window.minor_units as f64 <= ceiling,
            "reissue jumped from {} to {}",
            att1.lim_window.minor_units,
            second.lim_window.minor_units
        );
    }
}
