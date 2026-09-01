use byz_billing::{StripeClient, UsageMeter};
use byz_common::config::Config;
use byz_common::{FxTable, PrincipalStanding};
use byz_crypto::DilithiumKeypair;
use byz_identity::did::DidResolver;
use byz_mandate::engine::{MandateEngine, MandateStore};
use byz_provenance::{RuntimeRegistry, SignedProvenance};
use byz_receipt::batch::ReceiptBatcher;
use byz_reputation::scorer::ReputationService;
use byz_underwrite::{
    AttestationIssuer, PreviousLimit, RevocationRegistry, Underwriter, UnderwritingConfig,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::circuit_breaker::CircuitBreaker;
use crate::metrics::Metrics;
use crate::middleware::rate_limit::RateLimiter;
use crate::tee_client::TeeClient;
use crate::webhooks::WebhookDispatcher;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub gateway_keypair: Arc<DilithiumKeypair>,
    pub mandate_engine: Arc<RwLock<MandateEngine>>,
    pub reputation: Arc<RwLock<ReputationService>>,
    pub batcher: Arc<RwLock<ReceiptBatcher>>,
    pub did_resolver: Arc<RwLock<DidResolver>>,
    pub metrics: Metrics,
    pub rate_limiter: Arc<RateLimiter>,
    /// Persistent store — None in dev/in-memory mode
    pub store: Option<Arc<byz_store::Store>>,
    /// TEE enclave client — Some only when BYZ_TEE_ENABLED=true
    pub tee: Option<Arc<TeeClient>>,
    /// Webhook dispatcher for trust verdict events
    pub webhooks: WebhookDispatcher,
    /// Circuit breakers for external service calls
    pub cb_zkme: CircuitBreaker,
    pub cb_bitcoin: CircuitBreaker,
    pub cb_solana: CircuitBreaker,
    pub cb_base_rpc: CircuitBreaker,
    /// Usage meter for Stripe metered billing
    pub usage_meter: Arc<UsageMeter>,

    // ── Underwriting ─────────────────────────────────────────────────────────
    /// Turns behavioral history into a limit.
    pub underwriter: Arc<Underwriter>,
    /// Signs limit attestations.
    pub issuer: Arc<AttestationIssuer>,
    /// KYC standing per agent DID. Underwriting is gated on this.
    pub standings: Arc<RwLock<HashMap<String, PrincipalStanding>>>,
    /// Last limit issued per agent, so growth can be rate-capped.
    pub last_limits: Arc<RwLock<HashMap<String, PreviousLimit>>>,
    /// FX rates applied at presentation rather than at issuance.
    pub fx: Arc<FxTable>,

    // ── Provenance ───────────────────────────────────────────────────────────
    /// Trusted runtime signing keys.
    pub runtimes: Arc<RwLock<RuntimeRegistry>>,
    /// Accepted runtime-signed events per agent DID.
    pub provenance: Arc<RwLock<HashMap<String, Vec<SignedProvenance>>>>,
    /// Count of events rejected per agent, for the acceptance rate.
    pub provenance_rejected: Arc<RwLock<HashMap<String, usize>>>,
    /// Latest evidence commitment per agent.
    pub evidence_refs: Arc<RwLock<HashMap<String, String>>>,
    /// Early-kill cutoffs for outstanding attestations. Short TTLs mean the
    /// normal way to withdraw a limit is to stop reissuing it; this covers the
    /// compromised-agent case where waiting for expiry is too slow.
    pub revocations: Arc<RwLock<RevocationRegistry>>,
}

impl AppState {
    pub fn new(config: Config) -> Self {
        let threshold = config.reputation.default_threshold;
        let rate_limit = config.gateway.rate_limit_per_min;
        let gateway_keypair = DilithiumKeypair::generate();
        // The issuer signs with the gateway key, so a relying party that already
        // trusts this gateway's PassTokens can verify attestations with the same
        // key rather than establishing a second trust root.
        let issuer = AttestationIssuer::new("did:web:byzantium", gateway_keypair.clone());
        Self {
            config: Arc::new(config),
            gateway_keypair: Arc::new(gateway_keypair),
            mandate_engine: Arc::new(RwLock::new(MandateEngine::new(MandateStore::new()))),
            reputation: Arc::new(RwLock::new(ReputationService::new(threshold))),
            batcher: Arc::new(RwLock::new(ReceiptBatcher::new(100))),
            did_resolver: Arc::new(RwLock::new(DidResolver::new())),
            metrics: Metrics::default(),
            rate_limiter: Arc::new(RateLimiter::new(rate_limit)),
            store: None,
            tee: None,
            webhooks: WebhookDispatcher::from_env(),
            cb_zkme: CircuitBreaker::new("zkme", 5, 60),
            cb_bitcoin: CircuitBreaker::new("bitcoin-rpc", 3, 120),
            cb_solana: CircuitBreaker::new("solana-rpc", 5, 60),
            cb_base_rpc: CircuitBreaker::new("base-rpc", 5, 60),
            usage_meter: Arc::new(UsageMeter::new(StripeClient::from_env())),
            underwriter: Arc::new(Underwriter::new(UnderwritingConfig::default())),
            issuer: Arc::new(issuer),
            standings: Arc::new(RwLock::new(HashMap::new())),
            last_limits: Arc::new(RwLock::new(HashMap::new())),
            fx: Arc::new(FxTable::default()),
            runtimes: Arc::new(RwLock::new(RuntimeRegistry::new())),
            provenance: Arc::new(RwLock::new(HashMap::new())),
            provenance_rejected: Arc::new(RwLock::new(HashMap::new())),
            evidence_refs: Arc::new(RwLock::new(HashMap::new())),
            revocations: Arc::new(RwLock::new(RevocationRegistry::new())),
        }
    }

    pub fn with_store(mut self, store: byz_store::Store) -> Self {
        self.store = Some(Arc::new(store));
        self
    }

    pub fn with_tee(mut self, tee: TeeClient) -> Self {
        self.tee = Some(Arc::new(tee));
        self
    }
}
