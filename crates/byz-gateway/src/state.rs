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
use crate::idempotency::IdempotencyCache;
use crate::keystore::IssuerKeystore;
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
    /// The issuer signing key and the retired keys still accepted for
    /// verification. Published at `/v1/issuer-keys` so relying parties can
    /// check a credential without a prior key exchange.
    pub keystore: Arc<RwLock<IssuerKeystore>>,
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
    /// Replayed authorisations and settlements return their original response.
    /// Without this a client retry commits the same exposure twice.
    pub idempotency: Arc<RwLock<IdempotencyCache>>,
}

impl AppState {
    pub fn new(config: Config) -> Self {
        let threshold = config.reputation.default_threshold;
        let rate_limit = config.gateway.rate_limit_per_min;
        // Load the signing key rather than generating one. A key that does not
        // survive a restart takes every credential it ever signed with it.
        let keystore = match config.gateway.signing_key_path {
            Some(ref path) => match IssuerKeystore::load_or_create(path) {
                Ok(ks) => {
                    tracing::info!(kid = %ks.active_kid(), path = %path, "issuer signing key loaded");
                    ks
                }
                Err(e) => {
                    // Refusing to start is the right behaviour here, but AppState
                    // has no way to report it, so make the failure impossible to
                    // miss and fall back to ephemeral.
                    tracing::error!(error = %e, "could not load the issuer signing key");
                    panic!("issuer signing key at {path} could not be loaded: {e}");
                }
            },
            None => {
                tracing::warn!(
                    "BYZ_SIGNING_KEY_PATH is not set — generating an ephemeral issuer key. \
                     Every credential signed by this process becomes unverifiable when it \
                     restarts. Do not run this way outside local development."
                );
                IssuerKeystore::ephemeral()
            }
        };
        let gateway_keypair = keystore.active().clone();
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
            keystore: Arc::new(RwLock::new(keystore)),
            standings: Arc::new(RwLock::new(HashMap::new())),
            last_limits: Arc::new(RwLock::new(HashMap::new())),
            fx: Arc::new(FxTable::default()),
            runtimes: Arc::new(RwLock::new(RuntimeRegistry::new())),
            provenance: Arc::new(RwLock::new(HashMap::new())),
            provenance_rejected: Arc::new(RwLock::new(HashMap::new())),
            evidence_refs: Arc::new(RwLock::new(HashMap::new())),
            revocations: Arc::new(RwLock::new(RevocationRegistry::new())),
            idempotency: Arc::new(RwLock::new(IdempotencyCache::new())),
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
