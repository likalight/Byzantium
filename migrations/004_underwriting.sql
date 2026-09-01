-- Migration 004: Underwriting, exposure, provenance, revocation.
--
-- Everything the limits layer holds in memory needs a home that survives a
-- restart. Exposure especially: a limits system whose spend window resets to
-- zero when the process restarts hands out the same capacity twice.

-- ── Principal standing ───────────────────────────────────────────────────────
-- The KYC gate. Limits consolidate at the principal, so this is also what makes
-- splitting one agent into ten divide the limit instead of multiplying it.
CREATE TABLE IF NOT EXISTS principal_standings (
    agent_did TEXT PRIMARY KEY,
    principal_ref TEXT NOT NULL,
    kyc_tier TEXT NOT NULL,           -- unverified | basic | verified | institutional
    sanctions_clear BOOLEAN NOT NULL DEFAULT FALSE,
    jurisdiction TEXT NOT NULL DEFAULT '',
    entity_age_days INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_standings_principal ON principal_standings(principal_ref);

-- ── Issued limits ────────────────────────────────────────────────────────────
-- Retained so growth can be rate-capped across restarts. Without the previous
-- limit, every restart lets an agent step straight to whatever its score allows.
CREATE TABLE IF NOT EXISTS issued_limits (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_did TEXT NOT NULL,
    principal_ref TEXT NOT NULL,
    tier TEXT NOT NULL,
    ccy TEXT NOT NULL,
    lim_single_minor BIGINT NOT NULL,
    lim_window_minor BIGINT NOT NULL,
    window_secs BIGINT NOT NULL,
    fee_bps INTEGER NOT NULL,
    collateral_bps INTEGER NOT NULL,
    collateral_required_minor BIGINT NOT NULL DEFAULT 0,
    liability_model TEXT NOT NULL DEFAULT 'bureau',
    guarantor TEXT NOT NULL DEFAULT '',
    guarantee_covered_minor BIGINT NOT NULL DEFAULT 0,
    evidence_ref TEXT NOT NULL,
    mandate_hash TEXT NOT NULL,
    -- The full decision trail, so an adverse outcome stays explainable after the
    -- fact rather than only at the moment it was made.
    reasons JSONB NOT NULL DEFAULT '[]'::jsonb,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_issued_limits_agent ON issued_limits(agent_did, issued_at DESC);
CREATE INDEX IF NOT EXISTS idx_issued_limits_principal ON issued_limits(principal_ref);

-- ── Exposure ─────────────────────────────────────────────────────────────────
-- `at_risk` is committed-but-unresolved; `window_used` is settled inside the
-- current window. They are tracked separately because they answer different
-- questions, and because an unresolved commitment must not age out with the
-- window the way settled value does.
CREATE TABLE IF NOT EXISTS agent_exposure (
    agent_did TEXT PRIMARY KEY,
    ccy TEXT NOT NULL,
    at_risk_minor BIGINT NOT NULL DEFAULT 0,
    window_used_minor BIGINT NOT NULL DEFAULT 0,
    window_start TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    open_draws INTEGER NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Runtime keys ─────────────────────────────────────────────────────────────
-- The trust root for execution provenance. Revoked keys are kept rather than
-- deleted so evidence accepted while they were live stays explainable.
CREATE TABLE IF NOT EXISTS provenance_runtimes (
    runtime_id TEXT PRIMARY KEY,
    public_key_hex TEXT NOT NULL,
    registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ
);

-- ── Provenance events ────────────────────────────────────────────────────────
-- Only the hash of a payload is ever stored. Agent traces are commercially
-- sensitive and frequently the operator's own IP; holding the contents would
-- make this table an exfiltration target and the integration a non-starter.
CREATE TABLE IF NOT EXISTS provenance_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_did TEXT NOT NULL,
    session_id UUID NOT NULL,
    seq BIGINT NOT NULL,
    kind TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    label TEXT,
    ok BOOLEAN NOT NULL DEFAULT TRUE,
    runtime_id TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Replay defence at the storage layer as well as in the verifier.
    UNIQUE (agent_did, session_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_provenance_agent ON provenance_events(agent_did, occurred_at DESC);

-- ── Revocation cutoffs ───────────────────────────────────────────────────────
-- A cutoff rather than a list of credential ids: everything issued to this
-- subject before this instant is dead. O(1) to store and check, and it cannot
-- grow without bound the way a per-credential list does.
CREATE TABLE IF NOT EXISTS revocation_cutoffs (
    subject TEXT NOT NULL,
    subject_kind TEXT NOT NULL,       -- agent | principal
    effective_from TIMESTAMPTZ NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (subject, subject_kind)
);
