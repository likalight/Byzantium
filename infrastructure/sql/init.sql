-- Byzantium PostgreSQL schema
-- Operational data (not proof storage — that lives in immudb + Redis)

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Agent DID registry (mirrored from immudb for fast lookups)
CREATE TABLE IF NOT EXISTS agents (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    did           TEXT UNIQUE NOT NULL,
    operator_id   TEXT NOT NULL,
    public_key_hex TEXT NOT NULL,
    kyb_verified  BOOLEAN NOT NULL DEFAULT FALSE,
    active        BOOLEAN NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Spend mandates
CREATE TABLE IF NOT EXISTS mandates (
    id                  UUID PRIMARY KEY,
    agent_did           TEXT NOT NULL REFERENCES agents(did),
    operator_id         TEXT NOT NULL,
    per_tx_cap_cents    BIGINT NOT NULL,
    daily_cap_cents     BIGINT NOT NULL,
    mandate_root        TEXT,
    valid_from          TIMESTAMPTZ NOT NULL,
    valid_until         TIMESTAMPTZ NOT NULL,
    revoked_at          TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS mandates_agent_did_idx ON mandates (agent_did);
CREATE INDEX IF NOT EXISTS mandates_active_idx ON mandates (agent_did, valid_until) WHERE revoked_at IS NULL;

-- Receipt batches (roots anchored in immudb; full receipts in immudb)
CREATE TABLE IF NOT EXISTS receipt_batches (
    id              UUID PRIMARY KEY,
    merkle_root     TEXT NOT NULL,
    receipt_count   INT NOT NULL,
    immudb_tx_id    BIGINT,
    bitcoin_txid    TEXT,
    sealed_at       TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Receipt index (for proof lookups; full receipt bodies in immudb)
CREATE TABLE IF NOT EXISTS receipts (
    id              UUID PRIMARY KEY,
    agent_did       TEXT NOT NULL,
    mandate_id      UUID NOT NULL,
    batch_id        UUID REFERENCES receipt_batches(id),
    leaf_hash       TEXT NOT NULL,
    rail_id         TEXT NOT NULL,
    amount_cents    BIGINT,
    outcome         TEXT NOT NULL,
    timestamp       TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS receipts_agent_idx ON receipts (agent_did, timestamp DESC);
CREATE INDEX IF NOT EXISTS receipts_batch_idx ON receipts (batch_id);

-- Trust check audit log (sampled; not every check — hot path must not write)
CREATE TABLE IF NOT EXISTS trust_check_log (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    request_id      UUID NOT NULL,
    agent_did       TEXT NOT NULL,
    rail_id         TEXT NOT NULL,
    verdict         TEXT NOT NULL,
    latency_ms      INT,
    checked_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS trust_log_agent_idx ON trust_check_log (agent_did, checked_at DESC);
