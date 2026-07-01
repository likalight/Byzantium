-- Byzantium initial schema
-- Run with: sqlx migrate run

-- Agent DID registry
CREATE TABLE IF NOT EXISTS agents (
    did             TEXT        PRIMARY KEY,
    operator_id     TEXT        NOT NULL,
    public_key_hex  TEXT        NOT NULL,
    kyb_status      TEXT        NOT NULL DEFAULT 'pending',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deactivated_at  TIMESTAMPTZ,
    metadata        JSONB       NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_agents_operator ON agents (operator_id);

-- Spend mandates
CREATE TABLE IF NOT EXISTS mandates (
    id                      UUID        PRIMARY KEY,
    agent_did               TEXT        NOT NULL REFERENCES agents(did),
    operator_id             TEXT        NOT NULL,
    per_tx_cap_cents        BIGINT      NOT NULL,
    daily_cap_cents         BIGINT      NOT NULL,
    allowed_action_types    JSONB       NOT NULL DEFAULT '[]',
    counterparty_whitelist  JSONB       NOT NULL DEFAULT '[]',
    valid_from              TIMESTAMPTZ NOT NULL,
    valid_until             TIMESTAMPTZ NOT NULL,
    mandate_root            TEXT,
    signature               BYTEA,
    operator_pubkey         TEXT,
    revoked_at              TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mandates_agent    ON mandates (agent_did);
CREATE INDEX IF NOT EXISTS idx_mandates_operator ON mandates (operator_id);
CREATE INDEX IF NOT EXISTS idx_mandates_active   ON mandates (agent_did, valid_until)
    WHERE revoked_at IS NULL;

-- Daily spend tracking (rolling 24h windows)
CREATE TABLE IF NOT EXISTS daily_spend (
    agent_did       TEXT        NOT NULL,
    window_start    TIMESTAMPTZ NOT NULL,
    cents_spent     BIGINT      NOT NULL DEFAULT 0,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (agent_did, window_start)
);

-- Liability receipts
CREATE TABLE IF NOT EXISTS receipts (
    id              UUID        PRIMARY KEY,
    agent_did       TEXT        NOT NULL REFERENCES agents(did),
    action_type     TEXT        NOT NULL,
    counterparty    JSONB,
    amount_cents    BIGINT,
    outcome         TEXT        NOT NULL,
    mandate_id      UUID        NOT NULL REFERENCES mandates(id),
    rail_id         TEXT        NOT NULL,
    batch_id        UUID,
    batch_index     INT,
    signature       BYTEA,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_receipts_agent     ON receipts (agent_did, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_receipts_mandate   ON receipts (mandate_id);
CREATE INDEX IF NOT EXISTS idx_receipts_batch     ON receipts (batch_id);
CREATE INDEX IF NOT EXISTS idx_receipts_rail      ON receipts (rail_id);

-- Receipt batches (Merkle-sealed)
CREATE TABLE IF NOT EXISTS receipt_batches (
    id              UUID        PRIMARY KEY,
    merkle_root     TEXT        NOT NULL,
    receipt_count   INT         NOT NULL,
    sealed_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    immudb_tx_id    BIGINT,
    bitcoin_txid    TEXT,
    anchored_at     TIMESTAMPTZ
);

-- Rail API keys
CREATE TABLE IF NOT EXISTS api_keys (
    key_hash        TEXT        PRIMARY KEY,  -- SHA-256(key), never store plaintext
    rail_id         TEXT        NOT NULL,
    operator_id     TEXT        NOT NULL,
    scopes          JSONB       NOT NULL DEFAULT '["trust_check"]',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_api_keys_operator ON api_keys (operator_id);
