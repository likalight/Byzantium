-- Reputation scores and proof cache

CREATE TABLE IF NOT EXISTS reputation_scores (
    agent_did           TEXT        PRIMARY KEY,
    score               INT         NOT NULL DEFAULT 500,
    compliance_rate     FLOAT8      NOT NULL DEFAULT 1.0,
    violation_rate      FLOAT8      NOT NULL DEFAULT 0.0,
    total_actions       BIGINT      NOT NULL DEFAULT 0,
    commitment_hex      TEXT,
    commitment_nonce    TEXT,
    computed_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT score_range CHECK (score BETWEEN 0 AND 1000)
);

-- ZK threshold proof cache (also in Redis; this is the durable fallback)
CREATE TABLE IF NOT EXISTS proof_cache (
    agent_did           TEXT        PRIMARY KEY,
    proof_bytes         BYTEA       NOT NULL,
    threshold           INT         NOT NULL,
    commitment_hex      TEXT        NOT NULL,
    generated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at          TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_proof_cache_expires ON proof_cache (expires_at);
