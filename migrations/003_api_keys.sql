-- Migration 003: Operator API key management
-- Replaces the minimal rail api_keys table from 001 with a full operator key management table.

-- Drop the old minimal table (it only had key_hash as PK with no UUID)
DROP TABLE IF EXISTS api_keys;

CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_hash TEXT NOT NULL UNIQUE,  -- SHA-256 hex of the raw key
    label TEXT NOT NULL,
    operator_id TEXT NOT NULL,
    scopes TEXT[] NOT NULL DEFAULT '{}',  -- e.g. '{trust,audit,admin}'
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_api_keys_operator ON api_keys(operator_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
