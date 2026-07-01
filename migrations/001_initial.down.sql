-- Reverse of 001_initial.sql
-- Drop in reverse dependency order (dependents before dependencies)

DROP INDEX IF EXISTS idx_api_keys_operator;
DROP TABLE IF EXISTS api_keys;

DROP INDEX IF EXISTS idx_receipts_rail;
DROP INDEX IF EXISTS idx_receipts_batch;
DROP INDEX IF EXISTS idx_receipts_mandate;
DROP INDEX IF EXISTS idx_receipts_agent;
DROP TABLE IF EXISTS receipts;

DROP TABLE IF EXISTS receipt_batches;

DROP TABLE IF EXISTS daily_spend;

DROP INDEX IF EXISTS idx_mandates_active;
DROP INDEX IF EXISTS idx_mandates_operator;
DROP INDEX IF EXISTS idx_mandates_agent;
DROP TABLE IF EXISTS mandates;

DROP INDEX IF EXISTS idx_agents_operator;
DROP TABLE IF EXISTS agents;
