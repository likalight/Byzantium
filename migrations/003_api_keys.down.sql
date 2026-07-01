-- Reverse of 003_api_keys.sql
-- Drops the new operator-managed api_keys table introduced in this migration.
-- Note: the original api_keys table from 001_initial.sql is NOT restored here;
-- rolling back to 001 state requires running 001_initial.down.sql first.

DROP INDEX IF EXISTS idx_api_keys_hash;
DROP INDEX IF EXISTS idx_api_keys_operator;
DROP TABLE IF EXISTS api_keys;
