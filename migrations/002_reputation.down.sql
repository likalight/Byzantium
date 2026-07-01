-- Reverse of 002_reputation.sql

DROP INDEX IF EXISTS idx_proof_cache_expires;
DROP TABLE IF EXISTS proof_cache;

DROP TABLE IF EXISTS reputation_scores;
