-- Rollback for migration 004.
DROP TABLE IF EXISTS revocation_cutoffs;
DROP TABLE IF EXISTS provenance_events;
DROP TABLE IF EXISTS provenance_runtimes;
DROP TABLE IF EXISTS agent_exposure;
DROP TABLE IF EXISTS issued_limits;
DROP TABLE IF EXISTS principal_standings;
