# Changelog

All notable changes to Byzantium are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html)

## [Unreleased]

## [0.1.0] - 2026-07-01

### Added
- Gateway trust-check endpoint (`POST /v1/trust-check`) returning PASS / FLAG / BLOCK with a short-lived ML-DSA-signed `PassToken` in under 200 ms
- Spend mandate system: register, fetch, and revoke per-agent mandates with per-tx caps, daily caps, allowed action types, and counterparty whitelists (`POST /v1/mandates`, `GET /v1/mandates/:id`, `POST /v1/mandates/:id/revoke`)
- Liability receipt pipeline: submit receipts, batch them, seal batches with a Merkle root anchored into ImmuDB, and retrieve Merkle inclusion proofs (`POST /v1/receipts`, `GET /v1/receipts/:id/proof`, `POST /v1/batches/:id/seal`)
- EIP-3009 payment rail: verify `transferWithAuthorization` signed messages against Base L2 via JSON-RPC — validates time bounds, recovers signer, checks on-chain nonce state, and runs a Byzantium trust-check on the sender DID (`POST /v1/payments/eip3009/verify`)
- Solana SPL payment rail: verify finalized SPL token transfers — fetches from Solana JSON-RPC at confirmed commitment, asserts from/to/amount/mint, and runs a trust-check on `did:sol:<base58-pubkey>` (`POST /v1/payments/solana/verify`)
- Bitcoin anchor stub (`byz-rail-x402`) and agent-to-agent delegation rail (`byz-rail-a2a`) crates scaffolded in the workspace
- ImmuDB tamper-evident audit log integration: Merkle-batch anchoring of liability receipts with cryptographic inclusion proofs (`byz-anchor` crate)
- Neo4j reputation graph: behavioral scoring pipeline producing a 0–1000 composite trust score per agent DID, queried on every trust-check (`byz-reputation` crate)
- zkMe zero-knowledge KYC integration: verify agent identity credentials without revealing underlying PII (`POST /v1/agents` registration flow)
- TEE mode via Gramine SGX: mandate engine and reputation scorer run as separate SGX sidecar processes; signing keys generated inside the enclave and never cross the boundary; MRENCLAVE pinning enforced by the gateway (`BYZ_TEE_ENABLED`, `--profile tee`)
- SP1 zkVM (Succinct) proofs: credential-disclosure proof (attribute predicate without revealing value) and reputation-threshold proof (score above threshold without revealing raw score); proofs cached in Redis and refreshed in the background (`byz-proof` crate, `SP1_PROVER` env var)
- DID-based agent identity: register, fetch, and deactivate agent DIDs; optional zkMe KYC association (`POST /v1/agents`, `GET /v1/agents/:did`, `POST /v1/agents/:did/deactivate`)
- API key management: create, list, and revoke Bearer API keys per operator (`POST /v1/keys`, `GET /v1/keys`, `DELETE /v1/keys/:id`)
- Audit endpoints: list liability receipts with agent/timestamp filters and retrieve full Merkle proofs for sealed batches (`GET /v1/audit/receipts`, `GET /v1/audit/batches/:id`)
- TypeScript SDK (`sdk/typescript`, npm package `@byzantium/agent-sdk`): `ByzantiumClient` with `requirePass`, `trustCheck`, mandate, receipt, agent, and audit helpers; typed error classes `ByzantiumTrustError`, `ByzantiumApiError`, `ByzantiumRateLimitError`
- Rust SDK (`crates/byz-sdk`): async `ByzantiumClient` over `reqwest`; `require_pass` returns a `PassToken` or `SdkError::TrustBlocked`; `byz-common` shared types (`AgentDid`, `ActionType`, `TrustCheckRequest`)
- OpenAPI specification auto-generated from Axum routes
- Prometheus metrics exported at `GET /metrics` (text exposition format); pre-built Grafana dashboard provisioned via docker-compose
- OpenTelemetry tracing via OTLP/gRPC; Jaeger all-in-one bundled under the `observability` compose profile
- Alertmanager integration with pre-built alert rules (`monitoring/alerts.yml`) and configurable webhook + token for Slack/PagerDuty notifications
- Docker Compose stack covering all backing services: PostgreSQL 16, Redis 7, Neo4j 5 Community (with APOC), ImmuDB, Prometheus, Grafana, Jaeger, Alertmanager
- Kubernetes manifests in `deploy/k8s/` targeting the `byzantium` namespace: 3-replica Deployment with zero-downtime rolling updates, topology spread constraints, non-root UID 10001, read-only root filesystem, all capabilities dropped
- Database migrations managed via `sqlx-cli`; offline query cache (`.sqlx/`) enables `SQLX_OFFLINE` CI builds
- `Makefile` with targets for build, check, test, lint, fmt, migrate, docker-build/push/run, k8s-apply/rollout/restart, gramine-build, zk-build/setup, sqlx-prepare, seed, and help

[Unreleased]: https://github.com/byzantium/gateway/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/byzantium/gateway/releases/tag/v0.1.0
