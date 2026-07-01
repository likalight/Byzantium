# Byzantium

**AI agent trust verification layer.** Operators define spend mandates — per-transaction caps, allowed action types, counterparty whitelists, and daily limits. Before any agentic action (payment, API call, contract execution, cross-agent delegation) proceeds, the agent calls Byzantium. The gateway verifies payment rails (EIP-3009 on Base/USDC, Solana SPL), identity (DID resolution, zkMe KYC), and behavioral reputation (Neo4j graph, 0–1000 composite score) in under 200 ms and returns **PASS**, **FLAG**, or **BLOCK** together with a short-lived ML-DSA-signed `PassToken` that the downstream rail can verify in microseconds.

---

## Architecture

```
                     ┌────────────────────────────────────────────────────────┐
                     │                   Agent (any runtime)                  │
                     └─────────────────────────┬──────────────────────────────┘
                                               │  POST /v1/trust-check
                                               ▼
                     ┌────────────────────────────────────────────────────────┐
                     │               byz-gateway  (Axum, port 8080)           │
                     │  auth middleware → rate limiter → trust orchestrator   │
                     └──────┬───────────────┬────────────────┬────────────────┘
                            │               │                │
               ┌────────────▼───┐   ┌───────▼──────┐  ┌────▼────────────────┐
               │ Mandate Engine │   │ Reputation   │  │  Payment Rails      │
               │  (byz-mandate) │   │    Graph     │  │  byz-rail-eip3009   │
               │  [TEE sidecar] │   │  (Neo4j)     │  │  byz-rail-solana    │
               │  ML-DSA signed │   │  STARK proof │  │  byz-rail-x402      │
               └────────────────┘   └──────────────┘  └─────────────────────┘
                            │               │                │
                            └───────────────▼────────────────┘
                                           │  PASS + PassToken
                                           ▼
                     ┌────────────────────────────────────────────────────────┐
                     │           LiabilityReceipt → byz-anchor                │
                     │     Merkle batch → ImmuDB (tamper-evident log)         │
                     └────────────────────────────────────────────────────────┘
```

---

## Quick start

**Prerequisites:** Docker, Docker Compose.

```bash
cp .env.example .env
# Edit .env — at minimum set BYZ_API_KEYS, DATABASE_URL password, and NEO4J_PASSWORD
docker compose up -d
curl http://localhost:8080/health
# {"status":"ok","service":"byzantium-gateway","version":"..."}
```

Migrations run automatically in the `migrate` service before the gateway starts.

To enable TEE sidecars (requires Intel SGX hardware):

```bash
docker compose --profile tee up -d
```

---

## Configuration

All configuration is read from environment variables. Copy `.env.example` to `.env` for local development; in production inject via Kubernetes Secrets, AWS Secrets Manager, or HashiCorp Vault.

| Variable | Required | Default | Description |
|---|---|---|---|
| `BYZ_API_KEYS` | Yes | — | Comma-separated Bearer API keys. Generate with `openssl rand -hex 32`. |
| `DATABASE_URL` | Yes | — | PostgreSQL connection string (`postgres://user:pass@host:5432/db`). |
| `REDIS_URL` | Yes | `redis://localhost:6379` | Redis URL. Use `rediss://` for TLS in production. |
| `NEO4J_URI` | Yes | `bolt://localhost:7687` | Neo4j Bolt URI for the trust graph. |
| `NEO4J_USERNAME` | Yes | `neo4j` | Neo4j username. |
| `NEO4J_PASSWORD` | Yes | — | Neo4j password. |
| `IMMUDB_HOST` | Yes | `localhost` | Hostname of the ImmuDB tamper-evident log. |
| `IMMUDB_USERNAME` | Yes | `immudb` | ImmuDB username. |
| `IMMUDB_PASSWORD` | Yes | — | ImmuDB password. |
| `IMMUDB_DATABASE` | No | `byzantium` | Logical database name within ImmuDB. |
| `BASE_RPC_URL` | Yes* | `https://mainnet.base.org` | Base L2 JSON-RPC endpoint for EIP-3009 verification. |
| `ZKME_API_KEY` | Yes* | — | zkMe API key for zero-knowledge KYC checks. |
| `ZKME_API_URL` | No | `https://api.zkme.io` | zkMe API base URL. |
| `SP1_PROVER` | No | `local` | SP1 prover mode: `local`, `network`, or `mock`. |
| `SP1_PRIVATE_KEY` | Yes* | — | Ed25519 key for Succinct prover network (only when `SP1_PROVER=network`). |
| `BYZ_TEE_ENABLED` | No | `false` | Enable TEE-backed mandate and reputation sidecars. |
| `MANDATE_ENGINE_PORT` | No | `50051` | gRPC port for the mandate TEE sidecar. |
| `REPUTATION_TEE_PORT` | No | `50052` | gRPC port for the reputation TEE sidecar. |
| `RATE_LIMIT_PER_MIN` | No | `600` | Max trust-check requests per minute per source IP. |
| `PROOF_REFRESH_SECS` | No | `60` | How often the background task refreshes the reputation proof cache. |
| `GATEWAY_HOST` | No | `0.0.0.0` | Bind interface for the HTTP gateway. |
| `GATEWAY_PORT` | No | `8080` | TCP port for the HTTP gateway. |
| `RUST_LOG` | No | `info` | `tracing-subscriber` filter (e.g. `byzantium=debug,tower_http=info`). |

\* Required for that feature set to function.

---

## API reference

All routes under `/v1/` require `Authorization: Bearer <api-key>`. Public routes (`/health`, `/metrics`) have no authentication.

### Trust

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/trust-check` | Core hot-path call. Evaluates mandate compliance, reputation, and payment rail eligibility. Returns `PASS`/`FLAG`/`BLOCK` and a signed `PassToken` on `PASS`. Guaranteed <200 ms. |

```bash
curl -X POST http://localhost:8080/v1/trust-check \
  -H "Authorization: Bearer $BYZ_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_did": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    "action_type": "payment",
    "amount_cents": 5000,
    "rail_id": "eip3009",
    "counterparty": { "id": "merchant-42" }
  }'
```

### Mandates

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/mandates` | Register a spend mandate for an agent DID. Defines per-tx cap, daily cap, allowed action types, and counterparty whitelist. |
| `GET` | `/v1/mandates/:id` | Fetch a mandate by UUID. |
| `POST` | `/v1/mandates/:id/revoke` | Immediately revoke a mandate, blocking all future trust checks under it. |

```bash
# Create a mandate
curl -X POST http://localhost:8080/v1/mandates \
  -H "Authorization: Bearer $BYZ_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_did": "did:key:z6Mk...",
    "operator_id": "acme-corp",
    "allowed_action_types": ["payment", "api_call"],
    "per_tx_cap_cents": 10000,
    "daily_cap_cents": 100000,
    "counterparty_whitelist": ["stripe-acct-123"],
    "valid_from": "2025-01-01T00:00:00Z",
    "valid_until": "2026-01-01T00:00:00Z"
  }'

# Revoke
curl -X POST http://localhost:8080/v1/mandates/<uuid>/revoke \
  -H "Authorization: Bearer $BYZ_API_KEY"
```

### Receipts

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/receipts` | Submit a liability receipt after an action completes. Receipts are batched and anchored into ImmuDB. |
| `GET` | `/v1/receipts/:id/proof` | Retrieve the Merkle inclusion proof for a receipt inside its sealed batch. |
| `POST` | `/v1/batches/:id/seal` | Seal a receipt batch and write the batch Merkle root to ImmuDB. |

```bash
curl -X POST http://localhost:8080/v1/receipts \
  -H "Authorization: Bearer $BYZ_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_did": "did:key:z6Mk...",
    "action_type": "payment",
    "amount_cents": 5000,
    "mandate_id": "<uuid>",
    "rail_id": "eip3009",
    "outcome": "success"
  }'
```

### Payments

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/payments/eip3009/verify` | Verify an EIP-3009 `transferWithAuthorization` signed message: checks time bounds, recovers signer, verifies the on-chain nonce state, then runs a Byzantium trust-check on the sender DID. |
| `POST` | `/v1/payments/solana/verify` | Verify a finalized Solana SPL token transfer: fetches the transaction from the Solana JSON-RPC, asserts `from`/`to`/`amount`/`mint`, and runs a trust-check on `did:sol:<base58-pubkey>`. |

```bash
curl -X POST http://localhost:8080/v1/payments/eip3009/verify \
  -H "Authorization: Bearer $BYZ_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "token": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    "from": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
    "to": "0x1234...",
    "value": 1000000,
    "valid_after": 0,
    "valid_before": 9999999999,
    "nonce": "0x000...001",
    "signature": "0xaabbcc..."
  }'
```

### Identity

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/agents` | Register an agent DID with Byzantium. Associates a DID with an operator and optional zkMe KYC status. |
| `GET` | `/v1/agents/:did` | Retrieve agent registration and current trust status. |
| `POST` | `/v1/agents/:did/deactivate` | Deactivate an agent, permanently blocking trust checks for that DID. |

```bash
curl -X POST http://localhost:8080/v1/agents \
  -H "Authorization: Bearer $BYZ_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_did": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    "operator_id": "acme-corp",
    "display_name": "Acme Payment Agent v2"
  }'
```

### Audit

| Method | Path | Description |
|---|---|---|
| `GET` | `/v1/audit/receipts` | List liability receipts with optional filters: `agent_did`, `limit`, `from`, `to` (ISO 8601 timestamps). |
| `GET` | `/v1/audit/batches/:id` | Retrieve the full Merkle inclusion proof for a sealed batch anchored in ImmuDB. |

```bash
curl "http://localhost:8080/v1/audit/receipts?agent_did=did:key:z6Mk...&limit=50" \
  -H "Authorization: Bearer $BYZ_API_KEY"
```

### Keys

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/keys` | Create a new API key. |
| `GET` | `/v1/keys` | List all active API keys for the operator. |
| `DELETE` | `/v1/keys/:id` | Revoke an API key by ID. |

```bash
curl -X POST http://localhost:8080/v1/keys \
  -H "Authorization: Bearer $BYZ_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{ "label": "prod-agent-key" }'
```

### Public

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Liveness check. Returns `{"status":"ok","service":"byzantium-gateway","version":"..."}`. |
| `GET` | `/metrics` | Prometheus metrics in text exposition format. |

---

## TypeScript SDK

Install from the `sdk/typescript` directory (or publish to npm as `@byzantium/agent-sdk`):

```typescript
import { ByzantiumClient } from '@byzantium/agent-sdk';

const byz = new ByzantiumClient({
  baseUrl: 'https://gateway.byzantium.ai',
  apiKey: process.env.BYZ_API_KEY!,
  timeoutMs: 5000, // optional, default 5000
});

// requirePass throws ByzantiumTrustError on FLAG or BLOCK
const token = await byz.requirePass({
  agent_did: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
  action_type: 'Payment',
  rail_id: 'eip3009',
  amount_cents: 5000,
});

// Attach token to your downstream payment rail request
console.log('PassToken valid until:', token.valid_until);
```

**Error types:**

- `ByzantiumTrustError` — verdict was `FLAG` or `BLOCK`; inspect `.verdict` and `.reason`
- `ByzantiumApiError` — non-2xx HTTP response from the gateway
- `ByzantiumRateLimitError` — 429; inspect `.retryAfterMs`

Other methods available on `ByzantiumClient`: `trustCheck`, `createMandate`, `getMandate`, `revokeMandate`, `createReceipt`, `getInclusionProof`, `registerAgent`, `getAgent`, `deactivateAgent`, `listAuditReceipts`, `health`.

---

## Rust SDK

Add to `Cargo.toml`:

```toml
[dependencies]
byz-sdk = { path = "crates/byz-sdk" }
```

```rust
use byz_sdk::client::{ByzantiumClient, CreateMandateRequest};
use byz_common::{AgentDid, ActionType, TrustCheckRequest};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = ByzantiumClient::new("http://localhost:8080", "byz_key_abc123");

    // Liveness check
    assert!(client.health().await?);

    // Trust-check — returns PassToken on PASS, SdkError::TrustBlocked on FLAG/BLOCK
    let req = TrustCheckRequest {
        agent_did: AgentDid::new("did:key:z6Mk..."),
        action_type: ActionType::Payment,
        amount_cents: Some(5000),
        counterparty: None,
        rail_id: "eip3009".to_string(),
        idempotency_key: None,
    };
    let token = client.require_pass(&req).await?;
    println!("mandate_hash: {}", token.mandate_hash);

    Ok(())
}
```

**Error types** (`byz_sdk::error::SdkError`):

- `TrustBlocked { verdict, request_id }` — agent did not pass
- `ApiError { status, message }` — non-2xx response
- `RateLimited { retry_after_ms }` — 429
- `NetworkError(String)` — transport failure

---

## Payment rails

### EIP-3009 (Base / USDC, gasless)

`POST /v1/payments/eip3009/verify` accepts a signed `transferWithAuthorization` message (EIP-3009 / EIP-712). The verifier runs a four-step pipeline:

1. **Time bounds** — rejects if `now >= valid_before` or `now <= valid_after`
2. **Signature recovery** — calls `personal_ecRecover` via JSON-RPC against `BASE_RPC_URL` and compares with the `from` address
3. **Nonce check** — calls `authorizationState(address,bytes32)` on the token contract to confirm the nonce has not been used on-chain
4. **Trust check** — runs the sender DID through the full Byzantium mandate + reputation pipeline

### Solana SPL

`POST /v1/payments/solana/verify` fetches a finalized transaction by signature, diffs pre/post token balances for the specified mint, and verifies amount/sender/receiver before running a trust check on `did:sol:<base58-pubkey>`.

### X402

`POST /v1/payments/x402/verify` verifies HTTP-native payment receipts issued by X402-compatible servers.

### Agent-to-Agent (A2A)

`POST /v1/a2a/check` verifies cross-agent delegation chains. An agent acting on behalf of another must carry a delegation proof signed by the originating agent; Byzantium validates the chain and checks that the delegating agent itself passes trust.

---

## Admin Dashboard

A visual operations console is included at `dashboard/`.

```bash
cd dashboard
cp .env.example .env        # set VITE_API_URL and VITE_API_KEY
npm install
npm run dev                 # opens at http://localhost:3000
```

Or build for production:
```bash
npm run build               # outputs to dashboard/dist/
# Serve dist/ with any static file server or behind nginx
```

**Dashboard pages:**

| Page | What you see |
|------|-------------|
| Overview | Live KPI cards, 24h trust check chart, verdict distribution, recent activity |
| Agents | All registered agents, reputation scores, status |
| Trust Log | Full audit log with PASS/FLAG/BLOCK filter |
| API Keys | Create and revoke operator keys |
| Billing | Monthly usage chart, Stripe connection status |
| Health | Live status of every service (PostgreSQL, Redis, Neo4j, immuDB, TEE) |

---

## Testing

```bash
# Unit + library tests
make test

# End-to-end tests (full in-memory stack, no DB needed)
make e2e

# Load test — proves P99 < 200ms SLO at 100 concurrent users
make load-test              # requires k6: https://k6.io/docs/get-started/installation/
```

---

## Deployment

### Docker Compose (single server / staging)

```bash
make docker-build
docker compose up -d
```

### Kubernetes (production)

```bash
# 1. Provision TLS certificate (Let's Encrypt)
make tls-setup DOMAIN=api.yourdomain.com EMAIL=you@company.com

# 2. Seal secrets (safe to commit)
make seal-secrets

# 3. Deploy
make k8s-deploy

# 4. Backups run automatically at 2am UTC → S3
#    To run a backup manually:
make backup-now
```

### Production checklist

- [ ] `BYZ_API_KEYS` set to cryptographically random strings (`openssl rand -hex 32`)
- [ ] `BYZ_METRICS_TOKEN` set to protect `/metrics` endpoint
- [ ] `STRIPE_SECRET_KEY` and `STRIPE_PRICE_ID` set for billing
- [ ] `BYZ_CORS_ORIGINS` set to your frontend domain(s)
- [ ] PostgreSQL on a managed service (RDS, Cloud SQL, Supabase)
- [ ] Redis Sentinel or Cluster for HA (`deploy/redis/docker-compose.redis-ha.yml`)
- [ ] S3 bucket created and `BACKUP_S3_BUCKET` set
- [ ] Alert runbooks reviewed: `docs/runbooks/`

---

## For Investors & Business Stakeholders

### The problem

AI agents are being deployed to move real money and access sensitive data autonomously. There is no standard infrastructure layer to verify that an agent is acting within the bounds its operator defined — or to prove compliance after the fact. Every enterprise deploying AI agents today has this problem and no good solution.

### The solution

Byzantium is the trust layer the AI agent economy is missing — analogous to what Stripe is to payments, or what Twilio was to communications. Operators integrate one API. Before any agent takes an action, it calls Byzantium. We return a verdict in under 200 milliseconds. Every decision is cryptographically signed with post-quantum keys and permanently written to Bitcoin — creating an immutable audit trail that satisfies regulators, insurers, and enterprise compliance teams.

### Why this moat is defensible

1. **Speed** — sub-200ms means Byzantium adds no perceptible latency to any AI transaction. Alternatives that run full KYC or on-chain verification take seconds.
2. **Immutability** — Bitcoin-anchored audit trails cannot be altered retroactively. This is a compliance guarantee no database-backed competitor can match.
3. **Post-quantum ready** — ML-DSA (Dilithium) signatures future-proof every token against quantum attacks. Most competitors use ECDSA which will be broken.
4. **Multi-chain from day one** — Ethereum, Solana, HTTP (X402), and agent-to-agent protocols all supported. No competitor covers all four.

### Business model

Usage-based SaaS. Operators pay per trust check. Pricing tiers:

| Tier | Checks/month | Price |
|------|-------------|-------|
| Starter | Up to 50,000 | $49/mo |
| Growth | Up to 500,000 | $299/mo |
| Enterprise | Unlimited + SLA | Custom |

### Key metrics (current)

- < 200ms P99 trust check latency (load-tested)
- 4 payment rails supported
- 20 API endpoints
- 10/10 E2E tests passing
- 0 compiler errors
- Bitcoin + immuDB dual audit trail

---

## Contributing

1. Fork the repo and create a branch: `git checkout -b feature/my-feature`
2. Make your changes. Run `make test && make e2e` — both must pass.
3. Run `cargo clippy --workspace` — no new warnings.
4. Open a pull request.

For large changes, open an issue first to discuss the approach.

---

## License

MIT — see [LICENSE](LICENSE)

---

*Built with Rust, Axum, PostgreSQL, Redis, Neo4j, immuDB, and Bitcoin.*
4. **Trust-check** — runs a Byzantium mandate + reputation check on `did:evm:base:<from-address>`

On success the response is `{"status":"Valid","recovered_from":"0x...","value":1000000}`.

### Solana SPL

`POST /v1/payments/solana/verify` accepts a `{ signature, expected_from, expected_to, expected_amount_lamports, expected_mint }` body. The verifier:

1. Fetches the transaction from the Solana JSON-RPC at `confirmed` commitment
2. Verifies it is a finalized SPL token transfer matching `from`, `to`, `amount`, and `mint`
3. Runs a Byzantium trust-check on `did:sol:<base58-pubkey>`

---

## TEE mode

When `BYZ_TEE_ENABLED=true`, the mandate engine and reputation scorer run as separate Gramine SGX sidecar processes (`mandate-tee` on port 9001, `reputation-tee` on port 9002). Signing keys are generated fresh inside the enclave on every boot and never cross the SGX boundary. Each compliance decision is signed with an ML-DSA (Dilithium) key; the gateway verifies the enclave signature before accepting any result.

Remote attestation quotes are produced by Gramine and exposed via `GET /internal/attestation`. The gateway pins the expected `MRENCLAVE` measurement — set `BYZ_MRENCLAVE` inside the enclave environment. Any response from an enclave with a different measurement is rejected.

To build the Gramine manifests (requires Gramine installed):

```bash
make gramine-build
```

To run TEE services locally via Docker Compose:

```bash
docker compose --profile tee up -d
```

---

## ZK proofs

Byzantium uses the [SP1](https://github.com/succinctlabs/sp1) zkVM (Succinct) for two proof types, both generated off the hot path (background job or TEE) and verified on-path in single-digit milliseconds:

**Credential disclosure (`byz-proof/src/disclosure.rs`)** — proves that a credential attribute satisfies a predicate (e.g. `age >= 18`) without revealing the attribute value or any other credential field. The private witness (`attribute_value_private`, `attribute_salt_private`) stays inside the TEE; only the Merkle commitment and predicate result are published.

**Reputation threshold (`byz-proof/src/threshold.rs`)** — proves that an agent's behavioral score is at or above a required threshold without revealing the raw score. The score and nonce are private inputs; the public output is `commitment_hex` and `threshold`. The gateway caches `VerifiedThreshold` proofs in Redis (TTL controlled by `PROOF_REFRESH_SECS`) and refreshes them in the background.

Set `SP1_PROVER=network` and provide `SP1_PRIVATE_KEY` to delegate proof generation to the Succinct prover network. Use `SP1_PROVER=mock` in CI.

---

## Development

```bash
# Start all backing services (Postgres, Redis, Neo4j, ImmuDB, Prometheus, Grafana)
make dev

# Run the gateway outside Docker (faster iteration)
cargo run -p byz-gateway

# Run the full workspace test suite
make test

# Type-check + Clippy (zero warnings policy)
make check

# Format all Rust source in place
make fmt

# Regenerate sqlx offline query cache (requires a running Postgres)
make sqlx-prepare
# Commit the generated .sqlx/ directory to enable SQLX_OFFLINE builds in CI

# Apply database migrations manually
make migrate
```

Grafana is available at `http://localhost:3000` (admin / byzantium). Prometheus at `http://localhost:9090`.

---

## Production deployment

Kubernetes manifests are in `deploy/k8s/`. Apply them to the `byzantium` namespace:

```bash
kubectl create namespace byzantium
# Populate deploy/k8s/secrets.yaml.template and apply it first
kubectl apply -n byzantium -f deploy/k8s/secrets.yaml
kubectl apply -n byzantium -f deploy/k8s/
```

The deployment runs 3 replicas with a zero-downtime rolling update strategy (`maxUnavailable: 0`). Pods are spread across nodes via `topologySpreadConstraints`. The container runs as a non-root user (UID 10001) with a read-only root filesystem and all capabilities dropped.

**Horizontal Pod Autoscaler:** The manifests directory does not currently include an HPA resource; add one targeting CPU/memory as appropriate for your traffic profile using `kubectl autoscale deployment byzantium-gateway`.

**TEE pinning in production:** After building and signing Gramine SGX manifests with `make gramine-build`, extract the `MRENCLAVE` measurement and set it as `BYZ_MRENCLAVE` in your Kubernetes Secret. The gateway will reject any TEE sidecar response that does not match the pinned measurement.

**Image:** `ghcr.io/byzantium/gateway:latest`

```bash
# Build and push
make docker-push IMAGE_TAG=v1.0.0

# Watch rollout
make k8s-rollout
```

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
