# Configuration

All configuration is read from environment variables. Copy `.env.example` to
`.env` for local development; in production inject via Kubernetes Secrets,
AWS Secrets Manager, or HashiCorp Vault.

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
