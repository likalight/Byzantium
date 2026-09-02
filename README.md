<div align="center">

<img src="assets/banner.svg" alt="Byzantium — the underwriting layer for autonomous agents" width="100%">

<br>

[![CI](https://github.com/likalight/Byzantium/actions/workflows/ci.yml/badge.svg)](https://github.com/likalight/Byzantium/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-241%20passing-5FBE95)](#testing)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-CE422B?logo=rust&logoColor=white)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-4FA3F5)](LICENSE)
[![Crypto: ML-DSA](https://img.shields.io/badge/signatures-ML--DSA%20(Dilithium3)-8B5CF6)](https://csrc.nist.gov/pubs/fips/204/final)
[![RFC 9421](https://img.shields.io/badge/RFC%209421-HTTP%20Message%20Signatures-0EA5E9)](https://www.rfc-editor.org/rfc/rfc9421.html)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-E0A64A)](CONTRIBUTING.md)

**How much should an autonomous agent be trusted with?**<br>
Byzantium turns an agent's attested history into a portable, signed transaction limit — one that any chain honours on arrival.

[Quick start](#quick-start) · [How it works](#how-it-works) · [API reference](docs/api.md) · [Architecture](#repository-layout) · [Contributing](CONTRIBUTING.md)

</div>

---

## The gap this fills

The agentic payments stack consolidated fast, and it consolidated around identity and settlement — not around risk.

| Layer | Question it answers | Status |
|---|---|---|
| **Visa TAP** | Is this agent legitimate, or a bot? | Open spec on HTTP Message Signatures |
| **AP2** | Did a human authorise this? | 60+ orgs; the mandate carries a cap the *user* sets |
| **x402** | How does value move, per request? | Stablecoin settlement over HTTP 402 |
| **ACP / UCP** | How does checkout work at a merchant? | Merchant-side integration |
| **— missing —** | **How much should this agent be trusted with?** | Unowned. Default: a number a human typed once. |

That last row is underwriting, and it is genuinely absent. AP2's mandate *does* contain a spending cap — but the cap is an **input** from the principal, not an **output** of any risk process. There is no bureau, no history, nothing that follows the agent.

The practical consequence: an agent that has settled cleanly forty thousand times on Base gets the same opening ceiling on Solana as a keypair created five seconds ago. The cost isn't bridge latency — it's **trust re-establishment latency**, and it repeats on every chain.

## What Byzantium does

```
   earned history                 Byzantium                    any chain
 ┌────────────────────┐      ┌──────────────────┐      ┌────────────────────┐
 │ settlements        │      │  underwriting    │      │ verify a signature │
 │ runtime-signed     │ ───► │  engine          │ ───► │ nothing bridges    │
 │   execution traces │      │  ↓               │      │ no trust rebuild   │
 │ counterparty graph │      │  signed limit    │      │                    │
 │ KYC'd principal    │      │  attestation     │      │                    │
 └────────────────────┘      └──────────────────┘      └────────────────────┘
```

A **limit**, not a score. A score offloads the decision onto the relying party; a limit is the thing the issuer can be held to. It is short-lived (minutes to hours), scoped to chains and asset classes, priced by risk tier, and carries a hash of the evidence behind it — never the evidence itself.

**Neutrality is load-bearing.** Byzantium does not custody funds, bridge assets, issue credit, or run a chain. It competes with nobody for the transaction itself, which is the only reason a chain, a wallet and a merchant who all compete with each other can accept the same attestation.

## Quick start

**Prerequisites:** Docker and Docker Compose.

```bash
git clone https://github.com/likalight/Byzantium.git
cd byzantium
cp .env.example .env          # set BYZ_API_KEYS, DATABASE_URL, NEO4J_PASSWORD
docker compose up -d
curl http://localhost:8080/health
```

Migrations run automatically in the `migrate` service before the gateway starts. See [docs/configuration.md](docs/configuration.md) for every environment variable.

### Issue a portable limit in three calls

```bash
# 1. Bind the agent to a KYC'd principal. Nothing is underwritten before this.
curl -X POST localhost:8080/v1/principals \
  -H "Authorization: Bearer $BYZ_API_KEY" -H "Content-Type: application/json" \
  -d '{"agent_did":"did:byz:trader-01","principal_ref":"sha256:acme",
       "kyc_tier":"institutional","sanctions_clear":true,"jurisdiction":"SG"}'

# 2. Underwrite. Scope the limit to the chains it may be presented on.
curl -X POST localhost:8080/v1/limits/issue \
  -H "Authorization: Bearer $BYZ_API_KEY" -H "Content-Type: application/json" \
  -d '{"agent_did":"did:byz:trader-01","ccy":"USD",
       "chains":["base","solana"],"asset_classes":["stablecoin"],
       "action_types":["payment"]}'

# 3. Present the same attestation on a chain that has never seen this agent.
curl -X POST localhost:8080/v1/limits/verify \
  -H "Authorization: Bearer $BYZ_API_KEY" -H "Content-Type: application/json" \
  -d '{"attestation": {...}, "draw":{"amount_minor":50000,"currency":"USD",
       "asset_class":"stablecoin","chain":"solana","action_type":"payment"}}'
```

Every response carries a reason trail — for a refusal *and* for an approval. Adverse-action reasoning has to be designed in; it cannot be retrofitted onto an opaque model.

## How it works

### A limit is earned, not configured

Five controls, each able to reduce or refuse, each recording a typed reason:

| Control | What it does | Why |
|---|---|---|
| **Standing gates** | An unverified or sanctioned principal gets nothing | KYC opens a ceiling; it never earns a limit on its own, or the system rewards paperwork instead of behaviour |
| **Sublinear in value** | Standing grows with the square root of settled value | Proving twice as much must not earn twice the limit |
| **Experience cap** | A limit is never a large multiple of the largest completed action | Stops a long tail of tiny clean transfers unlocking one enormous draw |
| **Rate cap** | Bounded growth per window | Even a flawless run cannot step straight to the ceiling |
| **Principal consolidation** | The ceiling belongs to the principal, not each agent | Splitting one agent into ten divides the limit rather than multiplying it |

A new agent scores **zero**, not a neutral midpoint. A non-zero score for an agent with no history is free money for anyone who can generate a keypair; cold-start standing comes from the KYC'd principal instead.

### The runtime signs, not the agent

Execution provenance — tool calls, plans, memory writes, human approvals — is the signal that makes underwriting an *agent* different from underwriting a wallet, and the only part of the system not derivable from public chain data.

An agent attesting to its own good behaviour is a claim, not evidence. Traces are signed at the point of execution by a registered runtime key the agent does not hold, and **unsigned traces are ignored outright, not down-weighted** — partial credit is an incentive to flood the endpoint with cheap unverifiable claims.

Events commit to a *hash* of their payload. Agent traces are commercially sensitive and often the operator's own IP, so a dispute is settled with a Merkle inclusion proof for the specific step rather than by handing over an execution history.

### TAP extension

Visa's Trusted Agent Protocol answers *who is this*. It does not price risk. `byz-tap` implements RFC 9421 HTTP Message Signatures and adds one header, `Limit-Attestation`, which **must appear in the signature's covered components** — the verifier refuses the request otherwise rather than treating coverage as advisory.

A limit carried in an unsigned header can be rewritten in transit by anything on the path. That would make the extension worse than useless.

A merchant then checks two signatures answering two different questions:

| Signature | Answers | Key |
|---|---|---|
| TAP HTTP Message Signature | Did this request really come from this agent? | the agent's |
| Attestation signature | Who stands behind this limit, and what is it? | the issuer's |

### Liability is explicit

Byzantium launches as a **bureau**: it attests, and the relying party bears the loss. Capital-light, and it keeps the issuer out of lending. The attestation format carries a pluggable `Guarantee`, so an issuer or reinsurer can take the risk position later without the format or the engine changing — and a relying party is always told which model it is looking at.

## Repository layout

```
byzantium/
├── crates/
│   ├── byz-common/       Money, limits, attestations, shared types
│   ├── byz-crypto/       ML-DSA (Dilithium3), Kyber, Merkle trees
│   ├── byz-underwrite/   ★ score → limit, issuance, guarantors, revocation
│   ├── byz-reputation/   Behavioural scoring: value-weighted, decayed, anti-sybil
│   ├── byz-provenance/   ★ Runtime-signed execution traces, Merkle bundles
│   ├── byz-passport/     ★ principal → agent → session delegation
│   ├── byz-tap/          ★ RFC 9421 + the Limit-Attestation extension
│   ├── byz-mandate/      Enforcement engine and the exposure ledger
│   ├── byz-identity/     DIDs, verifiable credentials, zkMe KYC
│   ├── byz-gateway/      Axum HTTP gateway (the service)
│   ├── byz-store/        PostgreSQL, Redis, Neo4j persistence
│   ├── byz-receipt/      Liability receipts and batching
│   ├── byz-anchor/       Merkle anchoring into ImmuDB
│   ├── byz-proof/        ZK scaffolding (SP1 / Winterfell)
│   ├── byz-tee/          SGX/SEV enclave sidecars
│   ├── byz-rail-*/       EIP-3009 (Base/USDC), Solana SPL, x402, A2A
│   ├── byz-sdk/          Rust client
│   └── byz-billing/      Stripe metered usage
├── sdk/typescript/       TypeScript client + ProvenanceRecorder
├── migrations/           SQL migrations (001–004)
├── programs/             ZK circuits
├── docs/                 API reference, configuration, runbooks
└── deploy/               Kubernetes manifests, Helm
```

★ = the underwriting layer. The rest is the enforcement and settlement substrate it sits on.

## Documentation

| | |
|---|---|
| [API reference](docs/api.md) | Every endpoint, with examples |
| [Configuration](docs/configuration.md) | Environment variables |
| [SDKs](docs/sdks.md) | TypeScript and Rust clients, payment rails |
| [OpenAPI](openapi.yaml) | Machine-readable spec |
| [Runbooks](docs/runbooks) | Operational procedures |
| [Contributing](CONTRIBUTING.md) | Development setup and conventions |
| [Security](SECURITY.md) | Reporting a vulnerability |

## Testing

```bash
cargo test --workspace          # 241 tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

The suite is weighted toward adversarial cases rather than happy paths — bust-out farming, wash trading, sybil splitting, forged provenance, replayed events, swapped credentials, and scope-widening delegation each have dedicated tests. `crates/byz-gateway/tests/portability.rs` is the end-to-end proof: an agent earns standing on one chain and spends it on another.

## Design commitments

- **No token.** An underwriter whose incentives are tied to a token price is not a credible underwriter.
- **Post-quantum from day one.** Every signature is ML-DSA (Dilithium3). A credential underwriting financial exposure should not need reissuing when the signature scheme does.
- **Privacy is structural.** Attestations carry an evidence hash, never the evidence.
- **We custody nothing.** No funds, no bridging, no wrapping, no issuance — that is the regulatory perimeter, not just design hygiene.

## License

MIT — see [LICENSE](LICENSE).
