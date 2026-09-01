# API reference

All routes under `/v1/` require `Authorization: Bearer <api-key>`.
Public routes (`/health`, `/metrics`) have no authentication.

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

### Limits

Underwriting. `POST /v1/principals` must come first — nothing is issued to an agent with no verified principal, because a nonzero limit for an unverified keypair is free money.

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/principals` | Bind an agent to a KYC'd principal. Limits consolidate here, so splitting one agent into ten divides the limit rather than multiplying it. |
| `POST` | `/v1/limits/issue` | Underwrite the agent and return a signed `LimitAttestation`, plus the reason trail behind every control that shaped it. |
| `POST` | `/v1/limits/verify` | Honor a **presented** attestation for one draw. Verifies the signature, converts into the unit of account, applies the asset-class haircut, and nets against recorded exposure. |
| `POST` | `/v1/limits/settle` | Resolve a committed draw. Consumes window capacity on success, releases the exposure on failure, and feeds the outcome back to the scorer. |
| `POST` | `/v1/limits/revoke` | Kill the outstanding attestations for an agent or a whole principal. A future `effective_from` schedules the cutoff instead of invalidating credentials in flight. |

```bash
# 1. Bind the principal
curl -X POST http://localhost:8080/v1/principals   -H "Authorization: Bearer $BYZ_API_KEY" -H "Content-Type: application/json"   -d '{"agent_did":"did:byz:trader-01","principal_ref":"sha256:acme",
       "kyc_tier":"institutional","sanctions_clear":true,"jurisdiction":"SG"}'

# 2. Underwrite — scoped to the chains the limit may be presented on
curl -X POST http://localhost:8080/v1/limits/issue   -H "Authorization: Bearer $BYZ_API_KEY" -H "Content-Type: application/json"   -d '{"agent_did":"did:byz:trader-01","ccy":"USD",
       "chains":["base","solana"],"asset_classes":["stablecoin"],
       "action_types":["payment"]}'

# 3. Present the same attestation on a chain that has never seen this agent
curl -X POST http://localhost:8080/v1/limits/verify   -H "Authorization: Bearer $BYZ_API_KEY" -H "Content-Type: application/json"   -d '{"attestation": {...}, "draw":{"amount_minor":50000,"currency":"USD",
       "asset_class":"stablecoin","chain":"solana","action_type":"payment"}}'
```

A refusal always names its cause — `ChainOutOfScope`, `ExceedsSingle`, `ExceedsWindow` and so on — and an issued limit carries a typed reason for every control that bound it. Adverse-action reasoning is built in rather than retrofitted, because retrofitting it onto an opaque model is not realistically possible.

### Provenance

Runtime-signed execution evidence — the signal that distinguishes underwriting an agent from underwriting a wallet, and the only part of the system that is not forkable from public chain data.

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/runtimes` | Register a trusted runtime signing key. This is the trust root for the whole signal, so it is a deliberate operational act. |
| `POST` | `/v1/runtimes/revoke` | Revoke a runtime key. Previously accepted evidence stays explainable; nothing new signed by it is admitted. |
| `POST` | `/v1/provenance` | Submit signed traces. Returns the acceptance rate and the Merkle commitment. |
| `GET` | `/v1/provenance/:did` | Current evidence commitment and summary for an agent. |

**The runtime signs, not the agent.** An agent attesting to its own good behavior is a claim, not evidence. Traces are signed at the point of execution by a key the agent does not hold, and events that fail verification are **ignored outright rather than down-weighted** — partial credit would be an incentive to flood the endpoint with cheap unverifiable claims.

Events commit to a hash of their payload, never the payload. A dispute is settled with a Merkle inclusion proof for the specific step in question, so an agent's execution history never has to be handed over.

### TAP extension

Visa's Trusted Agent Protocol establishes that an agent talking to a merchant is a legitimate agent rather than a bot, over HTTP Message Signatures (RFC 9421). It answers *who is this*. It does not answer *how much should this agent be trusted with*.

`byz-tap` implements the signature layer and adds one header, `Limit-Attestation`, carrying a base64url-encoded `LimitAttestation`. **It must appear in the signature's covered components**, and the verifier refuses the request otherwise rather than treating coverage as advisory. That single rule is the whole security argument: a limit in an unsigned header can be rewritten in transit by anything on the path, which would make the extension worse than useless.

A merchant then checks two signatures answering two different questions:

| Signature | Question | Key |
|---|---|---|
| TAP HTTP Message Signature | did this request really come from this agent? | the agent's |
| Attestation signature | who stands behind this limit, and what is it? | the issuer's |

```rust
use byz_tap::{attach_limit_attestation, verify_request_with_limit, CoveredComponent,
              HttpMessage, TapSigner, TapVerifier, LIMIT_ATTESTATION_HEADER};

let mut msg = HttpMessage::new("POST", "https://merchant.example/checkout")
    .with_body(br#"{"sku":"widget-9"}"#.to_vec());
attach_limit_attestation(&mut msg, &attestation)?;

signer.sign(&mut msg, &[
    "@method".into(),
    "@target-uri".into(),
    CoveredComponent::new(LIMIT_ATTESTATION_HEADER),  // required
], "sig1")?;

// Merchant side: TAP signature, then attestation signature, then the draw.
let att = verify_request_with_limit(&verifier, &msg, "sig1", &issuer_key, &draw)?;
```

The signature base construction follows RFC 9421, so an existing TAP verifier needs one additional covered component rather than a second protocol. This is written to be proposed *into* TAP, not to route around it.

### Agent Passport

Three key levels, each delegating to the next:

```text
  principal  (KYC'd human or entity — where limits consolidate)
      |  signed delegation
  agent      (a DID, one or more signing keys, possibly one per chain)
      |  signed delegation, narrower scope, short expiry
  session    (individually revocable, disposable)
```

Two properties are enforced rather than documented:

- **History attaches to the DID, not to a key.** Rotating or revoking a key does not reset standing. Under the alternative, every rotation costs an operator their limit, and they stop rotating.
- **Delegation narrows, never widens.** A session key cannot authorise more than the agent key that issued it, and leaving a bound unset does not mean "unlimited" — it inherits the parent's. Without this the chain is decorative: an agent under a tight mandate would simply mint itself a permissive session key.

Revoking a parent implicitly revokes everything beneath it, because the chain stops resolving. Revoking a session leaves the agent key intact.

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
