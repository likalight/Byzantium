# SDKs

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
