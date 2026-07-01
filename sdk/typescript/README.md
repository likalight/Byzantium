# @byzantium/sdk

TypeScript client for the [Byzantium](https://byzantium.io) AI Agent Trust Gateway.

Byzantium verifies AI agent transactions in under 200ms — returning PASS, FLAG, or BLOCK before any payment or data access proceeds.

## Install

```bash
npm install @byzantium/sdk
```

## Quick start

```typescript
import { ByzantiumClient } from '@byzantium/sdk';

const client = new ByzantiumClient({
  apiKey: process.env.BYZANTIUM_API_KEY!,
  baseUrl: 'https://api.yourdomain.com',
});

const result = await client.trustCheck({
  agent_did: 'did:key:z6Mk...',
  action_type: 'Payment',
  rail_id: 'tx-123',
  amount_cents: 5000,
  counterparty: {
    id: 'did:key:z6Mk...',
  },
});

if (result.verdict.verdict === 'PASS') {
  // proceed with transaction
  console.log('Trust token:', result.token);
}
```

## requirePass (throw on non-PASS)

```typescript
const token = await client.requirePass({
  agent_did: 'did:key:z6Mk...',
  action_type: 'Payment',
  rail_id: 'x402',
  amount_cents: 5000,
});
// throws ByzantiumTrustError if verdict is FLAG or BLOCK
```

## Tool middleware (Anthropic / OpenAI / LangChain)

### Anthropic tool-use

```typescript
import { withByzantiumCheck } from '@byzantium/sdk';

const safeTool = withByzantiumCheck(paymentToolFn, {
  client,
  agentDid: 'did:key:z6Mk...',
  railId: 'x402',
  actionType: 'Payment',
});
```

### LangChain

```typescript
import { wrapLangChainTool } from '@byzantium/sdk';

const safeTool = wrapLangChainTool(myLangChainTool, {
  client,
  agentDid: 'did:key:z6Mk...',
  actionType: 'Payment',
});
```

## API Reference

### `new ByzantiumClient(options)`

| Option | Type | Description |
|--------|------|-------------|
| `apiKey` | `string` | Your Byzantium API key (Bearer token) |
| `baseUrl` | `string` | Your Byzantium gateway URL |
| `timeoutMs` | `number` | Request timeout in ms (default: 5000) |

### `client.trustCheck(req)` → `TrustCheckResponse`

Core method. Returns `{ verdict, token, request_id, checked_at, latency_ms }`.

### `client.requirePass(req)` → `PassToken`

Like `trustCheck` but throws `ByzantiumTrustError` if verdict is not `PASS`.

### `client.createMandate(req)` → `SpendMandate`

Register spending limits and allowed action types for an agent.

### `client.getMandate(mandateId)` → `SpendMandate`

### `client.revokeMandate(mandateId)` → `void`

### `client.registerAgent(reg)` → `{ agent_did: string }`

### `client.getAgent(did)` → `AgentRegistration`

### `client.listAuditReceipts(params?)` → receipts

### `client.createReceipt(receipt)` → `LiabilityReceipt`

### `client.health()` → `{ status, version }`

## Verdicts

| Verdict | Meaning |
|---------|---------|
| `PASS`  | Trust verified — transaction may proceed |
| `FLAG`  | Allowed but flagged for human review |
| `BLOCK` | Rejected — do not proceed |

## Action types

| Type | Description |
|------|-------------|
| `Payment` | Financial transfer |
| `ApiCall` | External API invocation |
| `DataAccess` | Read/write sensitive data |
| `ContractExecution` | On-chain contract call |
| `CrossAgentDelegation` | One agent delegating to another |
| `{ Custom: string }` | Any custom action type |

## Error classes

- `ByzantiumTrustError` — thrown by `requirePass` when verdict is FLAG or BLOCK
- `ByzantiumApiError` — HTTP error from the gateway (non-2xx)
- `ByzantiumRateLimitError` — 429 rate limit hit, includes `retryAfterMs`

## License

MIT
