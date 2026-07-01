# End-to-End Tests

These tests spin up a full in-memory Byzantium gateway and exercise the complete API flow.

## Run

```bash
cargo test -p byz-gateway --test e2e -- --nocapture
```

Or via Make:

```bash
make e2e
```

Or via the helper script:

```bash
bash scripts/run-e2e.sh
```

## What's tested

- **Happy path** (`e2e_happy_path`): register agent → create mandate → trust check → PASS verdict with PassToken
- **No mandate** (`e2e_no_mandate_blocks`): agent without mandate → BLOCK verdict
- **Cap exceeded** (`e2e_amount_over_cap_blocks`): amount > per_tx_cap_cents → BLOCK verdict
- **Health check** (`e2e_health_check`): GET /health → 200 with `{"status":"ok"}`
- **Unauthenticated** (`e2e_unauthenticated_returns_401`): missing Bearer token → 401
- **Request ID propagation** (`e2e_request_id_propagated`): client X-Request-Id echoed in response
- **Full audit trail** (`e2e_full_audit_trail`): mandate → receipt → GET /v1/audit/receipts
- **Revoked mandate** (`e2e_revoked_mandate_blocks`): revoke mandate → subsequent trust check → BLOCK
- **Idempotency** (`e2e_idempotent_trust_check`): two identical trust checks return same verdict
- **Rate limiting** (`e2e_rate_limit_returns_429`): burst over per-key rate limit → 429

## Notes

- All tests use isolated in-memory state (no shared globals, no external services).
- Each test creates its own server on a random port (port 0), so tests run safely in parallel.
- The reputation threshold is set to 400 in most tests (below the default agent score of 500)
  so freshly-registered agents can PASS without a transaction history.
- The `e2e_rate_limit_returns_429` test overrides `rate_limit_per_min` to 2 to trigger limiting easily.
