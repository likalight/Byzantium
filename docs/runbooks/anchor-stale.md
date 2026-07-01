# Runbook: AnchorStale

**Alert**: No Bitcoin/immudb anchor written in > 1 hour  
**Severity**: Warning  
**Impact**: Receipt proofs not yet Bitcoin-confirmed; liability records vulnerable until anchored

## Checks

1. Check immudb: `curl http://localhost:8322/healthz`
2. Check anchor job logs: `kubectl logs -l app=byzantium-gateway | grep anchor`
3. Check Bitcoin RPC: verify `BYZ_BITCOIN_RPC_URL` is reachable and wallet has funds for OP_RETURN fee

## Common causes

**immudb unreachable** — anchor service in offline/stub mode
- Restart immudb: `docker compose restart immudb`
- Gateway will auto-reconnect (3-attempt backoff)

**Bitcoin wallet insufficient funds** — fundrawtransaction fails
- Fund the wallet: `bitcoin-cli sendtoaddress <wallet-address> 0.001`

**Batch size too small** — anchor job only triggers when batch hits threshold
- Check `BYZ_ANCHOR_BATCH_SIZE` env var; lower it temporarily

## Note
Receipts are still cryptographically valid (Merkle proofs) even without Bitcoin anchoring — the anchor is an additional tamper-evidence layer. Missing one anchor is a warning, not a data loss event.
