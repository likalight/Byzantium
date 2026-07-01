# Runbook: ByzantiumGatewayDown

**Alert**: Prometheus cannot scrape gateway for 1+ minute  
**Severity**: Critical  
**Impact**: All trust-checks failing — agents are blocked

## Immediate response (< 2 min)

1. Check pods: `kubectl get pods -l app=byzantium-gateway`
2. Check pod logs: `kubectl logs -l app=byzantium-gateway --tail=100 --previous`
3. Check events: `kubectl describe pods -l app=byzantium-gateway`

## Common causes & fixes

**OOMKilled** — memory limit exceeded (usually ZK proof generation)
- `kubectl describe pod <pod-name>` → look for `OOMKilled`
- Temporary: `kubectl rollout restart deployment/byzantium-gateway`
- Fix: increase memory limit in `deploy/k8s/deployment.yaml` or disable `BYZ_ZK_PROOFS_ENABLED`

**CrashLoopBackOff** — startup failure
- Check logs for panic message
- Common cause: `BYZ_RATE_LIMIT_PER_MIN=0` → set to 600 in secrets
- Common cause: TEE attestation MRENCLAVE mismatch → update `BYZ_MANDATE_MRENCLAVE` or disable TEE

**PostgreSQL connection refused** — DB is down
- Check postgres: `kubectl get pods -l app=postgres`
- If postgres is down: `kubectl rollout restart statefulset/postgres`
- Gateway will start in in-memory mode if DB is unavailable (check logs for "persistent store unavailable")

**Image pull failure** — bad deployment
- `kubectl rollout undo deployment/byzantium-gateway`

## Recovery validation
```bash
curl https://api.yourdomain.com/health
# Expected: {"status":"ok","checks":{"postgres":"ok","redis":"ok"}}
```
