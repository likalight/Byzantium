# Runbook: TrustCheckLatencyHigh

**Alert**: P99 trust-check latency > 200ms for 2+ minutes  
**Severity**: Warning  
**SLO Impact**: Breaches <200ms core SLO

## Immediate checks (< 5 min)

1. Check gateway health: `curl https://api.yourdomain.com/health`
2. Check Grafana P99 panel for latency trend — sudden spike vs. gradual climb
3. Check Jaeger for slow traces: `http://jaeger:16686` → Service: byzantium-gateway → sort by duration

## Common causes & fixes

**Slow Neo4j** (reputation graph query > 100ms)
- Check Neo4j status: `docker compose exec neo4j neo4j status`
- Check slow query log: `CALL dbms.listQueries()`
- Fix: ensure `MATCH (a:Agent {did: $did})` has index on `did` — run `CREATE INDEX agent_did IF NOT EXISTS FOR (a:Agent) ON (a.did)`

**Redis miss storm** (cache hit rate drops, every trust-check queries Neo4j)
- Check cache hit rate in Grafana
- Warm up cache: `make seed` to create test receipts and trigger proof generation
- If Redis is down: `docker compose restart redis`

**Cold start after deploy**
- Normal — P99 spikes for 1-2 minutes after rolling deploy as JIT warms up
- Wait 3 minutes; if still elevated, check pod logs: `kubectl logs -l app=byzantium-gateway --tail=50`

## Escalation
If P99 > 500ms for > 5 minutes → escalate to on-call engineer + page via Alertmanager
