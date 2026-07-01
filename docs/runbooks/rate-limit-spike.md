# Runbook: RateLimitRejectionSpike

**Alert**: Rate limit rejections > 100/minute  
**Severity**: Warning  
**Impact**: Legitimate traffic may be rejected; possible abuse

## Checks

1. Check Grafana rate limit panel for which API keys are hitting limits
2. Check logs: `kubectl logs -l app=byzantium-gateway | grep "rate_limit" | grep "429"`
3. Look for unusual traffic patterns (single key, single IP)

## Common causes & fixes

**Misconfigured SDK client** — retry loop without backoff
- Contact operator; ask them to honor `Retry-After: 60` header
- Temporary: revoke the offending key via `DELETE /v1/keys/:id`

**Legitimate traffic spike** — product going viral / large batch job
- Increase per-key rate limit: update `BYZ_RATE_LIMIT_PER_MIN` and restart (or create a higher-limit key)

**Abuse / credential leak** — key being shared or scraped
- Revoke key immediately: `DELETE /v1/keys/:id`
- Audit recent usage in PostgreSQL: `SELECT * FROM api_keys WHERE id = '...'`
