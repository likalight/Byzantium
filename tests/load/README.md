# Load Tests

## Prerequisites
brew install k6  # or https://k6.io/docs/get-started/installation/

## Run against local stack
make dev  # start services first
k6 run tests/load/trust_check.js \
  -e BYZANTIUM_URL=http://localhost:8080 \
  -e BYZANTIUM_API_KEY=dev-key-local

## Run against production
k6 run tests/load/trust_check.js \
  -e BYZANTIUM_URL=https://api.yourdomain.com \
  -e BYZANTIUM_API_KEY=$BYZ_API_KEY

## Key thresholds
- P99 < 200ms (core SLO)
- Error rate < 1%
- P95 < 150ms (headroom buffer)

## Interpreting results
- `trust_check_duration p(99)` — must stay below 200ms
- `block_rate` — should be < 5% for well-configured agents
- `error_rate` — HTTP/timeout errors
