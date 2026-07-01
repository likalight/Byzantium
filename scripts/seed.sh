#!/usr/bin/env bash
# chmod +x scripts/seed.sh  (run once after cloning if needed)
set -euo pipefail

BASE_URL="${BYZ_BASE_URL:-http://localhost:8080}"
API_KEY="${BYZ_API_KEY:-dev-key-local}"
AUTH="Authorization: Bearer $API_KEY"

echo "Seeding Byzantium dev environment at $BASE_URL..."

# 1. Register a test agent
echo "Registering test agent..."
curl -sf -X POST "$BASE_URL/v1/agents" \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"did":"did:key:test-agent-001","display_name":"Test Agent 001","agent_type":"payment"}' \
  | jq .

# 2. Create a spend mandate for the test agent
echo "Creating spend mandate..."
curl -sf -X POST "$BASE_URL/v1/mandates" \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d '{
    "agent_did": "did:key:test-agent-001",
    "per_tx_cap_cents": 10000,
    "daily_cap_cents": 100000,
    "permitted_actions": ["payment", "data_access"],
    "counterparty_whitelist": []
  }' | jq .

# 3. Run a trust check
echo "Running trust check..."
curl -sf -X POST "$BASE_URL/v1/trust-check" \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d '{
    "agent_did": "did:key:test-agent-001",
    "action_type": "payment",
    "amount_cents": 500,
    "counterparty": {"did": "did:key:merchant-001", "display_name": "Test Merchant"}
  }' | jq .

# 4. Create a receipt
echo "Creating receipt..."
curl -sf -X POST "$BASE_URL/v1/receipts" \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d '{
    "agent_did": "did:key:test-agent-001",
    "action_type": "payment",
    "amount_cents": 500,
    "outcome": "success",
    "counterparty": {"did": "did:key:merchant-001", "display_name": "Test Merchant"},
    "metadata": {"item": "seed receipt"}
  }' | jq .

echo ""
echo "Seed complete. Check http://localhost:16686 for traces (if Jaeger is running)."
echo "Check http://localhost:3000 for Grafana dashboards."
