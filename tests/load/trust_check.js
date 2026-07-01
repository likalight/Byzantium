import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

// Custom metrics
const trustCheckDuration = new Trend('trust_check_duration', true);
const blockRate = new Rate('block_rate');
const flagRate = new Rate('flag_rate');
const passRate = new Rate('pass_rate');
const errorRate = new Rate('error_rate');

// Config from env vars
const BASE_URL = __ENV.BYZANTIUM_URL || 'http://localhost:8080';
const API_KEY  = __ENV.BYZANTIUM_API_KEY || 'dev-key-local';

export const options = {
  scenarios: {
    // Ramp up to 100 concurrent users, hold, ramp down
    ramp_up: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '30s', target: 10  },   // warm up
        { duration: '60s', target: 50  },   // ramp to 50
        { duration: '120s', target: 100 },  // ramp to 100 — SLO test
        { duration: '60s', target: 100 },   // hold at 100
        { duration: '30s', target: 0   },   // ramp down
      ],
    },
    // Spike test — sudden 5x burst
    spike: {
      executor: 'ramping-vus',
      startVUs: 0,
      startTime: '5m',
      stages: [
        { duration: '10s', target: 200 },
        { duration: '30s', target: 200 },
        { duration: '10s', target: 0   },
      ],
    },
  },
  thresholds: {
    // SLO: P99 trust-check < 200ms
    'trust_check_duration{scenario:ramp_up}': ['p(99)<200'],
    // Error rate < 1%
    'error_rate': ['rate<0.01'],
    // HTTP success rate > 99%
    'http_req_failed': ['rate<0.01'],
    // P95 < 150ms (headroom before SLO breach)
    'http_req_duration{status:200}': ['p(95)<150'],
  },
};

// Test agents — registered during setup
const TEST_AGENTS = Array.from({ length: 20 }, (_, i) => `did:key:load-test-agent-${i}`);

export function setup() {
  const headers = { 'Authorization': `Bearer ${API_KEY}`, 'Content-Type': 'application/json' };

  // Register test mandates
  for (const did of TEST_AGENTS) {
    const res = http.post(`${BASE_URL}/v1/mandates`, JSON.stringify({
      agent_did: did,
      operator_id: 'load-test-operator',
      counterparty_whitelist: [],
      allowed_action_types: ['payment', 'data_access'],
      per_tx_cap_cents: 50000,
      daily_cap_cents: 10000000,
      valid_days: 1,
    }), { headers });
    if (res.status !== 200 && res.status !== 201) {
      console.warn(`Failed to register mandate for ${did}: ${res.status}`);
    }
  }
  console.log(`Setup complete. ${TEST_AGENTS.length} test agents registered.`);
  return { agents: TEST_AGENTS };
}

export default function (data) {
  const agentDid = data.agents[Math.floor(Math.random() * data.agents.length)];
  const headers = { 'Authorization': `Bearer ${API_KEY}`, 'Content-Type': 'application/json' };

  const payload = JSON.stringify({
    agent_did: agentDid,
    action_type: Math.random() > 0.5 ? 'payment' : 'data_access',
    amount_cents: Math.floor(Math.random() * 10000),
    rail_id: `load-test-${__ITER}`,
    counterparty: {
      did: 'did:key:load-test-merchant',
      display_name: 'Load Test Merchant',
    },
  });

  const start = Date.now();
  const res = http.post(`${BASE_URL}/v1/trust-check`, payload, {
    headers,
    timeout: '500ms',  // fail fast — SLO is 200ms
  });
  trustCheckDuration.add(Date.now() - start);

  const ok = check(res, {
    'status is 200':            (r) => r.status === 200,
    'has verdict field':        (r) => r.json('verdict') !== undefined,
    'has x-request-id header':  (r) => r.headers['X-Request-Id'] !== undefined,
    'p99 under 200ms':          () => Date.now() - start < 200,
  });

  if (!ok || res.status !== 200) {
    errorRate.add(1);
    return;
  }
  errorRate.add(0);

  const verdict = res.json('verdict.verdict');
  passRate.add(verdict === 'PASS');
  flagRate.add(verdict === 'FLAG');
  blockRate.add(verdict === 'BLOCK');

  sleep(Math.random() * 0.1); // 0-100ms think time
}

export function teardown(data) {
  console.log('Load test complete.');
}
