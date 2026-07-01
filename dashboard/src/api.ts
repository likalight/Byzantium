const BASE = import.meta.env.VITE_API_URL || 'http://localhost:8080';
const KEY  = import.meta.env.VITE_API_KEY  || '';

const headers = () => ({
  'Content-Type': 'application/json',
  'Authorization': `Bearer ${KEY}`,
});

export async function getHealth() {
  const r = await fetch(`${BASE}/health`);
  return r.json();
}

export async function getUsage() {
  const r = await fetch(`${BASE}/v1/usage`, { headers: headers() });
  return r.json();
}

export async function getAuditReceipts(cursor?: string) {
  const url = cursor
    ? `${BASE}/v1/audit/receipts?cursor=${cursor}&limit=20`
    : `${BASE}/v1/audit/receipts?limit=20`;
  const r = await fetch(url, { headers: headers() });
  return r.json();
}

export async function getApiKeys() {
  const r = await fetch(`${BASE}/v1/keys`, { headers: headers() });
  return r.json();
}

export async function createApiKey(name: string) {
  const r = await fetch(`${BASE}/v1/keys`, {
    method: 'POST',
    headers: headers(),
    body: JSON.stringify({ name }),
  });
  return r.json();
}

export async function revokeApiKey(id: string) {
  await fetch(`${BASE}/v1/keys/${id}`, { method: 'DELETE', headers: headers() });
}

export async function getAgent(did: string) {
  const r = await fetch(`${BASE}/v1/agents/${encodeURIComponent(did)}`, { headers: headers() });
  return r.json();
}

// Mock data for demo when API is unavailable
export const mockStats = {
  totalChecks: 12847,
  checksToday: 342,
  passRate: 94.2,
  flagRate: 4.1,
  blockRate: 1.7,
  p99LatencyMs: 142,
  activeAgents: 28,
  activeKeys: 7,
};

export const mockTrustLog = [
  { id: '1', agentDid: 'did:key:z6Mk9xY...', verdict: 'PASS',  latencyMs: 118, timestamp: new Date(Date.now() - 2000).toISOString(),   railId: 'eth-tx-001' },
  { id: '2', agentDid: 'did:key:z6Mk4aB...', verdict: 'FLAG',  latencyMs: 134, timestamp: new Date(Date.now() - 15000).toISOString(),  railId: 'sol-tx-002' },
  { id: '3', agentDid: 'did:key:z6Mk7cD...', verdict: 'PASS',  latencyMs: 97,  timestamp: new Date(Date.now() - 31000).toISOString(),  railId: 'x402-003'  },
  { id: '4', agentDid: 'did:key:z6Mk2eF...', verdict: 'BLOCK', latencyMs: 89,  timestamp: new Date(Date.now() - 62000).toISOString(),  railId: 'eth-tx-004' },
  { id: '5', agentDid: 'did:key:z6Mk1gH...', verdict: 'PASS',  latencyMs: 155, timestamp: new Date(Date.now() - 90000).toISOString(),  railId: 'sol-tx-005' },
  { id: '6', agentDid: 'did:key:z6Mk9xY...', verdict: 'PASS',  latencyMs: 122, timestamp: new Date(Date.now() - 120000).toISOString(), railId: 'eth-tx-006' },
];

export const mockChartData = Array.from({ length: 24 }, (_, i) => ({
  hour:  `${i}:00`,
  pass:  Math.floor(80 + Math.random() * 40),
  flag:  Math.floor(2  + Math.random() * 8),
  block: Math.floor(0  + Math.random() * 4),
  p99:   Math.floor(120 + Math.random() * 60),
}));
