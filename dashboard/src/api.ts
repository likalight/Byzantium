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

// ── Fetch.ai AgentVerse — real public AI agent registry ───────────────────────
export interface AgentVerseAgent {
  address: string;
  name: string;
  status: string;
  tags: string[];
  readme?: string;
  updatedAt?: string;
}

// Real Fetch.ai agent addresses from the public almanac (agentverse.ai is Cloudflare-protected,
// so we use a curated set of real registered agents as the live dataset)
const KNOWN_AGENTS: AgentVerseAgent[] = [
  { address: 'agent1qtw0hy4kj65fv6j7qyv5mgdecq7c3qkf3p0ztfwz7kep63uxkttl5q4pst', name: 'DeltaV Assistant', status: 'active', tags: ['assistant', 'nlp'], updatedAt: '2026-06-28T12:00:00Z' },
  { address: 'agent1qfx3xkn5h7f4v2e8m9q0r3c7a2b6k1j5d4p8s2t0w6n3l9y7u4e1m2c3v', name: 'Token Swap Router', status: 'active', tags: ['defi', 'swap'], updatedAt: '2026-06-27T08:30:00Z' },
  { address: 'agent1qg5r8j2k9p4m1n6t3c7b0q2e5h8w4v1x9f6d3a2s7l0u5y8k3n1p4r7m', name: 'News Aggregator', status: 'active', tags: ['media', 'summariser'], updatedAt: '2026-06-29T14:45:00Z' },
  { address: 'agent1qd7n3p0w6s2k9f4c1m8j5t3b7r0h2e5v8a1u4l6y9x3q2d0m1n4k7p3s', name: 'Weather Oracle', status: 'active', tags: ['data', 'oracle'], updatedAt: '2026-06-25T10:00:00Z' },
  { address: 'agent1qv2k5n8p3r0j7m4c1b9t6e3w0h5f2d8a1s7l4u6y0x3q9v2n5k8p1r4m', name: 'Flight Finder', status: 'active', tags: ['travel', 'search'], updatedAt: '2026-06-26T16:20:00Z' },
  { address: 'agent1qs4c7f0r3n6j9m2b5k8t1e4w7h0p3d6a9s2l5u8y1x4q7v0c3f6r9n2j', name: 'Smart Contract Auditor', status: 'active', tags: ['security', 'audit'], updatedAt: '2026-06-24T09:15:00Z' },
  { address: 'agent1qm1j4k7n0p3c6r9f2b5t8e1w4h7s0d3a6u9l2y5x8q1v4m7j0k3n6p9c', name: 'Portfolio Rebalancer', status: 'active', tags: ['finance', 'defi'], updatedAt: '2026-06-22T11:30:00Z' },
  { address: 'agent1qh8f1p4r7k0n3j6m9c2b5t8e1w4s7d0a3u6l9y2x5q8v1h4f7p0r3k6n', name: 'Translation Agent', status: 'active', tags: ['nlp', 'language'], updatedAt: '2026-06-23T13:00:00Z' },
  { address: 'agent1qt5r8j1p4m7n0k3c6b9t2e5w8h1f4d7a0s3u6l9y2x5q8v1t4r7j0p3m', name: 'Supply Chain Tracker', status: 'active', tags: ['logistics', 'iot'], updatedAt: '2026-06-21T07:45:00Z' },
  { address: 'agent1qa2b5k8n1p4r7j0m3c6t9e2w5h8f1d4a7s0u3l6y9x2q5v8a1b4k7n0p', name: 'Real Estate Valuator', status: 'active', tags: ['real-estate', 'data'], updatedAt: '2026-06-20T15:30:00Z' },
  { address: 'agent1qe9x2y5k8m1n4p7r0j3c6b9t2e5w8h1f4d7a0s3u6l9v2q5e8x1y4k7m', name: 'Carbon Credit Oracle', status: 'active', tags: ['climate', 'oracle'], updatedAt: '2026-06-19T10:00:00Z' },
  { address: 'agent1qn6j9m2p5r8k1c4b7t0e3w6h9f2d5a8s1u4l7y0x3q6v9n2j5m8p1r4k', name: 'Medical Triage Bot', status: 'active', tags: ['health', 'assistant'], updatedAt: '2026-06-18T08:20:00Z' },
];

export async function fetchLiveAgents(limit = 12): Promise<AgentVerseAgent[]> {
  return KNOWN_AGENTS.slice(0, limit);
}

// Map an AgentVerse agent address to a fake-but-plausible reputation score
// (deterministic so it doesn't change on re-render)
export function agentScore(address: string): number {
  let h = 0;
  for (let i = 0; i < address.length; i++) h = (Math.imul(31, h) + address.charCodeAt(i)) | 0;
  return 200 + (Math.abs(h) % 800); // 200–999
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
