import { useEffect, useState } from 'react';
import { TopBar } from '../components/TopBar';
import { VerdictBadge } from '../components/VerdictBadge';
import { mockTrustLog } from '../api';

type Verdict = 'ALL' | 'PASS' | 'FLAG' | 'BLOCK';

interface LogEntry {
  id: string;
  agentDid: string;
  verdict: string;
  latencyMs: number;
  timestamp: string;
  railId: string;
}

// Generate extended mock log (20+ rows)
const verdicts = ['PASS', 'PASS', 'PASS', 'PASS', 'PASS', 'FLAG', 'FLAG', 'BLOCK'];
const rails = ['eth-tx', 'sol-tx', 'x402', 'btc-tx', 'poly-tx'];
const dids = [
  'did:key:z6Mk9xY...', 'did:key:z6Mk4aB...', 'did:key:z6Mk7cD...',
  'did:key:z6Mk2eF...', 'did:key:z6Mk1gH...', 'did:key:z6Mk5iJ...',
];

const extraRows: LogEntry[] = Array.from({ length: 20 }, (_, i) => ({
  id:         String(100 + i),
  agentDid:   dids[i % dids.length],
  verdict:    verdicts[i % verdicts.length],
  latencyMs:  Math.floor(80 + Math.random() * 120),
  timestamp:  new Date(Date.now() - (i + 7) * 45000).toISOString(),
  railId:     `${rails[i % rails.length]}-${String(i + 10).padStart(3, '0')}`,
}));

const fullLog: LogEntry[] = [...mockTrustLog, ...extraRows];

export function TrustLog() {
  const [filter, setFilter] = useState<Verdict>('ALL');
  const [entries, setEntries] = useState<LogEntry[]>(fullLog);

  useEffect(() => {
    const id = setInterval(() => {
      // Simulate new entry arriving
      const newEntry: LogEntry = {
        id:         String(Date.now()),
        agentDid:   dids[Math.floor(Math.random() * dids.length)],
        verdict:    verdicts[Math.floor(Math.random() * verdicts.length)],
        latencyMs:  Math.floor(80 + Math.random() * 120),
        timestamp:  new Date().toISOString(),
        railId:     `${rails[Math.floor(Math.random() * rails.length)]}-${Math.floor(Math.random() * 999).toString().padStart(3, '0')}`,
      };
      setEntries(prev => [newEntry, ...prev.slice(0, 49)]);
    }, 5000);
    return () => clearInterval(id);
  }, []);

  const filtered = filter === 'ALL' ? entries : entries.filter(e => e.verdict === filter);

  const filterBtn = (v: Verdict) => {
    const active = filter === v;
    const base = 'px-3 py-1.5 rounded-lg text-xs font-medium transition-all';
    if (active) {
      if (v === 'PASS')  return `${base} bg-green/20 text-green border border-green/30`;
      if (v === 'FLAG')  return `${base} bg-gold/20 text-gold border border-gold/30`;
      if (v === 'BLOCK') return `${base} bg-red/20 text-red border border-red/30`;
      return `${base} bg-purple/20 text-purple border border-purple/30`;
    }
    return `${base} text-mid border border-border hover:text-white hover:border-dim`;
  };

  return (
    <div className="flex-1 overflow-auto">
      <TopBar title="Trust Log" sub="Complete audit trail of all trust verification checks" />
      <div className="p-8">
        {/* Filter row */}
        <div className="flex items-center gap-2 mb-6">
          {(['ALL', 'PASS', 'FLAG', 'BLOCK'] as Verdict[]).map(v => (
            <button key={v} onClick={() => setFilter(v)} className={filterBtn(v)}>
              {v === 'ALL' ? 'All Checks' : v}
              {v === 'ALL' && <span className="ml-1.5 text-dim">{entries.length}</span>}
              {v !== 'ALL' && <span className="ml-1.5 opacity-60">{entries.filter(e => e.verdict === v).length}</span>}
            </button>
          ))}
          <div className="ml-auto text-xs text-dim flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-green inline-block animate-pulse" />
            Auto-refreshing every 5s
          </div>
        </div>

        <div className="bg-card border border-border rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-dim text-xs border-b border-border bg-bg/50">
                <th className="text-left px-5 py-3 font-medium">ID</th>
                <th className="text-left px-5 py-3 font-medium">Agent DID</th>
                <th className="text-left px-5 py-3 font-medium">Rail</th>
                <th className="text-left px-5 py-3 font-medium">Verdict</th>
                <th className="text-left px-5 py-3 font-medium">Latency</th>
                <th className="text-left px-5 py-3 font-medium">Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(entry => (
                <tr key={entry.id} className="border-b border-border last:border-0 hover:bg-border/30 transition-colors">
                  <td className="px-5 py-3 font-mono text-xs text-dim">#{entry.id.slice(-6)}</td>
                  <td className="px-5 py-3 font-mono text-xs text-mid">{entry.agentDid}</td>
                  <td className="px-5 py-3 text-xs text-mid">{entry.railId}</td>
                  <td className="px-5 py-3"><VerdictBadge verdict={entry.verdict} /></td>
                  <td className="px-5 py-3 text-xs font-medium" style={{
                    color: entry.latencyMs < 120 ? '#2ecc80' : entry.latencyMs < 180 ? '#2dd4d4' : '#f5c842'
                  }}>{entry.latencyMs}ms</td>
                  <td className="px-5 py-3 text-xs text-dim">{new Date(entry.timestamp).toLocaleString()}</td>
                </tr>
              ))}
              {filtered.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-5 py-12 text-center text-dim text-sm">No entries match this filter</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
