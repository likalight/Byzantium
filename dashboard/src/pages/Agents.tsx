import { TopBar } from '../components/TopBar';

interface Agent {
  did: string;
  status: 'Active' | 'Suspended' | 'Deactivated';
  score: number;
  created: string;
  checksTotal: number;
}

const mockAgents: Agent[] = [
  { did: 'did:key:z6Mk9xY...abc', status: 'Active',    score: 820, created: '2024-11-03', checksTotal: 4821 },
  { did: 'did:key:z6Mk4aB...def', status: 'Active',    score: 650, created: '2024-12-15', checksTotal: 2340 },
  { did: 'did:key:z6Mk7cD...ghi', status: 'Active',    score: 480, created: '2025-01-08', checksTotal: 1892 },
  { did: 'did:key:z6Mk2eF...jkl', status: 'Active',    score: 320, created: '2025-02-20', checksTotal: 983  },
  { did: 'did:key:z6Mk1gH...mno', status: 'Suspended', score: 180, created: '2024-10-01', checksTotal: 5102 },
  { did: 'did:key:z6Mk5iJ...pqr', status: 'Active',    score: 910, created: '2025-03-12', checksTotal: 341  },
];

function scoreColor(score: number): string {
  if (score >= 800) return '#2ecc80';
  if (score >= 600) return '#2dd4d4';
  if (score >= 400) return '#f5c842';
  if (score >= 250) return '#ff9040';
  return '#f05050';
}

function scoreLabel(score: number): string {
  if (score >= 800) return 'Excellent';
  if (score >= 600) return 'Good';
  if (score >= 400) return 'Fair';
  if (score >= 250) return 'Poor';
  return 'Critical';
}

export function Agents() {
  return (
    <div className="flex-1 overflow-auto">
      <TopBar title="Agents" sub="Registered AI agents and their trust profiles" />
      <div className="p-8">
        <div className="grid grid-cols-3 gap-4">
          {mockAgents.map(agent => {
            const color = scoreColor(agent.score);
            const isActive = agent.status === 'Active';
            return (
              <div
                key={agent.did}
                className="bg-card border border-border rounded-xl p-5 hover:border-purple/40 transition-colors cursor-pointer group"
              >
                {/* Header */}
                <div className="flex items-start justify-between mb-4">
                  <div
                    className="w-10 h-10 rounded-xl flex items-center justify-center text-white font-bold text-sm"
                    style={{ background: `${color}20`, border: `1px solid ${color}30` }}
                  >
                    <span style={{ color }}>◎</span>
                  </div>
                  <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${
                    isActive
                      ? 'bg-green/10 text-green border border-green/20'
                      : 'bg-red/10 text-red border border-red/20'
                  }`}>
                    {agent.status}
                  </span>
                </div>

                {/* DID */}
                <div className="font-mono text-xs text-mid mb-4 truncate group-hover:text-white transition-colors">
                  {agent.did}
                </div>

                {/* Score */}
                <div className="flex items-end justify-between mb-3">
                  <div>
                    <div className="text-dim text-xs mb-1">Reputation Score</div>
                    <div className="text-2xl font-bold" style={{ color }}>{agent.score}</div>
                    <div className="text-xs mt-0.5" style={{ color: `${color}80` }}>{scoreLabel(agent.score)}</div>
                  </div>
                  <div className="text-right">
                    <div className="text-dim text-xs mb-1">Total Checks</div>
                    <div className="text-white font-semibold text-lg">{agent.checksTotal.toLocaleString()}</div>
                  </div>
                </div>

                {/* Score bar */}
                <div className="h-1 bg-border rounded-full overflow-hidden mb-4">
                  <div
                    className="h-full rounded-full transition-all"
                    style={{ width: `${agent.score / 10}%`, background: color }}
                  />
                </div>

                {/* Footer */}
                <div className="text-xs text-dim">
                  Registered {new Date(agent.created).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
