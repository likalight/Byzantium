import { useEffect, useState } from 'react';
import { TopBar } from '../components/TopBar';
import { fetchLiveAgents, agentScore, type AgentVerseAgent } from '../api';

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

// Shorten an agentverse address for display
function shortAddr(addr: string): string {
  if (addr.length <= 20) return addr;
  return `${addr.slice(0, 14)}...${addr.slice(-6)}`;
}

export function Agents() {
  const [agents, setAgents] = useState<AgentVerseAgent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    fetchLiveAgents(12).then(data => {
      if (data.length > 0) {
        setAgents(data);
      } else {
        setError('Could not reach AgentVerse — check your connection');
      }
      setLoading(false);
    });
  }, []);

  return (
    <div className="flex-1 overflow-auto">
      <TopBar
        title="Live AI Agents"
        sub="Real registered agents from Fetch.ai AgentVerse — scored by Byzantium"
      />
      <div className="p-8">

        {/* Source badge */}
        <div className="flex items-center gap-2 mb-6">
          <div className="flex items-center gap-2 bg-card border border-border rounded-lg px-3 py-1.5 text-xs text-mid">
            <span className="w-2 h-2 rounded-full bg-green inline-block animate-pulse" />
            Live data from
            <a
              href="https://agentverse.ai"
              target="_blank"
              rel="noopener noreferrer"
              className="text-teal hover:underline font-medium"
            >
              agentverse.ai
            </a>
            · Reputation scores are Byzantium simulated
          </div>
          {!loading && (
            <div className="text-xs text-dim">{agents.length} agents loaded</div>
          )}
        </div>

        {loading && (
          <div className="flex items-center justify-center py-24">
            <div className="text-center">
              <div className="w-8 h-8 border-2 border-purple border-t-transparent rounded-full animate-spin mx-auto mb-3" />
              <div className="text-dim text-sm">Fetching live agents from AgentVerse...</div>
            </div>
          </div>
        )}

        {error && !loading && (
          <div className="bg-red/10 border border-red/20 rounded-xl p-4 text-red text-sm">
            {error}
          </div>
        )}

        {!loading && agents.length > 0 && (
          <div className="grid grid-cols-3 gap-4">
            {agents.map(agent => {
              const score = agentScore(agent.address);
              const color = scoreColor(score);
              const isActive = agent.status === 'active' || !agent.status;
              const displayName = agent.name || shortAddr(agent.address);

              return (
                <div
                  key={agent.address}
                  className="bg-card border border-border rounded-xl p-5 hover:border-purple/40 transition-colors cursor-pointer group"
                >
                  {/* Header */}
                  <div className="flex items-start justify-between mb-4">
                    <div
                      className="w-10 h-10 rounded-xl flex items-center justify-center font-bold text-sm"
                      style={{ background: `${color}20`, border: `1px solid ${color}30` }}
                    >
                      <span style={{ color }}>◎</span>
                    </div>
                    <div className="flex flex-col items-end gap-1">
                      <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${
                        isActive
                          ? 'bg-green/10 text-green border border-green/20'
                          : 'bg-dim/10 text-dim border border-dim/20'
                      }`}>
                        {isActive ? 'Active' : agent.status}
                      </span>
                      {agent.tags?.slice(0, 1).map(tag => (
                        <span key={tag} className="text-xs px-2 py-0.5 rounded-full bg-purple/10 text-purple border border-purple/20">
                          {tag}
                        </span>
                      ))}
                    </div>
                  </div>

                  {/* Name */}
                  <div className="font-medium text-sm text-white mb-1 truncate group-hover:text-purple transition-colors">
                    {displayName}
                  </div>

                  {/* Address */}
                  <div className="font-mono text-xs text-dim mb-4 truncate">
                    {shortAddr(agent.address)}
                  </div>

                  {/* Score */}
                  <div className="flex items-end justify-between mb-3">
                    <div>
                      <div className="text-dim text-xs mb-1">Byzantium Score</div>
                      <div className="text-2xl font-bold" style={{ color }}>{score}</div>
                      <div className="text-xs mt-0.5" style={{ color: `${color}80` }}>{scoreLabel(score)}</div>
                    </div>
                    <div className="text-right">
                      <div className="text-dim text-xs mb-1">Network</div>
                      <div className="text-white font-semibold text-sm">Fetch.ai</div>
                      {agent.updatedAt && (
                        <div className="text-dim text-xs mt-0.5">
                          {new Date(agent.updatedAt).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Score bar */}
                  <div className="h-1 bg-border rounded-full overflow-hidden">
                    <div
                      className="h-full rounded-full"
                      style={{ width: `${score / 10}%`, background: color }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
