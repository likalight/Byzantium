import { useState } from 'react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { TopBar } from '../components/TopBar';
import { StatCard } from '../components/StatCard';
import { VerdictBadge } from '../components/VerdictBadge';
import { mockStats, mockChartData, mockTrustLog } from '../api';

export function Overview() {
  const [stats] = useState(mockStats);
  const [chartData] = useState(mockChartData);
  const [log] = useState(mockTrustLog);

  const pieData = [
    { name: 'PASS',  value: stats.passRate,  color: '#2ecc80' },
    { name: 'FLAG',  value: stats.flagRate,  color: '#f5c842' },
    { name: 'BLOCK', value: stats.blockRate, color: '#f05050' },
  ];

  return (
    <div className="flex-1 overflow-auto">
      <TopBar title="Overview" sub="Real-time trust verification metrics" />
      <div className="p-8">
        {/* KPI row */}
        <div className="grid grid-cols-4 gap-4 mb-8">
          <StatCard label="Trust Checks Today"  value={stats.checksToday.toLocaleString()} sub="↑ 12% vs yesterday" accent="text-white"  icon="✓" />
          <StatCard label="Pass Rate"            value={`${stats.passRate}%`}               sub="of all checks"     accent="text-green" icon="◎" />
          <StatCard label="P99 Latency"          value={`${stats.p99LatencyMs}ms`}          sub="SLO: < 200ms ✓"   accent="text-teal"  icon="⚡" />
          <StatCard label="Active Agents"        value={stats.activeAgents}                 sub={`${stats.activeKeys} API keys`} accent="text-purple" icon="◈" />
        </div>

        {/* Chart + Pie */}
        <div className="grid grid-cols-3 gap-6 mb-8">
          {/* 24h area chart */}
          <div className="col-span-2 bg-card border border-border rounded-xl p-5">
            <div className="text-white font-medium text-sm mb-1">Trust Checks — Last 24 Hours</div>
            <div className="text-dim text-xs mb-4">PASS / FLAG / BLOCK breakdown by hour</div>
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={chartData}>
                <defs>
                  <linearGradient id="gPass"  x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#2ecc80" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#2ecc80" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="gFlag"  x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#f5c842" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#f5c842" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="gBlock" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#f05050" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#f05050" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="hour" stroke="#50507a" tick={{ fontSize: 10 }} interval={3} />
                <YAxis stroke="#50507a" tick={{ fontSize: 10 }} />
                <Tooltip
                  contentStyle={{ background: '#10101e', border: '1px solid #1c1c2e', borderRadius: 8, fontSize: 12 }}
                />
                <Area type="monotone" dataKey="pass"  stroke="#2ecc80" fill="url(#gPass)"  strokeWidth={2} />
                <Area type="monotone" dataKey="flag"  stroke="#f5c842" fill="url(#gFlag)"  strokeWidth={2} />
                <Area type="monotone" dataKey="block" stroke="#f05050" fill="url(#gBlock)" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          {/* Pie chart */}
          <div className="bg-card border border-border rounded-xl p-5">
            <div className="text-white font-medium text-sm mb-1">Verdict Distribution</div>
            <div className="text-dim text-xs mb-4">All time</div>
            <ResponsiveContainer width="100%" height={160}>
              <PieChart>
                <Pie data={pieData} cx="50%" cy="50%" innerRadius={45} outerRadius={70} dataKey="value" strokeWidth={0}>
                  {pieData.map((d, i) => <Cell key={i} fill={d.color} />)}
                </Pie>
                <Tooltip
                  contentStyle={{ background: '#10101e', border: '1px solid #1c1c2e', borderRadius: 8, fontSize: 12 }}
                  formatter={(v: number) => `${v}%`}
                />
              </PieChart>
            </ResponsiveContainer>
            <div className="space-y-2 mt-2">
              {pieData.map(d => (
                <div key={d.name} className="flex justify-between text-xs">
                  <span className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full inline-block" style={{ background: d.color }} />
                    {d.name}
                  </span>
                  <span className="font-medium" style={{ color: d.color }}>{d.value}%</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Recent trust checks */}
        <div className="bg-card border border-border rounded-xl">
          <div className="px-5 py-4 border-b border-border flex items-center justify-between">
            <div className="text-white font-medium text-sm">Recent Trust Checks</div>
            <a href="/log" className="text-purple text-xs hover:underline">View all →</a>
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="text-dim text-xs border-b border-border">
                <th className="text-left px-5 py-3 font-medium">Agent DID</th>
                <th className="text-left px-5 py-3 font-medium">Rail</th>
                <th className="text-left px-5 py-3 font-medium">Verdict</th>
                <th className="text-left px-5 py-3 font-medium">Latency</th>
                <th className="text-left px-5 py-3 font-medium">Time</th>
              </tr>
            </thead>
            <tbody>
              {log.map(entry => (
                <tr key={entry.id} className="border-b border-border last:border-0 hover:bg-border/30 transition-colors">
                  <td className="px-5 py-3 font-mono text-xs text-mid">{entry.agentDid}</td>
                  <td className="px-5 py-3 text-xs text-mid">{entry.railId}</td>
                  <td className="px-5 py-3"><VerdictBadge verdict={entry.verdict} /></td>
                  <td className="px-5 py-3 text-xs text-teal font-medium">{entry.latencyMs}ms</td>
                  <td className="px-5 py-3 text-xs text-dim">{new Date(entry.timestamp).toLocaleTimeString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
