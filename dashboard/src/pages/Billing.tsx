import { TopBar } from '../components/TopBar';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';

const TIER_LIMIT = 15000;
const CURRENT_USAGE = 12847;

const monthlyData = [
  { month: 'Jan', checks: 8400  },
  { month: 'Feb', checks: 9200  },
  { month: 'Mar', checks: 11000 },
  { month: 'Apr', checks: 12847 },
  { month: 'May', checks: 10200 },
  { month: 'Jun', checks: 13400 },
];

const CURRENT_MONTH = 'Apr';

export function Billing() {
  const usagePct = Math.round((CURRENT_USAGE / TIER_LIMIT) * 100);
  const barColor = usagePct >= 90 ? '#f05050' : usagePct >= 70 ? '#f5c842' : '#6c63ff';

  return (
    <div className="flex-1 overflow-auto">
      <TopBar title="Billing" sub="Usage tracking and subscription management" />
      <div className="p-8 space-y-6">

        {/* This month's usage */}
        <div className="bg-card border border-border rounded-xl p-6">
          <div className="flex items-start justify-between mb-6">
            <div>
              <div className="text-dim text-xs font-medium uppercase tracking-wide mb-1">This Month's Usage</div>
              <div className="text-4xl font-bold text-white">{CURRENT_USAGE.toLocaleString()}</div>
              <div className="text-dim text-sm mt-1">trust checks billed</div>
            </div>
            <div className="text-right">
              <div className="text-dim text-xs mb-1">Tier Limit</div>
              <div className="text-mid font-semibold">{TIER_LIMIT.toLocaleString()} checks</div>
              <div className="mt-3">
                <span className={`text-xs font-medium px-2.5 py-1 rounded-full ${
                  true
                    ? 'bg-green/10 text-green border border-green/20'
                    : 'bg-red/10 text-red border border-red/20'
                }`}>
                  Stripe configured: Yes
                </span>
              </div>
            </div>
          </div>

          {/* Progress bar */}
          <div className="mb-2">
            <div className="flex justify-between text-xs text-dim mb-1.5">
              <span>{CURRENT_USAGE.toLocaleString()} used</span>
              <span>{usagePct}% of limit</span>
            </div>
            <div className="h-2.5 bg-border rounded-full overflow-hidden">
              <div
                className="h-full rounded-full transition-all"
                style={{
                  width: `${usagePct}%`,
                  background: `linear-gradient(90deg, #6c63ff, ${barColor})`,
                }}
              />
            </div>
            <div className="flex justify-between text-xs text-dim mt-1.5">
              <span>0</span>
              <span>{TIER_LIMIT.toLocaleString()}</span>
            </div>
          </div>

          {usagePct >= 80 && (
            <div className="mt-4 bg-gold/5 border border-gold/20 rounded-lg px-4 py-3 text-xs text-gold">
              Approaching tier limit. Consider upgrading your plan to avoid overages.
            </div>
          )}
        </div>

        {/* Plan details */}
        <div className="grid grid-cols-3 gap-4">
          {[
            { label: 'Plan',          value: 'Growth',        sub: '$0.002 / check over limit' },
            { label: 'Billing Cycle', value: 'Monthly',       sub: 'Renews May 1, 2025'        },
            { label: 'Est. Invoice',  value: '$25.69',        sub: 'based on current usage'    },
          ].map(({ label, value, sub }) => (
            <div key={label} className="bg-card border border-border rounded-xl p-5">
              <div className="text-dim text-xs font-medium uppercase tracking-wide mb-2">{label}</div>
              <div className="text-white font-bold text-xl">{value}</div>
              <div className="text-dim text-xs mt-1">{sub}</div>
            </div>
          ))}
        </div>

        {/* Usage history chart */}
        <div className="bg-card border border-border rounded-xl p-6">
          <div className="text-white font-medium text-sm mb-1">Usage History</div>
          <div className="text-dim text-xs mb-5">Last 6 months — trust checks processed</div>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={monthlyData} barSize={32}>
              <XAxis dataKey="month" stroke="#50507a" tick={{ fontSize: 11 }} />
              <YAxis stroke="#50507a" tick={{ fontSize: 11 }} />
              <Tooltip
                contentStyle={{ background: '#10101e', border: '1px solid #1c1c2e', borderRadius: 8, fontSize: 12 }}
                formatter={(v: number) => [v.toLocaleString(), 'Checks']}
              />
              <Bar dataKey="checks" radius={[4, 4, 0, 0]}>
                {monthlyData.map(entry => (
                  <Cell
                    key={entry.month}
                    fill={entry.month === CURRENT_MONTH ? '#6c63ff' : '#2a2a4a'}
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
          <div className="mt-3 flex items-center gap-4 text-xs text-dim">
            <span className="flex items-center gap-1.5">
              <span className="w-3 h-3 rounded-sm inline-block bg-purple" />
              Current month
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-3 h-3 rounded-sm inline-block bg-[#2a2a4a]" />
              Previous months
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
