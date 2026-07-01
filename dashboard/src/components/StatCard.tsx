interface StatCardProps {
  label: string;
  value: string | number;
  sub?: string;
  accent?: string;
  icon?: string;
}

export function StatCard({ label, value, sub, accent = 'text-white', icon }: StatCardProps) {
  return (
    <div className="bg-card border border-border rounded-xl p-5">
      <div className="flex items-start justify-between">
        <div>
          <div className="text-dim text-xs font-medium uppercase tracking-wide mb-2">{label}</div>
          <div className={`text-3xl font-bold ${accent}`}>{value}</div>
          {sub && <div className="text-dim text-xs mt-1">{sub}</div>}
        </div>
        {icon && <span className="text-2xl opacity-40">{icon}</span>}
      </div>
    </div>
  );
}
