interface TopBarProps { title: string; sub?: string; }

export function TopBar({ title, sub }: TopBarProps) {
  return (
    <div className="px-8 py-5 border-b border-border flex items-center justify-between">
      <div>
        <h1 className="text-white font-semibold text-lg">{title}</h1>
        {sub && <p className="text-dim text-sm mt-0.5">{sub}</p>}
      </div>
      <div className="flex items-center gap-2 text-xs text-dim">
        <span className="w-2 h-2 rounded-full bg-green inline-block" />
        Live
      </div>
    </div>
  );
}
