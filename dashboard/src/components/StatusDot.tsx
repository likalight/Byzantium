export function StatusDot({ status }: { status: 'ok' | 'warn' | 'error' | 'unknown' }) {
  const colors = { ok: 'bg-green', warn: 'bg-gold', error: 'bg-red', unknown: 'bg-dim' };
  return <span className={`inline-block w-2 h-2 rounded-full ${colors[status]}`} />;
}
