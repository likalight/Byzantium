export function VerdictBadge({ verdict }: { verdict: string }) {
  const styles: Record<string, string> = {
    PASS:  'bg-green/10  text-green  border border-green/20',
    FLAG:  'bg-gold/10   text-gold   border border-gold/20',
    BLOCK: 'bg-red/10    text-red    border border-red/20',
  };
  return (
    <span className={`text-xs font-bold px-2 py-0.5 rounded-full ${styles[verdict] ?? 'bg-border text-mid'}`}>
      {verdict}
    </span>
  );
}
