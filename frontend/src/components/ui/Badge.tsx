const severityMap: Record<string, string> = {
  critical: 'bg-red-500/10 text-red-400 border-red-500/20',
  high: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
  medium: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
  low: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
  info: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
  none: 'bg-slate-500/10 text-slate-400 border-slate-500/20',
};

export function Badge({ label }: { label: string }) {
  const key = label.toLowerCase();
  const cls = severityMap[key] ?? severityMap.none;
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold tracking-widest uppercase border ${cls}`}>
      {label}
    </span>
  );
}
