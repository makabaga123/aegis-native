import { Inbox } from 'lucide-react';

export function EmptyState({ title, desc }: { title: string; desc?: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-4 py-20 text-slate-500">
      <Inbox className="w-12 h-12" />
      <span className="text-sm font-mono tracking-widest uppercase">{title}</span>
      {desc && <span className="text-xs text-slate-600">{desc}</span>}
    </div>
  );
}
