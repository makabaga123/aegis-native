import { useEffect, useState } from 'react';
import { getRuntimeTimeline } from '../lib/api';
import { Badge } from '../components/ui/Badge';
import { CodeBlock } from '../components/ui/CodeBlock';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import { EmptyState } from '../components/ui/EmptyState';
import { RefreshCw, ChevronDown, ChevronRight } from 'lucide-react';

interface RuntimeItem {
  id: number;
  event_type?: string;
  timestamp?: string;
  created_at?: string;
  event_data?: Record<string, unknown>;
  findings?: Array<{ severity?: string; title?: string; description?: string }>;
}

export function RuntimeTimeline() {
  const [items, setItems] = useState<RuntimeItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<Set<number>>(new Set());

  const fetch = () => {
    setLoading(true);
    getRuntimeTimeline(200)
      .then((r) => setItems((r as { items: RuntimeItem[] }).items || []))
      .catch(() => setItems([]))
      .finally(() => setLoading(false));
  };

  useEffect(() => { fetch(); }, []);

  const toggle = (id: number) => {
    const next = new Set(expanded);
    next.has(id) ? next.delete(id) : next.add(id);
    setExpanded(next);
  };

  return (
    <main className="pt-28 pb-20">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between mb-8">
          <h2 className="text-3xl md:text-5xl font-extrabold tracking-tighter text-white">
            RUNTIME <span className="text-transparent bg-clip-text bg-gradient-to-r from-indigo-400 to-cyan-400">EDR</span>
          </h2>
          <button onClick={fetch} className="flex items-center gap-2 px-4 py-2 bg-white/5 border border-white/10 rounded-full text-xs font-mono tracking-widest uppercase text-slate-400 hover:text-white hover:border-indigo-500/30 transition-all">
            <RefreshCw className="w-3.5 h-3.5" /> Refresh
          </button>
        </div>

        {loading ? <LoadingSpinner label="Loading timeline..." />
        : items.length === 0 ? <EmptyState title="No runtime events" desc="Send events to /api/runtime/events to populate the timeline." />
        : (
          <div className="space-y-3">
            {items.map((item) => (
              <div key={item.id} className="rounded-xl bg-white/5 border border-white/10 overflow-hidden">
                <button
                  onClick={() => toggle(item.id)}
                  className="w-full flex items-center gap-4 p-5 text-left hover:bg-white/[0.02] transition-colors"
                >
                  {expanded.has(item.id) ? <ChevronDown className="w-4 h-4 text-slate-500" /> : <ChevronRight className="w-4 h-4 text-slate-500" />}
                  <span className="font-mono text-xs text-indigo-400 uppercase tracking-wider">{item.event_type || 'event'}</span>
                  <span className="font-mono text-xs text-slate-500">{item.timestamp || item.created_at || '—'}</span>
                  <div className="ml-auto flex gap-2">
                    {item.findings?.filter((f) => f.severity).slice(0, 3).map((f, i) => <span key={i}><Badge label={f.severity!} /></span>)}
                  </div>
                </button>
                {expanded.has(item.id) && (
                  <div className="px-5 pb-5 space-y-3 border-t border-white/5 pt-4">
                    {item.findings && item.findings.length > 0 && (
                      <div className="space-y-2">
                        {item.findings.map((f, i) => (
                          <div key={i} className="p-3 rounded-lg bg-black/30 border border-white/5">
                            <div className="flex items-center gap-2 mb-1">
                              {f.severity && <Badge label={f.severity} />}
                              <span className="text-white text-sm font-medium">{f.title}</span>
                            </div>
                            {f.description && <p className="text-slate-400 text-xs">{f.description}</p>}
                          </div>
                        ))}
                      </div>
                    )}
                    {item.event_data && <CodeBlock code={JSON.stringify(item.event_data, null, 2)} language="event data" />}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </main>
  );
}
