import { useEffect, useState } from 'react';
import { FileSearch, ChevronDown, ChevronRight, ExternalLink } from 'lucide-react';
import { getFindings, getTasks } from '../lib/api';
import { Badge } from '../components/ui/Badge';
import { CodeBlock } from '../components/ui/CodeBlock';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import { EmptyState } from '../components/ui/EmptyState';

interface Finding {
  id: number;
  severity?: string;
  title?: string;
  description?: string;
  rule_id?: string;
  target?: string;
  created_at?: string;
}

interface Task {
  id: number;
  task_type?: string;
  status?: string;
  target?: string;
  created_at?: string;
  summary?: unknown;
}

export function Reports() {
  const [tab, setTab] = useState<'findings' | 'tasks'>('findings');
  const [findings, setFindings] = useState<Finding[]>([]);
  const [tasks, setTasks] = useState<Task[]>([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<Set<number>>(new Set());

  useEffect(() => {
    setLoading(true);
    Promise.all([getFindings(200), getTasks(100)])
      .then(([f, t]) => {
        setFindings((f as { items: Finding[] }).items || []);
        setTasks((t as { items: Task[] }).items || []);
      })
      .catch(() => { setFindings([]); setTasks([]); })
      .finally(() => setLoading(false));
  }, []);

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
            RE<span className="text-transparent bg-clip-text bg-gradient-to-r from-indigo-400 to-cyan-400">PORTS</span>
          </h2>
          <a
            href="/api/report/html" target="_blank" rel="noreferrer"
            className="flex items-center gap-2 px-4 py-2 bg-white/5 border border-white/10 rounded-full text-xs font-mono tracking-widest uppercase text-slate-400 hover:text-white hover:border-indigo-500/30 transition-all"
          >
            Full Report <ExternalLink className="w-3 h-3" />
          </a>
        </div>

        <div className="flex gap-2 mb-8 border-b border-white/5 pb-0">
          {(['findings', 'tasks'] as const).map((t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`px-5 py-3 rounded-t-xl text-sm font-mono tracking-wider uppercase transition-all
                ${tab === t ? 'bg-white/5 border border-white/10 border-b-transparent text-white' : 'text-slate-500 hover:text-slate-300'}`}
            >
              {t === 'findings' ? `Findings (${findings.length})` : `Tasks (${tasks.length})`}
            </button>
          ))}
        </div>

        {loading ? <LoadingSpinner label="Loading reports..." />
        : tab === 'findings' ? (
          findings.length === 0 ? <EmptyState title="No findings yet" desc="Run a scan to generate security findings." />
          : (
            <div className="space-y-3">
              {findings.map((f) => (
                <div key={f.id} className="rounded-xl bg-white/5 border border-white/10 overflow-hidden">
                  <button
                    onClick={() => toggle(f.id)}
                    className="w-full flex items-center gap-4 p-5 text-left hover:bg-white/[0.02] transition-colors"
                  >
                    {expanded.has(f.id) ? <ChevronDown className="w-4 h-4 text-slate-500" /> : <ChevronRight className="w-4 h-4 text-slate-500" />}
                    <span className="font-mono text-xs text-indigo-400 uppercase tracking-wider">#{f.id}</span>
                    <span className="font-medium text-white text-sm flex-1">{f.title || f.rule_id || 'Finding'}</span>
                    {f.severity && <Badge label={f.severity} />}
                    <span className="font-mono text-xs text-slate-500">{f.created_at}</span>
                  </button>
                  {expanded.has(f.id) && (
                    <div className="px-5 pb-5 border-t border-white/5 pt-4 space-y-3">
                      {f.description && <p className="text-slate-400 text-sm">{f.description}</p>}
                      {f.target && <p className="text-slate-500 text-xs font-mono">Target: {f.target}</p>}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )
        ) : (
          tasks.length === 0 ? <EmptyState title="No tasks yet" desc="Run a scan to see task history." />
          : (
            <div className="space-y-3">
              {tasks.map((t) => (
                <div key={t.id} className="rounded-xl bg-white/5 border border-white/10 overflow-hidden">
                  <button
                    onClick={() => toggle(t.id)}
                    className="w-full flex items-center gap-4 p-5 text-left hover:bg-white/[0.02] transition-colors"
                  >
                    {expanded.has(t.id) ? <ChevronDown className="w-4 h-4 text-slate-500" /> : <ChevronRight className="w-4 h-4 text-slate-500" />}
                    <span className="font-mono text-xs text-indigo-400 uppercase tracking-wider">#{t.id}</span>
                    <span className="font-mono text-xs text-slate-400 uppercase tracking-wider">{t.task_type || 'task'}</span>
                    <span className="flex-1 text-white text-sm">{t.target || '—'}</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold tracking-widest uppercase border
                      ${t.status === 'finished' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' :
                        t.status === 'failed' ? 'bg-red-500/10 text-red-400 border-red-500/20' :
                        'bg-yellow-500/10 text-yellow-400 border-yellow-500/20'}`}>
                      {t.status}
                    </span>
                    <span className="font-mono text-xs text-slate-500">{t.created_at}</span>
                  </button>
                  {expanded.has(t.id) && t.summary && (
                    <div className="px-5 pb-5 border-t border-white/5 pt-4">
                      <CodeBlock code={JSON.stringify(t.summary, null, 2)} language="summary" />
                    </div>
                  )}
                </div>
              ))}
            </div>
          )
        )}
      </div>
    </main>
  );
}
