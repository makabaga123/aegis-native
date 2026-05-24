import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Container, Cpu, Brain, ShieldAlert, Activity, FileSearch,
  Workflow, Terminal, ArrowRight, Circle
} from 'lucide-react';
import { getFindings, getTasks, healthCheck } from '../lib/api';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';

const tools = [
  { to: '/scan', icon: Container, label: 'Scan', desc: 'Dockerfile, Image, K8s YAML' },
  { to: '/agent', icon: Brain, label: 'AI Agent', desc: 'Single-agent analysis' },
  { to: '/multi-agent', icon: Workflow, label: 'Multi-Agent', desc: 'Supervisor orchestration' },
  { to: '/runtime', icon: Activity, label: 'Runtime EDR', desc: 'Event timeline & monitoring' },
  { to: '/mcp', icon: Terminal, label: 'MCP Tools', desc: 'Tool registry & execution' },
  { to: '/reports', icon: FileSearch, label: 'Reports', desc: 'Findings & task history' },
];

export function Dashboard() {
  const [health, setHealth] = useState<{ status: string } | null>(null);
  const [findingsCount, setFindingsCount] = useState<number | null>(null);
  const [tasksCount, setTasksCount] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      healthCheck().catch(() => ({ status: 'disconnected' })),
      getFindings(1).catch(() => ({ items: [] })),
      getTasks(1).catch(() => ({ items: [] })),
    ]).then(([h, f, t]) => {
      setHealth(h as { status: string });
      setFindingsCount(Array.isArray((f as { items: unknown[] }).items) ? (f as { items: unknown[] }).items.length : 0);
      setTasksCount(Array.isArray((t as { items: unknown[] }).items) ? (t as { items: unknown[] }).items.length : 0);
      setLoading(false);
    });
  }, []);

  if (loading) return <LoadingSpinner label="Connecting to backend..." />;

  return (
    <main className="pt-28 pb-20">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="mb-12">
          <h2 className="text-3xl md:text-5xl font-extrabold tracking-tighter mb-4 text-white">
            DASH<span className="text-transparent bg-clip-text bg-gradient-to-r from-indigo-400 to-cyan-400">BOARD</span>
          </h2>
          <div className="flex items-center gap-6 text-sm">
            <div className="flex items-center gap-2">
              <Circle className={`w-2 h-2 ${health?.status === 'ok' ? 'text-emerald-400' : 'text-red-400'}`} fill="currentColor" />
              <span className="font-mono text-slate-400 uppercase tracking-wider text-xs">
                {health?.status === 'ok' ? 'Backend Online' : 'Backend Offline'}
              </span>
            </div>
            <span className="text-slate-600">|</span>
            <span className="font-mono text-slate-400 uppercase tracking-wider text-xs">
              Findings: {findingsCount ?? '—'}
            </span>
            <span className="text-slate-600">|</span>
            <span className="font-mono text-slate-400 uppercase tracking-wider text-xs">
              Tasks: {tasksCount ?? '—'}
            </span>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {tools.map((tool) => (
            <Link
              key={tool.to}
              to={tool.to}
              className="group relative rounded-3xl p-8 bg-white/5 border border-white/10 hover:border-indigo-500/30 transition-all overflow-hidden flex flex-col shadow-lg hover:shadow-indigo-500/10"
            >
              <div className="absolute top-0 right-0 w-48 h-48 bg-indigo-500/5 rounded-full blur-[60px] -translate-y-1/2 translate-x-1/2 group-hover:bg-indigo-500/10 transition-colors" />
              <div className="w-12 h-12 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center mb-6 text-indigo-400 relative z-10">
                <tool.icon className="w-6 h-6" />
              </div>
              <h3 className="text-xl font-bold tracking-tight text-white mb-2 relative z-10">{tool.label}</h3>
              <p className="text-sm text-slate-400 mb-4 relative z-10">{tool.desc}</p>
              <div className="mt-auto flex items-center gap-2 text-xs font-mono tracking-widest uppercase text-indigo-400 group-hover:text-indigo-300 transition-colors relative z-10">
                Open <ArrowRight className="w-3 h-3" />
              </div>
            </Link>
          ))}
        </div>
      </div>
    </main>
  );
}
