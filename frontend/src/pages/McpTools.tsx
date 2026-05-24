import { useEffect, useState } from 'react';
import { Terminal, Play, ChevronDown, ChevronRight } from 'lucide-react';
import { listMcpTools, callMcpTool } from '../lib/api';
import { CodeBlock } from '../components/ui/CodeBlock';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import { EmptyState } from '../components/ui/EmptyState';

interface ToolDef {
  name: string;
  description?: string;
  parameters?: Record<string, unknown>;
}

export function McpTools() {
  const [tools, setTools] = useState<ToolDef[]>([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [results, setResults] = useState<Record<string, unknown>>({});
  const [running, setRunning] = useState<Set<string>>(new Set());

  useEffect(() => {
    listMcpTools()
      .then((r) => setTools((r as { tools?: ToolDef[] }).tools || (r as ToolDef[])))
      .catch(() => setTools([]))
      .finally(() => setLoading(false));
  }, []);

  const toggle = (name: string) => {
    const next = new Set(expanded);
    next.has(name) ? next.delete(name) : next.add(name);
    setExpanded(next);
  };

  async function execute(tool: ToolDef) {
    const runningSet = new Set(running);
    runningSet.add(tool.name);
    setRunning(runningSet);
    try {
      const r = await callMcpTool(tool.name, {});
      setResults((prev) => ({ ...prev, [tool.name]: r }));
    } catch (e) {
      setResults((prev) => ({ ...prev, [tool.name]: { error: String(e) } }));
    }
    runningSet.delete(tool.name);
    setRunning(runningSet);
  }

  return (
    <main className="pt-28 pb-20">
      <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8">
        <h2 className="text-3xl md:text-5xl font-extrabold tracking-tighter mb-8 text-white">
          MCP <span className="text-transparent bg-clip-text bg-gradient-to-r from-indigo-400 to-cyan-400">TOOLS</span>
        </h2>

        {loading ? <LoadingSpinner label="Loading tools..." />
        : tools.length === 0 ? <EmptyState title="No MCP tools available" desc="Check that the backend is running and the MCP server is initialized." />
        : (
          <div className="space-y-3">
            {tools.map((tool) => (
              <div key={tool.name} className="rounded-xl bg-white/5 border border-white/10 overflow-hidden">
                <div className="flex items-center gap-3 p-5">
                  <button onClick={() => toggle(tool.name)} className="text-slate-500 hover:text-white">
                    {expanded.has(tool.name) ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                  </button>
                  <Terminal className="w-4 h-4 text-indigo-400" />
                  <div className="flex-1">
                    <span className="font-mono text-sm text-white">{tool.name}</span>
                    {tool.description && <p className="text-xs text-slate-500 mt-0.5">{tool.description}</p>}
                  </div>
                  <button
                    onClick={() => execute(tool)}
                    disabled={running.has(tool.name)}
                    className="flex items-center gap-2 px-4 py-2 bg-indigo-500/10 border border-indigo-500/20 rounded-full text-xs font-mono tracking-widest uppercase text-indigo-400 hover:bg-indigo-500/20 transition-all disabled:opacity-30"
                  >
                    <Play className="w-3 h-3" /> {running.has(tool.name) ? 'Running...' : 'Execute'}
                  </button>
                </div>
                {expanded.has(tool.name) && (
                  <div className="px-5 pb-5 border-t border-white/5 pt-4 space-y-3">
                    {tool.parameters && (
                      <div>
                        <span className="text-[10px] font-mono tracking-widest uppercase text-slate-500 block mb-2">Parameters</span>
                        <CodeBlock code={JSON.stringify(tool.parameters, null, 2)} language="schema" />
                      </div>
                    )}
                    {results[tool.name] !== undefined && (
                      <div>
                        <span className="text-[10px] font-mono tracking-widest uppercase text-slate-500 block mb-2">Result</span>
                        <CodeBlock code={JSON.stringify(results[tool.name], null, 2)} language="result" />
                      </div>
                    )}
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
