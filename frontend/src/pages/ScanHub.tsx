import { useState } from 'react';
import { Container, FileCode, Search } from 'lucide-react';
import { scanImage, scanDockerfile, scanK8sYaml } from '../lib/api';
import { FileUpload } from '../components/ui/FileUpload';
import { CodeBlock } from '../components/ui/CodeBlock';
import { Badge } from '../components/ui/Badge';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';

type Tab = 'dockerfile' | 'image' | 'k8s';

interface Finding {
  severity?: string;
  title?: string;
  description?: string;
  rule_id?: string;
}

interface ScanResult {
  task_id: number;
  target: string;
  summary: Record<string, unknown>;
  findings: Finding[];
}

export function ScanHub() {
  const [tab, setTab] = useState<Tab>('dockerfile');
  const [imageName, setImageName] = useState('');
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function runImageScan() {
    if (!imageName.trim()) return;
    setLoading(true); setError(null); setResult(null);
    try {
      const r = await scanImage(imageName.trim()) as ScanResult;
      setResult(r);
    } catch (e) { setError(String(e)); }
    setLoading(false);
  }

  async function runFileScan(file: File) {
    setLoading(true); setError(null); setResult(null);
    try {
      const r = tab === 'dockerfile' ? await scanDockerfile(file) as ScanResult : await scanK8sYaml(file) as ScanResult;
      setResult(r);
    } catch (e) { setError(String(e)); }
    setLoading(false);
  }

  const tabs: { key: Tab; label: string; icon: typeof FileCode }[] = [
    { key: 'dockerfile', label: 'Dockerfile', icon: FileCode },
    { key: 'image', label: 'Image (Trivy)', icon: Container },
    { key: 'k8s', label: 'K8s YAML', icon: Search },
  ];

  return (
    <main className="pt-28 pb-20">
      <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8">
        <h2 className="text-3xl md:text-5xl font-extrabold tracking-tighter mb-8 text-white">
          SCAN <span className="text-transparent bg-clip-text bg-gradient-to-r from-indigo-400 to-cyan-400">HUB</span>
        </h2>

        <div className="flex gap-2 mb-8 border-b border-white/5 pb-0">
          {tabs.map((t) => (
            <button
              key={t.key}
              onClick={() => { setTab(t.key); setResult(null); setError(null); }}
              className={`flex items-center gap-2 px-5 py-3 rounded-t-xl text-sm font-mono tracking-wider uppercase transition-all
                ${tab === t.key ? 'bg-white/5 border border-white/10 border-b-transparent text-white' : 'text-slate-500 hover:text-slate-300'}`}
            >
              <t.icon className="w-4 h-4" /> {t.label}
            </button>
          ))}
        </div>

        <div className="mb-8">
          {tab === 'image' ? (
            <div className="flex gap-4">
              <input
                type="text"
                value={imageName}
                onChange={(e) => setImageName(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && runImageScan()}
                placeholder="e.g. nginx:latest"
                className="flex-1 px-5 py-4 bg-white/5 border border-white/10 rounded-xl text-white font-mono text-sm placeholder:text-slate-600 focus:outline-none focus:border-indigo-500/50 transition-colors"
              />
              <button
                onClick={runImageScan}
                disabled={loading || !imageName.trim()}
                className="px-8 py-4 bg-white text-black text-xs font-bold rounded-xl hover:bg-indigo-100 uppercase tracking-widest transition-all disabled:opacity-30 disabled:cursor-not-allowed"
              >
                Scan
              </button>
            </div>
          ) : (
            <FileUpload
              accept={tab === 'k8s' ? '.yaml,.yml' : '*'}
              label={`Upload ${tab === 'dockerfile' ? 'a Dockerfile' : 'a Kubernetes YAML'} to scan`}
              onFile={runFileScan}
            />
          )}
        </div>

        {loading && <LoadingSpinner label="Scanning..." />}

        {error && (
          <div className="p-4 rounded-xl bg-red-500/5 border border-red-500/20 text-red-400 font-mono text-sm">{error}</div>
        )}

        {result && (
          <div className="space-y-6">
            <div className="flex items-center gap-4 text-sm">
              <span className="font-mono text-slate-400 uppercase tracking-wider text-xs">
                Task #{result.task_id} — {result.target}
              </span>
            </div>
            <div className="space-y-3">
              {result.findings.map((f, i) => (
                <div key={i} className="p-5 rounded-xl bg-white/5 border border-white/10 hover:border-indigo-500/20 transition-all">
                  <div className="flex items-start justify-between gap-4 mb-2">
                    <h4 className="text-white font-semibold text-sm">{f.title || f.rule_id || 'Finding'}</h4>
                    {f.severity && <Badge label={f.severity} />}
                  </div>
                  {f.description && <p className="text-slate-400 text-xs leading-relaxed">{f.description}</p>}
                </div>
              ))}
            </div>
            {result.summary && <CodeBlock code={JSON.stringify(result.summary, null, 2)} language="summary" />}
          </div>
        )}
      </div>
    </main>
  );
}
