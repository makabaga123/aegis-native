import { useState } from 'react';
import { Workflow, Send } from 'lucide-react';
import { analyzeMulti, analyzeMultiFiles } from '../lib/api';
import { FileUpload } from '../components/ui/FileUpload';
import { CodeBlock } from '../components/ui/CodeBlock';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';

export function MultiAgentAnalysis() {
  const [mode, setMode] = useState<'json' | 'files'>('files');
  const [image, setImage] = useState('');
  const [dockerfile, setDockerfile] = useState<File | null>(null);
  const [k8sYaml, setK8sYaml] = useState<File | null>(null);
  const [terraform, setTerraform] = useState<File | null>(null);
  const [cloudConfig, setCloudConfig] = useState<File | null>(null);
  const [runtimeJson, setRuntimeJson] = useState('');
  const [kernelJson, setKernelJson] = useState('');
  const [result, setResult] = useState<unknown>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function run() {
    setLoading(true); setError(null); setResult(null);
    try {
      if (mode === 'json') {
        const body: Record<string, unknown> = {};
        if (image.trim()) body.image = image.trim();
        if (dockerfile) body.dockerfile_text = await dockerfile.text();
        if (k8sYaml) body.k8s_yaml_text = await k8sYaml.text();
        if (terraform) body.terraform_text = await terraform.text();
        if (cloudConfig) body.cloud_config_text = await cloudConfig.text();
        if (runtimeJson.trim()) { try { body.runtime_events = JSON.parse(runtimeJson); } catch { body.runtime_events = runtimeJson; } }
        if (kernelJson.trim()) { try { body.kernel_events = JSON.parse(kernelJson); } catch { body.kernel_events = kernelJson; } }
        setResult(await analyzeMulti(body));
      } else {
        const fd = new FormData();
        if (image.trim()) fd.append('image', image.trim());
        if (dockerfile) fd.append('dockerfile', dockerfile);
        if (k8sYaml) fd.append('k8s_yaml', k8sYaml);
        if (terraform) fd.append('terraform', terraform);
        if (cloudConfig) fd.append('cloud_config', cloudConfig);
        if (runtimeJson.trim()) fd.append('runtime_events_json', runtimeJson);
        if (kernelJson.trim()) fd.append('kernel_events_json', kernelJson);
        setResult(await analyzeMultiFiles(fd));
      }
    } catch (e) { setError(String(e)); }
    setLoading(false);
  }

  return (
    <main className="pt-28 pb-20">
      <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8">
        <h2 className="text-3xl md:text-5xl font-extrabold tracking-tighter mb-8 text-white">
          MULTI-<span className="text-transparent bg-clip-text bg-gradient-to-r from-indigo-400 to-cyan-400">AGENT</span>
        </h2>
        <p className="text-slate-400 text-sm mb-8 max-w-2xl">
          The Supervisor Agent coordinates specialized sub-agents (K8s, Docker, Host, Cloud, Runtime) to analyze all inputs simultaneously and correlate findings across layers.
        </p>

        <div className="flex gap-2 mb-8">
          {(['files', 'json'] as const).map((m) => (
            <button
              key={m}
              onClick={() => setMode(m)}
              className={`px-5 py-2 rounded-full text-xs font-mono tracking-widest uppercase transition-all
                ${mode === m ? 'bg-white text-black' : 'bg-white/5 border border-white/10 text-slate-400 hover:text-white'}`}
            >
              {m === 'files' ? 'File Upload' : 'JSON Input'}
            </button>
          ))}
        </div>

        <div className="space-y-6 mb-8">
          <div>
            <label className="block text-xs font-mono tracking-widest uppercase text-slate-500 mb-2">Image (optional)</label>
            <input type="text" value={image} onChange={(e) => setImage(e.target.value)} placeholder="nginx:latest"
              className="w-full px-5 py-3 bg-white/5 border border-white/10 rounded-xl text-white font-mono text-sm placeholder:text-slate-600 focus:outline-none focus:border-indigo-500/50" />
          </div>

          {mode === 'files' ? (
            <>
              <FileUpload accept="*" label="Dockerfile (optional)" onFile={setDockerfile} />
              <FileUpload accept=".yaml,.yml" label="Kubernetes YAML (optional)" onFile={setK8sYaml} />
              <FileUpload accept=".tf" label="Terraform (optional)" onFile={setTerraform} />
              <FileUpload accept=".json" label="Cloud Config JSON (optional)" onFile={setCloudConfig} />
            </>
          ) : null}

          <div>
            <label className="block text-xs font-mono tracking-widest uppercase text-slate-500 mb-2">Runtime Events JSON (optional)</label>
            <textarea rows={3} value={runtimeJson} onChange={(e) => setRuntimeJson(e.target.value)} placeholder='[{"event_type":"execve",...}]'
              className="w-full px-5 py-3 bg-white/5 border border-white/10 rounded-xl text-white font-mono text-sm placeholder:text-slate-600 focus:outline-none focus:border-indigo-500/50 resize-y" />
          </div>

          <div>
            <label className="block text-xs font-mono tracking-widest uppercase text-slate-500 mb-2">Kernel Events JSON (optional)</label>
            <textarea rows={3} value={kernelJson} onChange={(e) => setKernelJson(e.target.value)} placeholder='[{"event_type":"shell",...}]'
              className="w-full px-5 py-3 bg-white/5 border border-white/10 rounded-xl text-white font-mono text-sm placeholder:text-slate-600 focus:outline-none focus:border-indigo-500/50 resize-y" />
          </div>

          <button
            onClick={run} disabled={loading}
            className="flex items-center gap-2 px-8 py-4 bg-white text-black text-xs font-bold rounded-full hover:bg-indigo-100 uppercase tracking-widest transition-all disabled:opacity-30"
          >
            <Send className="w-4 h-4" /> Run Multi-Agent Analysis
          </button>
        </div>

        {loading && <LoadingSpinner label="Supervisor analyzing..." />}
        {error && <div className="p-4 rounded-xl bg-red-500/5 border border-red-500/20 text-red-400 font-mono text-sm">{error}</div>}
        {result && <CodeBlock code={JSON.stringify(result, null, 2)} language="result" />}
      </div>
    </main>
  );
}
