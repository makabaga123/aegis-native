import { motion } from "motion/react";
import { TerminalSquare, ShieldAlert, Cpu } from "lucide-react";

export function CodeDemo() {
  const codeSnippet = `# Start multi-agent analysis via CLI
python aegis_cli.py analyze --target my-k8s-deployment.yaml

# Expected Output:
# [Supervisory] Analyzing target context...
# [K8s Agent] Found privileged container execution risk.
# [Docker Agent] Image ubuntu:latest has 3 critical CVEs.
# [Resolution] Applied least-privilege pod security context.`;

  return (
    <section id="code-demo" className="py-24 relative overflow-hidden bg-[#080808]">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        <div className="mb-16 md:text-center max-w-3xl mx-auto">
          <h2 className="text-3xl md:text-5xl font-extrabold tracking-tighter mb-4 text-white uppercase">
            DEVELOPER <span className="text-indigo-500">READY</span>
          </h2>
          <p className="text-slate-400 text-lg">
            Integrate AegisNative directly into your CI/CD pipelines or run standalone analysis via Python CLI and API.
          </p>
        </div>

        <div className="max-w-4xl mx-auto rounded-xl overflow-hidden shadow-2xl border border-white/10 bg-black/60 backdrop-blur-sm">
          <div className="flex items-center justify-between px-4 py-3 bg-white/5 border-b border-white/10">
            <div className="flex gap-2">
              <div className="w-3 h-3 rounded-full bg-red-500/80" />
              <div className="w-3 h-3 rounded-full bg-yellow-500/80" />
              <div className="w-3 h-3 rounded-full bg-green-500/80" />
            </div>
            <div className="text-[10px] font-mono tracking-widest text-slate-500 uppercase">bash</div>
          </div>
          <div className="p-6 overflow-x-auto">
            <pre className="font-mono text-sm leading-loose text-slate-300">
              <code>
                <span className="text-indigo-400"># Start multi-agent analysis via CLI</span>
                <br />
                <span className="text-cyan-400">python</span> aegis_cli.py analyze --target my-k8s-deployment.yaml
                <br />
                <br />
                <span className="text-indigo-400"># Expected Output:</span>
                <br />
                <span className="text-slate-500"># [Supervisory] Analyzing target context...</span>
                <br />
                <span className="text-slate-500"># [K8s Agent] Found privileged container execution risk.</span>
                <br />
                <span className="text-slate-500"># [Docker Agent] Image ubuntu:latest has 3 critical CVEs.</span>
                <br />
                <span className="text-emerald-400"># [Resolution] Applied least-privilege pod security context.</span>
              </code>
            </pre>
          </div>
        </div>
      </div>
    </section>
  );
}
