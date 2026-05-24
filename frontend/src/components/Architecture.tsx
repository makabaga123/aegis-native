import { motion } from "motion/react";
import { Workflow, Layers, ShieldCheck } from "lucide-react";

export function Architecture() {
  return (
    <section id="architecture" className="py-24 relative overflow-hidden bg-black/20 border-y border-white/5">
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,rgba(99,102,241,0.05),transparent_50%)] pointer-events-none" />
      
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        <div className="grid md:grid-cols-2 gap-16 items-center">
          
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5 }}
          >
            <h2 className="text-3xl md:text-5xl font-extrabold tracking-tighter mb-6 text-white">
              AUTONOMOUS THREAT <span className="text-transparent bg-clip-text bg-gradient-to-r from-indigo-400 to-cyan-400">REMEDIATION</span>
            </h2>
            <p className="text-slate-400 text-lg mb-8 leading-relaxed">
              AegisNative uses a hierarchical agentic architecture. The Supervisory Agent coordinates specialized sub-agents to analyze context from eBPF, Docker, and IaC sources, ensuring precise threat detection and automated response.
            </p>

            <ul className="space-y-6">
              {[
                {
                  icon: Layers,
                  title: "Context-Aware Telemetry",
                  desc: "Aggregates signals from standard K8s apiserver, container runtimes, and deep kernel traces."
                },
                {
                  icon: Workflow,
                  title: "MCP Tooling Framework",
                  desc: "Agents dynamically select tools (grep, kubectl, docker inspect) via the Model Context Protocol."
                },
                {
                  icon: ShieldCheck,
                  title: "Actionable Insights",
                  desc: "Outputs clear remediation steps, YAML patches, or direct alerts to security operations teams."
                }
              ].map((item, i) => (
                <li key={i} className="flex gap-4">
                  <div className="flex-shrink-0 mt-1">
                    <div className="w-10 h-10 rounded-lg bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400">
                      <item.icon className="w-5 h-5" />
                    </div>
                  </div>
                  <div>
                    <h4 className="text-white font-semibold mb-1">{item.title}</h4>
                    <p className="text-slate-400 text-sm leading-relaxed">{item.desc}</p>
                  </div>
                </li>
              ))}
            </ul>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, x: 20 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5, delay: 0.2 }}
            className="relative"
          >
            <div className="absolute inset-0 bg-gradient-to-tr from-indigo-600/20 to-blue-700/20 blur-3xl opacity-50" />
            <div className="relative rounded-3xl border border-white/10 bg-white/5 backdrop-blur-sm p-8 shadow-2xl shadow-indigo-500/40">
              <div className="space-y-4">
                <div className="p-4 rounded-xl bg-black/60 border border-white/10 flex items-center gap-4">
                  <div className="w-3 h-3 rounded-full bg-emerald-500 shadow-[0_0_10px_rgba(16,185,129,0.5)]" />
                  <span className="font-mono text-xs tracking-widest uppercase text-emerald-400">Supervisory Agent Active</span>
                </div>
                <div className="pl-8 border-l border-white/10 space-y-4">
                  <div className="p-4 rounded-xl bg-black/60 border border-white/10 text-slate-300 text-sm leading-relaxed">
                    <span className="text-indigo-400 font-mono text-[10px] tracking-widest uppercase block mb-1">K8s Agent</span>
                    Analyzing suspicious RBAC RoleBinding...
                  </div>
                  <div className="p-4 rounded-xl bg-black/60 border border-white/10 text-slate-300 text-sm leading-relaxed">
                    <span className="text-indigo-400 font-mono text-[10px] tracking-widest uppercase block mb-1">Host Agent</span>
                    Falco triggered Rule "Write below etc". Correlating pid 14032.
                  </div>
                  <div className="p-4 rounded-xl bg-black/60 border border-white/10 text-slate-300 text-sm leading-relaxed">
                    <span className="text-indigo-400 font-mono text-[10px] tracking-widest uppercase block mb-1">Docker Agent</span>
                    Identifying related container layers and image CVEs...
                  </div>
                </div>
              </div>
            </div>
          </motion.div>

        </div>
      </div>
    </section>
  );
}
