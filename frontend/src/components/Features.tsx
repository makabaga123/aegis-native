import { motion } from "motion/react";
import { Container, Network, Server, Brain, ShieldAlert, Cpu } from "lucide-react";

const features = [
  {
    title: "Runtime eBPF Analysis",
    description: "Deep kernel-level event tracing using Falco and Tetragon for immediate threat neutralization.",
    icon: Network,
    gridClass: "md:col-span-2 md:row-span-2",
  },
  {
    title: "Docker & K8s Native",
    description: "Seamlessly scan Dockerfiles, container images, and Kubernetes manifests (YAML/RBAC).",
    icon: Container,
    gridClass: "md:col-span-1 md:row-span-1",
  },
  {
    title: "Multi-Agent Architecture",
    description: "Specialized agents for K8s, Docker, and Host layers managed by a Supervisory AI.",
    icon: Brain,
    gridClass: "md:col-span-1 md:row-span-1",
  },
  {
    title: "LLM Provider Flexibility",
    description: "Supports DeepSeek, Zhipu GLM, OpenAI, and local processing via Ollama.",
    icon: Cpu,
    gridClass: "md:col-span-1 md:row-span-1",
  },
  {
    title: "IaC & Cloud Config",
    description: "Scan Terraform and cloud configurations for drifts and misconfigurations.",
    icon: Server,
    gridClass: "md:col-span-1 md:row-span-1",
  },
  {
    title: "MCP Tool Layer",
    description: "Flexible Model Context Protocol style tools extending agent capabilities.",
    icon: ShieldAlert,
    gridClass: "md:col-span-2 md:row-span-1",
  },
];

export function Features() {
  return (
    <section id="features" className="py-24 relative overflow-hidden bg-[#080808]">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        <div className="mb-16 md:text-center max-w-3xl mx-auto">
          <h2 className="text-3xl md:text-5xl font-extrabold tracking-tighter mb-4 text-white">
            COMPREHENSIVE <span className="text-transparent bg-clip-text bg-gradient-to-r from-indigo-400 to-cyan-400">DEFENSE</span>
          </h2>
          <p className="text-slate-400 text-lg">
            Covering everything from static infrastructure code to live kernel-level execution.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 md:grid-rows-3 gap-6 auto-rows-[200px]">
          {features.map((feature, idx) => (
            <motion.div
              key={feature.title}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: idx * 0.1 }}
              className={`relative group rounded-3xl p-8 bg-white/5 border border-white/10 hover:border-indigo-500/30 transition-all overflow-hidden flex flex-col justify-end shadow-lg hover:shadow-indigo-500/10 ${feature.gridClass}`}
            >
              <div className="absolute top-0 right-0 w-64 h-64 bg-indigo-500/5 rounded-full blur-[80px] -translate-y-1/2 translate-x-1/2 group-hover:bg-indigo-500/10 transition-colors" />
              
              <div className="mb-auto">
                <div className="w-12 h-12 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center mb-6 text-indigo-400">
                  <feature.icon className="w-6 h-6" />
                </div>
              </div>
              
              <div>
                <h3 className="text-xl font-bold tracking-tight text-white mb-2">{feature.title}</h3>
                <p className="text-sm font-medium text-slate-400 leading-relaxed max-w-[90%]">
                  {feature.description}
                </p>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
