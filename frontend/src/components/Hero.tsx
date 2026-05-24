import { Link } from 'react-router-dom';
import { motion } from 'motion/react';
import { ArrowRight, Terminal } from 'lucide-react';

export function Hero() {
  return (
    <section className="relative pt-32 pb-20 lg:pt-48 lg:pb-32 overflow-hidden">
      <div className="absolute top-0 right-1/4 w-[500px] h-[500px] bg-indigo-900/20 rounded-full blur-[120px] mix-blend-screen pointer-events-none" />
      <div className="absolute bottom-0 left-1/4 w-[400px] h-[400px] bg-cyan-900/10 rounded-full blur-[100px] mix-blend-screen pointer-events-none" />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10 text-center">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.1 }}
          className="inline-flex items-center gap-2 px-3 py-1 rounded border border-indigo-500/30 bg-indigo-900/30 text-indigo-400 text-[10px] font-mono tracking-widest uppercase mb-8"
        >
          <span className="flex h-2 w-2 rounded-full bg-indigo-500 animate-pulse" />
          Multi-Agent Security Platform
        </motion.div>

        <motion.h1
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.2 }}
          className="text-5xl md:text-7xl font-extrabold leading-[0.9] tracking-tighter mb-8 text-white"
        >
          Cloud-Native Security,<br />
          <span className="text-transparent bg-clip-text bg-gradient-to-r from-indigo-400 to-cyan-400">
            Powered by AI Agents.
          </span>
        </motion.h1>

        <motion.p
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.3 }}
          className="max-w-2xl mx-auto text-lg md:text-xl text-slate-400 mb-10 leading-relaxed"
        >
          AegisNative provides autonomous, real-time protection for Docker, Kubernetes, and IaC. It fuses eBPF kernel insights with LLM-driven agents to detect, analyze, and neutralize threats.
        </motion.p>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.4 }}
          className="flex flex-col sm:flex-row items-center justify-center gap-4"
        >
          <Link
            to="/dashboard"
            className="flex items-center justify-center gap-2 px-8 py-4 w-full sm:w-auto text-xs font-bold text-black bg-white rounded-full hover:bg-indigo-100 uppercase tracking-widest transition-colors"
          >
            Get Started
            <ArrowRight className="w-4 h-4" />
          </Link>
          <Link
            to="/dashboard"
            className="flex items-center justify-center gap-2 px-8 py-4 w-full sm:w-auto text-xs font-bold text-white bg-white/5 border border-white/10 rounded-full hover:bg-white/10 uppercase tracking-widest transition-colors"
          >
            <Terminal className="w-4 h-4" />
            Open Dashboard
          </Link>
        </motion.div>
      </div>
    </section>
  );
}
