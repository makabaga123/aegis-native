export function Footer() {
  return (
    <footer className="border-t border-white/5 bg-black/40 pt-16 pb-8">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-12 mb-12">
          <div className="md:col-span-2">
            <div className="flex items-center gap-3 mb-6">
              <div className="w-6 h-6 bg-indigo-600 rounded-sm flex items-center justify-center transform rotate-45">
                <div className="w-3 h-3 bg-white/80 rounded-full transform -rotate-45"></div>
              </div>
              <span className="text-lg font-bold tracking-tighter text-white">
                AEGIS<span className="text-indigo-500">NATIVE</span>
              </span>
            </div>
            <p className="text-slate-400 text-sm leading-relaxed max-w-sm">
              A multi-agent cloud-native security platform for Docker, Kubernetes, IaC, cloud config and runtime eBPF event analysis.
            </p>
          </div>
          <div>
            <h4 className="text-white font-medium mb-4 text-[10px] tracking-widest uppercase">Resources</h4>
            <ul className="space-y-3 text-xs text-slate-400">
              <li><a href="https://github.com/makabaga123/aegis-native" target="_blank" rel="noreferrer" className="hover:text-white transition-colors">GitHub Repository</a></li>
              <li><a href="#features" className="hover:text-white transition-colors">Features</a></li>
              <li><a href="#architecture" className="hover:text-white transition-colors">Architecture</a></li>
            </ul>
          </div>
          <div>
            <h4 className="text-white font-medium mb-4 text-[10px] tracking-widest uppercase">Community</h4>
            <ul className="space-y-3 text-xs text-slate-400">
              <li><a href="https://github.com/makabaga123/aegis-native/issues" target="_blank" rel="noreferrer" className="hover:text-white transition-colors">Issues</a></li>
              <li><a href="https://github.com/makabaga123/aegis-native/pulls" target="_blank" rel="noreferrer" className="hover:text-white transition-colors">Pull Requests</a></li>
              <li><a href="https://github.com/makabaga123/aegis-native/graphs/contributors" target="_blank" rel="noreferrer" className="hover:text-white transition-colors">Contributors</a></li>
            </ul>
          </div>
        </div>
        <div className="pt-8 border-t border-white/5 flex flex-col md:flex-row justify-between items-center text-[10px] tracking-[0.2em] font-medium text-slate-500 uppercase">
          <div className="flex flex-col sm:flex-row items-center gap-6 mb-4 md:mb-0">
            <div className="flex items-center gap-2 italic">
              <span className="w-1.5 h-1.5 bg-emerald-500 rounded-full animate-pulse"></span>
              <span>SYSTEM CLUSTER ACTIVE</span>
            </div>
            <span>NODE ID: AEGIS-77B-NORTH</span>
          </div>
          <div className="flex gap-6">
            <span className="text-indigo-400">&copy; {new Date().getFullYear()} AEGIS NATIVE FOUNDATION</span>
          </div>
        </div>
      </div>
    </footer>
  );
}
