import { useState } from 'react';
import { Copy, Check } from 'lucide-react';

export function CodeBlock({ code, language = 'json' }: { code: string; language?: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="rounded-xl overflow-hidden shadow-2xl border border-white/10 bg-black/60 backdrop-blur-sm">
      <div className="flex items-center justify-between px-4 py-3 bg-white/5 border-b border-white/10">
        <div className="flex gap-2">
          <div className="w-3 h-3 rounded-full bg-red-500/80" />
          <div className="w-3 h-3 rounded-full bg-yellow-500/80" />
          <div className="w-3 h-3 rounded-full bg-green-500/80" />
        </div>
        <div className="flex items-center gap-3">
          <span className="text-[10px] font-mono tracking-widest text-slate-500 uppercase">{language}</span>
          <button onClick={handleCopy} className="text-slate-500 hover:text-white transition-colors">
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
          </button>
        </div>
      </div>
      <div className="p-4 overflow-x-auto max-h-96 overflow-y-auto">
        <pre className="font-mono text-xs leading-relaxed text-slate-300 whitespace-pre-wrap">{code}</pre>
      </div>
    </div>
  );
}
