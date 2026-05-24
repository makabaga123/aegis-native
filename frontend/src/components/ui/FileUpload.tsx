import { useCallback, useState, type DragEvent, type ChangeEvent } from 'react';
import { Upload, FileText } from 'lucide-react';

export function FileUpload({ onFile, accept = '*', label = 'Drop a file here or click to browse' }: {
  onFile: (f: File) => void;
  accept?: string;
  label?: string;
}) {
  const [drag, setDrag] = useState(false);
  const [fileName, setFileName] = useState<string | null>(null);

  const handleDrop = useCallback((e: DragEvent) => {
    e.preventDefault(); setDrag(false);
    const f = e.dataTransfer.files[0];
    if (f) { setFileName(f.name); onFile(f); }
  }, [onFile]);

  const handleChange = (e: ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (f) { setFileName(f.name); onFile(f); }
  };

  return (
    <div
      onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
      onDragLeave={() => setDrag(false)}
      onDrop={handleDrop}
      className={`relative group rounded-2xl border-2 border-dashed p-8 text-center transition-all cursor-pointer
        ${drag ? 'border-indigo-400 bg-indigo-500/5' : 'border-white/10 hover:border-indigo-500/30 bg-white/[0.02]'}`}
    >
      <input type="file" accept={accept} onChange={handleChange} className="absolute inset-0 opacity-0 cursor-pointer" />
      {fileName ? (
        <div className="flex items-center justify-center gap-3 text-slate-300">
          <FileText className="w-6 h-6 text-indigo-400" />
          <span className="font-mono text-sm">{fileName}</span>
        </div>
      ) : (
        <div className="flex flex-col items-center gap-3 text-slate-500">
          <Upload className="w-8 h-8 group-hover:text-indigo-400 transition-colors" />
          <span className="text-sm font-medium">{label}</span>
        </div>
      )}
    </div>
  );
}
