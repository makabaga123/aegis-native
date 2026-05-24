import { Routes, Route } from 'react-router-dom';
import { Header } from './components/Header';
import { Footer } from './components/Footer';
import { Landing } from './pages/Landing';
import { Dashboard } from './pages/Dashboard';
import { ScanHub } from './pages/ScanHub';
import { RuntimeTimeline } from './pages/RuntimeTimeline';
import { AgentAnalysis } from './pages/AgentAnalysis';
import { MultiAgentAnalysis } from './pages/MultiAgentAnalysis';
import { McpTools } from './pages/McpTools';
import { Reports } from './pages/Reports';

export default function App() {
  return (
    <div className="min-h-screen bg-[#080808]">
      <Header />
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/scan" element={<ScanHub />} />
        <Route path="/runtime" element={<RuntimeTimeline />} />
        <Route path="/agent" element={<AgentAnalysis />} />
        <Route path="/multi-agent" element={<MultiAgentAnalysis />} />
        <Route path="/mcp" element={<McpTools />} />
        <Route path="/reports" element={<Reports />} />
      </Routes>
      <Footer />
    </div>
  );
}
