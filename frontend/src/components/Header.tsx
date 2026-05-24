import { useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { motion, AnimatePresence } from 'motion/react';
import { Github, Menu, X } from 'lucide-react';

const navItems = [
  { to: '/', label: 'Home' },
  { to: '/dashboard', label: 'Dashboard' },
  { to: '/scan', label: 'Scan' },
  { to: '/agent', label: 'Agent' },
  { to: '/multi-agent', label: 'Multi-Agent' },
  { to: '/runtime', label: 'Runtime' },
  { to: '/mcp', label: 'MCP' },
  { to: '/reports', label: 'Reports' },
];

export function Header() {
  const location = useLocation();
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <motion.header
      initial={{ opacity: 0, y: -20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
      className="fixed top-0 inset-x-0 z-50 border-b border-white/5 bg-black/20 backdrop-blur-md"
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-10 py-4">
        <div className="flex items-center justify-between">
          <Link to="/" className="flex items-center space-x-3">
            <div className="w-8 h-8 bg-indigo-600 rounded-sm flex items-center justify-center transform rotate-45">
              <div className="w-4 h-4 bg-white/80 rounded-full transform -rotate-45" />
            </div>
            <span className="text-xl font-bold tracking-tighter text-white">
              AEGIS<span className="text-indigo-500">NATIVE</span>
            </span>
          </Link>

          <nav className="hidden lg:flex flex-1 justify-center space-x-6 text-xs font-medium tracking-wide">
            {navItems.map((item) => (
              <Link
                key={item.to}
                to={item.to}
                className={`uppercase transition-colors hover:text-white ${
                  location.pathname === item.to ? 'text-indigo-400' : 'text-slate-400'
                }`}
              >
                {item.label}
              </Link>
            ))}
          </nav>

          <div className="flex items-center gap-4">
            <a
              href="https://github.com/makabaga123/aegis-native"
              target="_blank"
              rel="noreferrer"
              className="hidden sm:flex items-center gap-2 px-5 py-2 bg-white text-black text-xs font-bold rounded-full hover:bg-indigo-100 uppercase tracking-widest transition-all"
            >
              <Github className="w-4 h-4" />
              <span>GitHub</span>
            </a>
            <button
              className="lg:hidden text-slate-400 hover:text-white transition-colors"
              onClick={() => setMobileOpen(!mobileOpen)}
            >
              {mobileOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
            </button>
          </div>
        </div>
      </div>

      <AnimatePresence>
        {mobileOpen && (
          <motion.nav
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="lg:hidden border-t border-white/5 bg-black/90 backdrop-blur-md overflow-hidden"
          >
            <div className="px-4 py-4 space-y-2">
              {navItems.map((item) => (
                <Link
                  key={item.to}
                  to={item.to}
                  onClick={() => setMobileOpen(false)}
                  className={`block px-4 py-2 rounded-lg text-sm font-medium uppercase tracking-wide transition-colors ${
                    location.pathname === item.to ? 'text-indigo-400 bg-indigo-500/5' : 'text-slate-400 hover:text-white hover:bg-white/5'
                  }`}
                >
                  {item.label}
                </Link>
              ))}
            </div>
          </motion.nav>
        )}
      </AnimatePresence>
    </motion.header>
  );
}
