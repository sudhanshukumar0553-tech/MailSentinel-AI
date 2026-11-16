import React from "react";
import { ShieldAlert, Loader2 } from "lucide-react";
import { useTheme } from "../context/ThemeContext";

export const LoadingScreen: React.FC = () => {
  const { isDark } = useTheme();

  return (
    <div
      className={`min-h-screen flex flex-col items-center justify-center p-6 relative overflow-hidden transition-colors duration-200 ${
        isDark ? "bg-[#080D1A] text-slate-100" : "bg-slate-50 text-slate-900"
      }`}
    >
      {/* Animated Aurora Glow Accents */}
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-cyan-500/15 rounded-full blur-3xl pointer-events-none animate-pulse" />
      <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-purple-500/15 rounded-full blur-3xl pointer-events-none animate-pulse" />

      <div className="relative z-10 flex flex-col items-center text-center space-y-4 max-w-sm animate-fade-in">
        <div className="w-16 h-16 rounded-2xl bg-gradient-to-tr from-purple-600 via-indigo-600 to-cyan-500 flex items-center justify-center shadow-[0_0_35px_rgba(6,182,212,0.45)]">
          <ShieldAlert className="w-9 h-9 text-white animate-pulse" />
        </div>
        <div>
          <h1 className="text-xl font-bold tracking-wide bg-gradient-to-r from-white via-cyan-200 to-cyan-400 bg-clip-text text-transparent">
            MailSentinel AI
          </h1>
          <p className="text-[11px] font-mono uppercase tracking-widest text-cyan-400/80 mt-1">
            SOC Defense Platform
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs font-mono text-slate-400 pt-2">
          <Loader2 className="w-4 h-4 animate-spin text-cyan-400" />
          <span>Initializing Zero-Trust Security Gate...</span>
        </div>
      </div>
    </div>
  );
};
