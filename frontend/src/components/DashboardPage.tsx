import React, { useEffect, useState } from "react";
import {
  ShieldAlert,
  ShieldCheck,
  Flame,
  Bug,
  Globe,
  TrendingUp,
  RefreshCw
} from "lucide-react";
import { api } from "../api/client";
import { useTheme } from "../context/ThemeContext";
import type { AnalyticsOverview } from "../types";
import { formatIST } from "../utils/dateFormatter";

export const DashboardPage: React.FC = () => {
  const { isDark } = useTheme();
  const [data, setData] = useState<AnalyticsOverview | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchAnalytics = async () => {
    setLoading(true);
    try {
      const res = await api.getAnalytics();
      setData(res);
    } catch (err) {
      console.error("Failed to load analytics:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAnalytics();
  }, []);

  if (loading || !data) {
    return (
      <div className={`flex flex-col items-center justify-center min-h-[300px] space-y-3 ${isDark ? "text-slate-400" : "text-slate-600"}`}>
        <div className="w-8 h-8 border-2 border-cyan-500/20 border-t-cyan-500 rounded-full animate-spin"></div>
        <span className="text-xs font-mono">Aggregating Security Analytics...</span>
      </div>
    );
  }

  const statCards = [
    {
      title: "Total Emails Scanned",
      value: data.total_scans,
      icon: ShieldCheck,
      color: isDark ? "text-cyan-400" : "text-sky-600",
      border: isDark ? "border-cyan-500/20" : "border-sky-200",
      bg: isDark ? "bg-cyan-950/20" : "bg-sky-50/50"
    },
    {
      title: "Threats Neutralized",
      value: data.threats_blocked,
      icon: ShieldAlert,
      color: "text-rose-500",
      border: isDark ? "border-rose-500/20" : "border-rose-200",
      bg: isDark ? "bg-rose-950/20" : "bg-rose-50/50"
    },
    {
      title: "Phishing Campaigns",
      value: data.phishing_detected,
      icon: Flame,
      color: "text-orange-500",
      border: isDark ? "border-orange-500/20" : "border-orange-200",
      bg: isDark ? "bg-orange-950/20" : "bg-orange-50/50"
    },
    {
      title: "Spam Bulk Junk",
      value: data.spam_detected,
      icon: Bug,
      color: "text-amber-500",
      border: isDark ? "border-amber-500/20" : "border-amber-200",
      bg: isDark ? "bg-amber-950/20" : "bg-amber-50/50"
    },
    {
      title: "Malicious URLs Intercepted",
      value: data.malicious_urls_intercepted,
      icon: Globe,
      color: "text-purple-500",
      border: isDark ? "border-purple-500/20" : "border-purple-200",
      bg: isDark ? "bg-purple-950/20" : "bg-purple-50/50"
    },
    {
      title: "Average Risk Score",
      value: `${data.average_risk_score} / 100`,
      icon: TrendingUp,
      color: "text-indigo-500",
      border: isDark ? "border-indigo-500/20" : "border-indigo-200",
      bg: isDark ? "bg-indigo-950/20" : "bg-indigo-50/50"
    }
  ];

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1
            className={`text-2xl font-bold flex items-center gap-2 ${
              isDark ? "text-white" : "text-slate-900 font-extrabold"
            }`}
          >
            <ShieldAlert className={`w-7 h-7 ${isDark ? "text-cyan-400" : "text-sky-600"}`} />
            Security Analytics & Telemetry
          </h1>
          <p className={`text-sm ${isDark ? "text-slate-400" : "text-slate-600"}`}>
            Real-time cybersecurity threat telemetry and email classification metrics.
          </p>
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          <span className={`text-[11px] font-mono px-2.5 py-1 rounded border ${
            isDark ? "bg-slate-900 border-slate-800 text-slate-400" : "bg-white border-slate-200 text-slate-600 shadow-xs"
          }`}>
            Telemetry Synced: <strong className={isDark ? "text-cyan-400" : "text-sky-700"}>{formatIST(data.synced_at || new Date())}</strong>
          </span>

          <button
            onClick={fetchAnalytics}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs font-mono transition-colors cursor-pointer ${
              isDark
                ? "bg-slate-900 border-slate-800 hover:border-cyan-500/40 text-slate-300 hover:text-cyan-300"
                : "bg-white border-slate-200 hover:border-sky-400 text-slate-700 hover:text-sky-700 shadow-xs"
            }`}
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Refresh Data</span>
          </button>
        </div>
      </div>

      {/* 6 Key Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {statCards.map((card, idx) => {
          const Icon = card.icon;
          return (
            <div
              key={idx}
              className={`p-5 rounded-xl border ${card.border} ${card.bg} flex items-center justify-between shadow-lg transition-all cyber-card-hover ${
                isDark ? "bg-[#0E1726]/80" : "bg-white"
              }`}
            >
              <div>
                <span className={`text-xs font-mono uppercase tracking-wider block mb-1 ${isDark ? "text-slate-400" : "text-slate-500"}`}>
                  {card.title}
                </span>
                <span className={`text-2xl font-black font-mono ${card.color}`}>
                  {card.value}
                </span>
              </div>
              <div
                className={`p-3 rounded-lg border ${
                  isDark ? "bg-slate-900/80 border-slate-800" : "bg-slate-100 border-slate-200"
                } ${card.color}`}
              >
                <Icon className="w-6 h-6" />
              </div>
            </div>
          );
        })}
      </div>

      {/* Threat Distribution Chart Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Severity Distribution Bars */}
        <div
          className={`lg:col-span-8 rounded-xl p-6 border space-y-6 transition-colors ${
            isDark ? "bg-[#0E1726]/80 border-slate-800" : "bg-white border-slate-200 shadow-xs"
          }`}
        >
          <h2
            className={`text-sm font-semibold uppercase font-mono tracking-wider ${
              isDark ? "text-cyan-400" : "text-sky-700 font-bold"
            }`}
          >
            Threat Severity Distribution
          </h2>

          <div className="space-y-4">
            {data.threat_distribution.map((dist, idx) => {
              const percentage = data.total_scans > 0 ? (dist.count / data.total_scans) * 100 : 0;
              return (
                <div key={idx} className="space-y-1.5">
                  <div className="flex items-center justify-between text-xs font-mono">
                    <span className={isDark ? "text-slate-300 font-medium" : "text-slate-700 font-medium"}>
                      {dist.tier}
                    </span>
                    <span className={isDark ? "text-slate-400" : "text-slate-500"}>
                      {dist.count} emails ({percentage.toFixed(1)}%)
                    </span>
                  </div>
                  <div
                    className={`w-full h-3 rounded-full overflow-hidden border ${
                      isDark ? "bg-slate-900 border-slate-800" : "bg-slate-100 border-slate-200"
                    }`}
                  >
                    <div
                      className="h-full rounded-full transition-all duration-500"
                      style={{
                        width: `${Math.max(percentage, 2)}%`,
                        backgroundColor: dist.color
                      }}
                    ></div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Threat Level Quick Legend */}
        <div
          className={`lg:col-span-4 rounded-xl p-6 border space-y-4 transition-colors ${
            isDark ? "bg-[#0E1726]/80 border-slate-800" : "bg-white border-slate-200 shadow-xs"
          }`}
        >
          <h2
            className={`text-sm font-semibold uppercase font-mono tracking-wider ${
              isDark ? "text-purple-400" : "text-purple-700 font-bold"
            }`}
          >
            Threat Severity Matrix
          </h2>

          <div className="space-y-3 text-xs">
            <div
              className={`severity-card severity-card-critical p-2.5 rounded border cursor-default ${
                isDark
                  ? "bg-rose-950/40 border-rose-500/30 text-rose-300"
                  : "bg-rose-50 border-rose-200 text-rose-800"
              }`}
            >
              <strong className="block font-mono text-rose-500">CRITICAL (86 - 100)</strong>
              Confirmed malicious phishing attacks, spoofed credentials, or malware delivery vectors.
            </div>

            <div
              className={`severity-card severity-card-dangerous p-2.5 rounded border cursor-default ${
                isDark
                  ? "bg-orange-950/40 border-orange-500/30 text-orange-300"
                  : "bg-orange-50 border-orange-200 text-orange-800"
              }`}
            >
              <strong className="block font-mono text-orange-500">DANGEROUS (61 - 85)</strong>
              High-risk deceptive content, obfuscated URLs, or aggressive financial coercion.
            </div>

            <div
              className={`severity-card severity-card-suspicious p-2.5 rounded border cursor-default ${
                isDark
                  ? "bg-amber-950/40 border-amber-500/30 text-amber-300"
                  : "bg-amber-50 border-amber-200 text-amber-800"
              }`}
            >
              <strong className="block font-mono text-amber-500">SUSPICIOUS (26 - 60)</strong>
              Commercial bulk junk, aggressive marketing leads, or unverified link patterns.
            </div>

            <div
              className={`severity-card severity-card-safe p-2.5 rounded border cursor-default ${
                isDark
                  ? "bg-emerald-950/40 border-emerald-500/30 text-emerald-300"
                  : "bg-emerald-50 border-emerald-200 text-emerald-800"
              }`}
            >
              <strong className="block font-mono text-emerald-500">SAFE (0 - 25)</strong>
              Legitimate, authenticated internal and business communications.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
