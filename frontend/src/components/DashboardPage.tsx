import React, { useEffect, useState, useCallback, useRef } from "react";
import {
  ShieldAlert,
  ShieldCheck,
  Flame,
  Bug,
  Globe,
  TrendingUp,
  RefreshCw,
  AlertCircle,
  Inbox
} from "lucide-react";
import { api } from "../api/client";
import { useTheme } from "../context/ThemeContext";
import type { AnalyticsOverview } from "../types";
import { formatIST } from "../utils/dateFormatter";

const EMPTY_ANALYTICS: AnalyticsOverview = {
  total_scans: 0,
  clean_emails: 0,
  threats_blocked: 0,
  phishing_detected: 0,
  spam_detected: 0,
  malicious_urls_intercepted: 0,
  average_risk_score: 0.0,
  synced_at: new Date().toISOString(),
  threat_distribution: [
    { tier: "Safe", count: 0, color: "#10B981" },
    { tier: "Suspicious", count: 0, color: "#F59E0B" },
    { tier: "Dangerous", count: 0, color: "#F97316" },
    { tier: "Critical", count: 0, color: "#EF4444" }
  ]
};

export const DashboardPage: React.FC = () => {
  const { isDark } = useTheme();
  const [data, setData] = useState<AnalyticsOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const fetchTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const fetchAnalytics = useCallback(async () => {
    setLoading(true);
    setError(null);

    // Guard with 12s safety timeout to guarantee loading state never hangs indefinitely
    if (fetchTimeoutRef.current) {
      clearTimeout(fetchTimeoutRef.current);
    }
    fetchTimeoutRef.current = setTimeout(() => {
      setLoading(false);
      setError((prev) => prev || "Analytics aggregation timed out after 12s. Please check backend connection.");
    }, 12000);

    try {
      const res = await api.getAnalytics();
      if (fetchTimeoutRef.current) clearTimeout(fetchTimeoutRef.current);
      setData(res);
      setError(null);
    } catch (err: any) {
      if (fetchTimeoutRef.current) clearTimeout(fetchTimeoutRef.current);
      console.error("Failed to load analytics:", err);
      setError(err?.message || "Failed to aggregate security analytics.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAnalytics();
    return () => {
      if (fetchTimeoutRef.current) clearTimeout(fetchTimeoutRef.current);
    };
  }, [fetchAnalytics]);

  // Loading State
  if (loading && !data) {
    return (
      <div className={`flex flex-col items-center justify-center min-h-[360px] space-y-4 ${isDark ? "text-slate-400" : "text-slate-600"}`}>
        <div className="relative">
          <div className="w-10 h-10 border-2 border-cyan-500/20 border-t-cyan-500 rounded-full animate-spin"></div>
          <div className="absolute inset-0 flex items-center justify-center">
            <span className="w-2 h-2 bg-cyan-400 rounded-full animate-pulse"></span>
          </div>
        </div>
        <div className="text-center space-y-1">
          <span className="text-xs font-mono font-semibold tracking-wider uppercase block text-cyan-400">Aggregating Security Analytics...</span>
          <span className="text-[11px] text-slate-500 font-mono">Querying multi-engine telemetry & threat metrics</span>
        </div>
      </div>
    );
  }

  // Error State with Retry
  if (error && !data) {
    return (
      <div className="min-h-[360px] flex items-center justify-center p-4">
        <div className={`max-w-md w-full p-6 rounded-xl border text-center space-y-4 ${
          isDark ? "bg-[#0E1726] border-rose-500/30 text-slate-300" : "bg-white border-rose-200 text-slate-700 shadow-md"
        }`}>
          <div className="w-12 h-12 mx-auto rounded-full bg-rose-500/10 border border-rose-500/30 flex items-center justify-center text-rose-400">
            <AlertCircle className="w-6 h-6" />
          </div>
          <div className="space-y-1.5">
            <h3 className="font-bold text-sm text-rose-400 uppercase font-mono tracking-wider">
              Analytics Synchronization Error
            </h3>
            <p className="text-xs text-slate-400 leading-relaxed font-mono">
              {error}
            </p>
          </div>
          <div className="flex items-center justify-center gap-3 pt-2">
            <button
              onClick={fetchAnalytics}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-600 text-slate-950 font-mono text-xs font-bold transition-all shadow-md cursor-pointer"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Retry Sync</span>
            </button>
            <button
              onClick={() => {
                setData(EMPTY_ANALYTICS);
                setError(null);
              }}
              className={`px-3 py-2 rounded-lg border text-xs font-mono transition-colors cursor-pointer ${
                isDark ? "border-slate-700 hover:bg-slate-800 text-slate-400" : "border-slate-300 hover:bg-slate-100 text-slate-600"
              }`}
            >
              Zero Telemetry View
            </button>
          </div>
        </div>
      </div>
    );
  }

  // Fallback to empty analytics if data is null
  const activeData = data || EMPTY_ANALYTICS;

  const statCards = [
    {
      title: "Total Emails Scanned",
      value: activeData.total_scans,
      icon: ShieldCheck,
      color: isDark ? "text-cyan-400" : "text-sky-600",
      border: isDark ? "border-cyan-500/20" : "border-sky-200",
      bg: isDark ? "bg-cyan-950/20" : "bg-sky-50/50"
    },
    {
      title: "Threats Neutralized",
      value: activeData.threats_blocked,
      icon: ShieldAlert,
      color: "text-rose-500",
      border: isDark ? "border-rose-500/20" : "border-rose-200",
      bg: isDark ? "bg-rose-950/20" : "bg-rose-50/50"
    },
    {
      title: "Phishing Campaigns",
      value: activeData.phishing_detected,
      icon: Flame,
      color: "text-orange-500",
      border: isDark ? "border-orange-500/20" : "border-orange-200",
      bg: isDark ? "bg-orange-950/20" : "bg-orange-50/50"
    },
    {
      title: "Spam Bulk Junk",
      value: activeData.spam_detected,
      icon: Bug,
      color: "text-amber-500",
      border: isDark ? "border-amber-500/20" : "border-amber-200",
      bg: isDark ? "bg-amber-950/20" : "bg-amber-50/50"
    },
    {
      title: "Malicious URLs Intercepted",
      value: activeData.malicious_urls_intercepted,
      icon: Globe,
      color: "text-purple-500",
      border: isDark ? "border-purple-500/20" : "border-purple-200",
      bg: isDark ? "bg-purple-950/20" : "bg-purple-50/50"
    },
    {
      title: "Average Risk Score",
      value: `${activeData.average_risk_score} / 100`,
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
            Telemetry Synced: <strong className={isDark ? "text-cyan-400" : "text-sky-700"}>{formatIST(activeData.synced_at || new Date())}</strong>
          </span>

          <button
            onClick={fetchAnalytics}
            disabled={loading}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs font-mono transition-colors cursor-pointer ${
              loading ? "opacity-60 cursor-not-allowed" : ""
            } ${
              isDark
                ? "bg-slate-900 border-slate-800 hover:border-cyan-500/40 text-slate-300 hover:text-cyan-300"
                : "bg-white border-slate-200 hover:border-sky-400 text-slate-700 hover:text-sky-700 shadow-xs"
            }`}
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin text-cyan-400" : ""}`} />
            <span>{loading ? "Syncing..." : "Refresh Data"}</span>
          </button>
        </div>
      </div>

      {/* Empty State Banner (if 0 scans recorded) */}
      {activeData.total_scans === 0 && (
        <div className={`p-4 rounded-xl border flex items-center gap-3.5 ${
          isDark ? "bg-cyan-950/20 border-cyan-500/30 text-cyan-300" : "bg-sky-50 border-sky-200 text-sky-800"
        }`}>
          <Inbox className="w-5 h-5 shrink-0 text-cyan-400" />
          <div className="text-xs space-y-0.5">
            <span className="font-bold font-mono tracking-wide">Awaiting Security Scans:</span>
            <p className="text-slate-400 text-[11px]">
              No emails have been analyzed in this account yet. Submit plain text or RFC822 emails in the <strong>Live Scanner</strong> to populate real-time threat telemetry.
            </p>
          </div>
        </div>
      )}

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
            {activeData.threat_distribution.map((dist, idx) => {
              const percentage = activeData.total_scans > 0 ? (dist.count / activeData.total_scans) * 100 : 0;
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
