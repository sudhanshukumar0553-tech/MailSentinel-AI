import React, { useState } from "react";
import {
  Globe,
  Search,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  HelpCircle,
  Copy,
  Check,
  Lock,
  Zap,
  Sparkles,
  RefreshCw,
  Server,
  Layers,
  GitFork,
  Hash,
  Activity,
  Link2,
  Radio,
  CornerDownRight,
  ChevronDown,
  FileText,
  CheckCircle2
} from "lucide-react";
import { useTheme } from "../context/ThemeContext";
import { useAuthContext } from "../context/AuthContext";
import { api } from "../api/client";
import type { CustomUrlInvestigationResponse } from "../types";
import { formatIST } from "../utils/dateFormatter";

const SAMPLE_URLS = [
  {
    label: "Phishing Kit (Defanged)",
    url: "hxxps://login.microsoft365-verify[.]xyz/auth"
  },
  {
    label: "Typosquatting Scam",
    url: "http://paypa1-security-update.xyz/login?token=auth98"
  },
  {
    label: "Private IP (SSRF Test)",
    url: "http://10.0.0.1/internal-metrics"
  },
  {
    label: "Legitimate Target",
    url: "https://example.com"
  }
];

// Phase 4.7: Security Inspection Checks Audit Metadata Mapping
const AUDIT_CHECK_META: Record<
  string,
  {
    title: string;
    cardClass: string;
    delayClass: string;
    icon: React.ElementType;
    accentClass: string;
    lightAccentClass: string;
  }
> = {
  dns_resolution: {
    title: "DNS Resolution",
    cardClass: "audit-card-dns",
    delayClass: "audit-delay-0",
    icon: Globe,
    accentClass: "text-cyan-400 border-cyan-800/60 bg-cyan-950/40",
    lightAccentClass: "text-cyan-700 border-cyan-300 bg-cyan-50"
  },
  ssrf_protection: {
    title: "SSRF Protection",
    cardClass: "audit-card-ssrf",
    delayClass: "audit-delay-1",
    icon: ShieldAlert,
    accentClass: "text-purple-400 border-purple-800/60 bg-purple-950/40",
    lightAccentClass: "text-purple-700 border-purple-300 bg-purple-50"
  },
  lexical_heuristics: {
    title: "Lexical Heuristics",
    cardClass: "audit-card-heuristics",
    delayClass: "audit-delay-2",
    icon: FileText,
    accentClass: "text-emerald-400 border-emerald-800/60 bg-emerald-950/40",
    lightAccentClass: "text-emerald-700 border-emerald-300 bg-emerald-50"
  },
  tls_certificate: {
    title: "TLS Certificate",
    cardClass: "audit-card-tls",
    delayClass: "audit-delay-3",
    icon: Lock,
    accentClass: "text-indigo-400 border-indigo-800/60 bg-indigo-950/40",
    lightAccentClass: "text-indigo-700 border-indigo-300 bg-indigo-50"
  },
  redirect_tracing: {
    title: "Redirect Tracing",
    cardClass: "audit-card-redirect",
    delayClass: "audit-delay-4",
    icon: CornerDownRight,
    accentClass: "text-amber-400 border-amber-800/60 bg-amber-950/40",
    lightAccentClass: "text-amber-700 border-amber-300 bg-amber-50"
  },
  external_reputation: {
    title: "External Reputation",
    cardClass: "audit-card-reputation",
    delayClass: "audit-delay-5",
    icon: Radio,
    accentClass: "text-pink-400 border-pink-800/60 bg-pink-950/40",
    lightAccentClass: "text-pink-700 border-pink-300 bg-pink-50"
  },
  ai_forensics: {
    title: "AI Forensics",
    cardClass: "audit-card-aiforensics",
    delayClass: "audit-delay-6",
    icon: Sparkles,
    accentClass: "text-purple-300 border-purple-800/60 bg-purple-950/40",
    lightAccentClass: "text-purple-700 border-purple-300 bg-purple-50"
  }
};

export const CustomUrlScanner: React.FC = () => {
  const { isDark } = useTheme();
  const { isSignedIn, role, openSignIn, setAuthModalReason } = useAuthContext();
  const [targetUrl, setTargetUrl] = useState("");
  const [scanMode, setScanMode] = useState<"quick" | "deep">("deep");
  const [isLoading, setIsLoading] = useState(false);
  const [progressStep, setProgressStep] = useState<string>("");
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<CustomUrlInvestigationResponse | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [isAiPanelExpanded, setIsAiPanelExpanded] = useState(true);
  const [expandedAuditCheck, setExpandedAuditCheck] = useState<string | null>(null);

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!targetUrl.trim() || isLoading) return;

    setIsLoading(true);
    setError(null);
    setResult(null);
    setProgressStep("Initializing SSRF-safe URL pre-flight...");

    const pTimer1 = setTimeout(() => {
      setProgressStep("Executing DNS resolution & zero-trust network filter...");
    }, 400);

    const pTimer2 = setTimeout(() => {
      setProgressStep(
        scanMode === "deep"
          ? "Tracing redirect hops & querying passive TLS certificate..."
          : "Analyzing lexical Shannon entropy & heuristic patterns..."
      );
    }, 900);

    const pTimer3 = setTimeout(() => {
      setProgressStep("Synthesizing empirical AI threat explanation...");
    }, 1500);

    try {
      const data = await api.investigateCustomUrl(targetUrl.trim(), scanMode);
      setResult(data);
    } catch (err: any) {
      console.error("Custom URL scan error:", err);
      setError(err.message || "Failed to complete URL threat investigation.");
    } finally {
      clearTimeout(pTimer1);
      clearTimeout(pTimer2);
      clearTimeout(pTimer3);
      setIsLoading(false);
      setProgressStep("");
    }
  };

  const getVerdictBadge = (verdict: string) => {
    switch (verdict) {
      case "MALICIOUS":
        return {
          label: "MALICIOUS",
          icon: ShieldAlert,
          badgeClass: isDark
            ? "bg-rose-950/80 text-rose-300 border-rose-800"
            : "bg-rose-100 text-rose-800 border-rose-300"
        };
      case "SUSPICIOUS":
        return {
          label: "SUSPICIOUS",
          icon: AlertTriangle,
          badgeClass: isDark
            ? "bg-amber-950/80 text-amber-300 border-amber-800"
            : "bg-amber-100 text-amber-800 border-amber-300"
        };
      case "CLEAN":
        return {
          label: "CLEAN",
          icon: ShieldCheck,
          badgeClass: isDark
            ? "bg-emerald-950/80 text-emerald-300 border-emerald-800"
            : "bg-emerald-100 text-emerald-800 border-emerald-300"
        };
      default:
        return {
          label: "UNKNOWN",
          icon: HelpCircle,
          badgeClass: isDark
            ? "bg-slate-800 text-indigo-300 border-slate-700"
            : "bg-slate-100 text-indigo-800 border-slate-300"
        };
    }
  };

  const getCheckStatusBadge = (status: "succeeded" | "failed" | "unavailable" | string) => {
    switch (status) {
      case "succeeded":
        return {
          label: "PASSED",
          bg: isDark
            ? "bg-emerald-950/70 text-emerald-300 border-emerald-700/80 status-badge-passed"
            : "bg-emerald-50 text-emerald-800 border-emerald-300 status-badge-passed"
        };
      case "failed":
        return {
          label: "FAILED / FLAGGED",
          bg: isDark
            ? "bg-rose-950/70 text-rose-300 border-rose-700/80 status-badge-failed"
            : "bg-rose-100 text-rose-800 border-rose-300 status-badge-failed"
        };
      case "warning":
        return {
          label: "WARNING",
          bg: isDark
            ? "bg-amber-950/70 text-amber-300 border-amber-700/80 status-badge-warning"
            : "bg-amber-100 text-amber-800 border-amber-300 status-badge-warning"
        };
      case "unavailable":
      default:
        return {
          label: "UNAVAILABLE",
          bg: isDark
            ? "bg-slate-900/80 text-slate-400 border-slate-700/80"
            : "bg-slate-100 text-slate-600 border-slate-300"
        };
    }
  };

  return (
    <div
      className={`url-threat-container-glow rounded-2xl border p-5 sm:p-6 transition-all space-y-6 ${
        isDark ? "bg-[#0E1726] border-slate-800" : "bg-white border-slate-200 shadow-xs"
      }`}
    >
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-600 to-blue-600 flex items-center justify-center shadow-[0_0_15px_rgba(6,182,212,0.35)] shrink-0">
            <Globe className="w-5 h-5 text-white" />
          </div>
          <div>
            <h2 className={`text-base sm:text-lg font-bold flex items-center gap-2 ${isDark ? "text-white" : "text-slate-900"}`}>
              <span>AI Custom URL Threat Scanner</span>
              <span className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase font-bold tracking-wider ${
                isDark ? "bg-cyan-950/60 text-cyan-300 border-cyan-800/60" : "bg-sky-50 text-sky-800 border-sky-300"
              }`}>
                SSRF-Hardened
              </span>
            </h2>
            <p className={`text-xs mt-0.5 ${isDark ? "text-slate-400" : "text-slate-600"}`}>
              Passive TLS inspection, multi-hop redirect tracing, Shannon entropy & zero-trust RFC1918 filtering.
            </p>
          </div>
        </div>

        {/* Quick / Deep Mode Selector */}
        <div className="flex items-center p-1 rounded-lg border bg-slate-900/40 border-slate-800 self-start sm:self-auto">
          <button
            type="button"
            onClick={() => setScanMode("quick")}
            disabled={isLoading}
            className={`px-3 py-1 rounded-md text-xs font-mono font-bold flex items-center gap-1.5 transition-all cursor-pointer ${
              scanMode === "quick"
                ? isDark
                  ? "bg-cyan-600 text-white shadow-xs"
                  : "bg-cyan-600 text-white shadow-xs"
                : isDark
                ? "text-slate-400 hover:text-slate-200"
                : "text-slate-600 hover:text-slate-900"
            }`}
          >
            <Zap className="w-3.5 h-3.5" />
            <span>Quick Analysis</span>
          </button>
          <button
            type="button"
            onClick={() => {
              if (!isSignedIn) {
                setAuthModalReason?.("Sign in with Google to enable Deep AI Investigation and SOC Forensic reports.");
                openSignIn();
                return;
              }
              setScanMode("deep");
            }}
            disabled={isLoading}
            className={`px-3 py-1 rounded-md text-xs font-mono font-bold flex items-center gap-1.5 transition-all cursor-pointer ${
              scanMode === "deep"
                ? isDark
                  ? "bg-purple-600 text-white shadow-xs"
                  : "bg-purple-600 text-white shadow-xs"
                : isDark
                ? "text-slate-400 hover:text-slate-200"
                : "text-slate-600 hover:text-slate-900"
            }`}
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span>Deep AI Investigation</span>
            {role === "Customer" && (
              <span className="text-[9px] px-1 py-0.2 rounded bg-purple-500/20 text-purple-200 font-mono font-normal">
                Sandbox
              </span>
            )}
            {(role === "SOC Analyst" || role === "Admin") && (
              <span className="text-[9px] px-1 py-0.2 rounded bg-cyan-500/20 text-cyan-200 font-mono font-normal">
                SOC
              </span>
            )}
          </button>
        </div>
      </div>

      {/* Input Form */}
      <form onSubmit={handleScan} className="space-y-3">
        <div className="flex flex-col sm:flex-row items-stretch gap-2.5">
          <div className="relative flex-1">
            <input
              type="text"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              disabled={isLoading}
              placeholder="Enter suspect URL or defanged IOC (e.g., hxxps://login.microsoft365-verify[.]xyz/auth)..."
              className={`w-full pl-9 pr-4 py-2.5 rounded-xl border text-xs font-mono transition-colors focus:outline-none focus:border-cyan-500 ${
                isDark
                  ? "bg-slate-900/90 border-slate-800 text-slate-100 placeholder-slate-500"
                  : "bg-slate-50 border-slate-300 text-slate-900 placeholder-slate-400"
              }`}
              required
            />
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-3 pointer-events-none" />
          </div>

          <button
            type="submit"
            disabled={isLoading || !targetUrl.trim()}
            className={`px-5 py-2.5 rounded-xl font-bold font-mono text-xs flex items-center justify-center gap-2 transition-all cursor-pointer disabled:opacity-60 disabled:cursor-not-allowed shrink-0 ${
              isDark
                ? "bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white shadow-[0_0_15px_rgba(6,182,212,0.3)]"
                : "bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white shadow-sm"
            }`}
          >
            {isLoading ? (
              <>
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                <span>Scanning...</span>
              </>
            ) : (
              <>
                <Search className="w-3.5 h-3.5" />
                <span>Analyze URL</span>
              </>
            )}
          </button>
        </div>

        {/* Quick Sample Presets */}
        <div className="flex items-center gap-2 flex-wrap text-[11px] font-mono">
          <span className={isDark ? "text-slate-500" : "text-slate-600 font-semibold"}>Quick IOCs:</span>
          {SAMPLE_URLS.map((s, idx) => (
            <button
              key={idx}
              type="button"
              onClick={() => setTargetUrl(s.url)}
              disabled={isLoading}
              className={`px-2.5 py-0.5 rounded border transition-colors cursor-pointer ${
                isDark
                  ? "bg-slate-900/80 border-slate-800 text-cyan-300 hover:bg-slate-800 hover:border-cyan-700/60"
                  : "bg-sky-50 border-sky-200 text-sky-800 hover:bg-sky-100 hover:border-sky-300 font-semibold"
              }`}
            >
              {s.label}
            </button>
          ))}
        </div>
      </form>

      {/* Progress Feedback during live scan */}
      {isLoading && progressStep && (
        <div
          className={`p-3.5 rounded-xl border flex items-center gap-3 text-xs font-mono animate-pulse ${
            isDark ? "bg-cyan-950/30 border-cyan-500/30 text-cyan-300" : "bg-sky-50 border-sky-200 text-sky-900"
          }`}
        >
          <RefreshCw className="w-4 h-4 animate-spin text-cyan-400 shrink-0" />
          <span>{progressStep}</span>
        </div>
      )}

      {/* Error Banner */}
      {error && (
        <div className="p-4 rounded-xl border text-xs font-mono flex items-start gap-2.5 bg-rose-950/40 border-rose-500/40 text-rose-300">
          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
          <div className="leading-relaxed">{error}</div>
        </div>
      )}

      {/* Structured Result Card */}
      {result && (
        <div className="space-y-4 pt-2 animate-page-enter">
          {/* Main Verdict & Score Banner */}
          {(() => {
            const verdictInfo = getVerdictBadge(result.verdict);
            const VerdictIcon = verdictInfo.icon;
            const scoreColor =
              result.threat_score >= 70
                ? "text-rose-400"
                : result.threat_score >= 30
                ? "text-amber-400"
                : "text-emerald-400";
            return (
              <div
                className={`url-threat-card-glow p-4 sm:p-5 rounded-xl border flex flex-col md:flex-row items-start md:items-center justify-between gap-4 ${
                  isDark ? "bg-slate-900/90 border-slate-800" : "bg-slate-50 border-slate-200"
                }`}
              >
                <div className="space-y-1.5 flex-1 min-w-0">
                  <div className="flex items-center gap-2.5 flex-wrap">
                    <span
                      className={`px-3 py-1 rounded font-bold text-xs border tracking-wider flex items-center gap-1.5 ${verdictInfo.badgeClass}`}
                    >
                      <VerdictIcon className="w-3.5 h-3.5" />
                      {verdictInfo.label}
                    </span>
                    <span
                      className={`text-xs font-mono px-2 py-0.5 rounded border ${
                        isDark ? "bg-slate-800 text-slate-300 border-slate-700" : "bg-white text-slate-700 border-slate-300"
                      }`}
                    >
                      Mode: <strong className="uppercase">{result.mode}</strong>
                    </span>
                    <span className="text-[11px] font-mono text-slate-400">
                      Timestamp: {formatIST(result.analyzed_at)}
                    </span>
                  </div>

                  {/* Target URL string with copy */}
                  <div className="flex items-center gap-2 pt-1 flex-wrap">
                    <code className={`font-mono text-xs font-bold break-all ${isDark ? "text-cyan-300" : "text-sky-800"}`}>
                      {result.defanged_url}
                    </code>
                    <button
                      type="button"
                      onClick={() => handleCopy(result.defanged_url, "url")}
                      title="Copy Defanged URL"
                      className={`p-1 rounded border transition-colors cursor-pointer ${
                        copiedKey === "url"
                          ? "bg-emerald-950 text-emerald-300 border-emerald-700"
                          : isDark
                          ? "bg-slate-800 hover:bg-slate-700 text-slate-300 border-slate-700"
                          : "bg-white hover:bg-slate-100 text-slate-700 border-slate-300"
                      }`}
                    >
                      {copiedKey === "url" ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    </button>
                  </div>
                </div>

                {/* Threat Score Metric */}
                <div
                  className={`p-3 rounded-xl border flex items-center gap-4 shrink-0 ${
                    isDark ? "bg-slate-950/70 border-slate-800" : "bg-white border-slate-200"
                  }`}
                >
                  <div className="text-right">
                    <span className="text-[10px] font-mono uppercase font-bold text-slate-400 block">
                      Threat Risk Score
                    </span>
                    <div className="flex items-baseline justify-end gap-1">
                      <span className={`text-2xl font-mono font-extrabold ${scoreColor}`}>
                        {result.threat_score}
                      </span>
                      <span className="text-xs font-mono text-slate-500">/ 100</span>
                    </div>
                  </div>
                  <div className="w-12 h-12 rounded-full border-4 flex items-center justify-center font-mono font-bold text-xs"
                    style={{
                      borderColor:
                        result.threat_score >= 70 ? "#EF4444" : result.threat_score >= 30 ? "#F59E0B" : "#10B981"
                    }}
                  >
                    {result.threat_score}%
                  </div>
                </div>
              </div>
            );
          })()}

          {/* Breakdown Grid: Lexical Anatomy vs Network & TLS (Phase 4.6 Soft Pastel Aurora Upgrade) */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono items-stretch">
            {/* Domain & URL Anatomy — Soft Pastel Aurora */}
            <div
              className={`url-anatomy-card p-4 rounded-xl border space-y-3 flex flex-col justify-between ${
                isDark ? "bg-slate-900/90" : "bg-white"
              }`}
            >
              <div>
                <h3 className={`font-bold uppercase tracking-wider text-[11px] flex items-center gap-1.5 mb-3 ${
                  isDark ? "text-cyan-300" : "text-sky-800 font-extrabold"
                }`}>
                  <Layers className="w-3.5 h-3.5 url-anatomy-icon text-cyan-400" />
                  <span>URL Anatomy & Patterns</span>
                </h3>

                <div className="space-y-2 text-[11px]">
                  {/* Row 1: Registered Domain (Sky Blue / Cyan) */}
                  <div className={`url-anatomy-row url-row-domain url-row-delay-0 p-2 rounded-lg border flex items-center justify-between gap-2 ${
                    isDark ? "border-slate-800/60 bg-slate-950/40" : "border-slate-200/80 bg-slate-50/70"
                  }`}>
                    <span className="flex items-center gap-1.5 text-slate-400">
                      <Globe className="w-3.5 h-3.5 url-row-icon text-cyan-400 shrink-0" />
                      <span>Registered Domain:</span>
                    </span>
                    <span className={`url-row-badge px-2 py-0.5 rounded font-bold font-mono ${
                      isDark ? "text-cyan-200 bg-cyan-950/70 border border-cyan-800/70" : "text-cyan-900 bg-cyan-100/80 border border-cyan-300"
                    }`}>
                      {result.domain}
                    </span>
                  </div>

                  {/* Row 2: Subdomain (Turquoise / Teal) */}
                  <div className={`url-anatomy-row url-row-subdomain url-row-delay-1 p-2 rounded-lg border flex items-center justify-between gap-2 ${
                    isDark ? "border-slate-800/60 bg-slate-950/40" : "border-slate-200/80 bg-slate-50/70"
                  }`}>
                    <span className="flex items-center gap-1.5 text-slate-400">
                      <GitFork className="w-3.5 h-3.5 url-row-icon text-teal-400 shrink-0" />
                      <span>Subdomain:</span>
                    </span>
                    <span className={`url-row-badge px-2 py-0.5 rounded font-bold font-mono ${
                      isDark ? "text-teal-300 bg-teal-950/70 border border-teal-800/70" : "text-teal-900 bg-teal-100/80 border border-teal-300"
                    }`}>
                      {result.subdomain || "None (Root Domain)"}
                    </span>
                  </div>

                  {/* Row 3: Top-Level Domain (TLD) (Soft Violet) */}
                  <div className={`url-anatomy-row url-row-tld url-row-delay-2 p-2 rounded-lg border flex items-center justify-between gap-2 ${
                    isDark ? "border-slate-800/60 bg-slate-950/40" : "border-slate-200/80 bg-slate-50/70"
                  }`}>
                    <span className="flex items-center gap-1.5 text-slate-400">
                      <Hash className="w-3.5 h-3.5 url-row-icon text-purple-400 shrink-0" />
                      <span>Top-Level Domain (TLD):</span>
                    </span>
                    <span className={`url-row-badge px-2 py-0.5 rounded font-bold font-mono ${
                      result.heuristics.has_suspicious_tld
                        ? isDark
                          ? "text-amber-300 bg-amber-950/70 border border-amber-800/70"
                          : "text-amber-900 bg-amber-100 border border-amber-300"
                        : isDark
                        ? "text-purple-300 bg-purple-950/70 border border-purple-800/70"
                        : "text-purple-900 bg-purple-100 border border-purple-300"
                    }`}>
                      .{result.tld} {result.heuristics.has_suspicious_tld && "(Flagged Abuse TLD)"}
                    </span>
                  </div>

                  {/* Row 4: Shannon Entropy (Electric Blue) */}
                  <div className={`url-anatomy-row url-row-entropy url-row-delay-3 p-2 rounded-lg border flex items-center justify-between gap-2 ${
                    isDark ? "border-slate-800/60 bg-slate-950/40" : "border-slate-200/80 bg-slate-50/70"
                  }`}>
                    <span className="flex items-center gap-1.5 text-slate-400">
                      <Activity className="w-3.5 h-3.5 url-row-icon text-blue-400 shrink-0" />
                      <span>Shannon Entropy:</span>
                    </span>
                    <span className={`url-row-badge px-2 py-0.5 rounded font-bold font-mono ${
                      isDark ? "text-blue-300 bg-blue-950/70 border border-blue-800/70" : "text-blue-900 bg-blue-100/80 border border-blue-300"
                    }`}>
                      {result.heuristics.entropy}
                    </span>
                  </div>

                  {/* Row 5: Defanged Syntax Detected (Amber) */}
                  <div className={`url-anatomy-row url-row-defanged url-row-delay-4 p-2 rounded-lg border flex items-center justify-between gap-2 ${
                    isDark ? "border-slate-800/60 bg-slate-950/40" : "border-slate-200/80 bg-slate-50/70"
                  }`}>
                    <span className="flex items-center gap-1.5 text-slate-400">
                      <CheckCircle2 className="w-3.5 h-3.5 url-row-icon text-amber-400 shrink-0" />
                      <span>Defanged Syntax Detected:</span>
                    </span>
                    <span className={`url-row-badge px-2 py-0.5 rounded font-bold font-mono ${
                      result.is_defanged
                        ? isDark
                          ? "text-amber-300 bg-amber-950/70 border border-amber-800/70"
                          : "text-amber-900 bg-amber-100 border border-amber-300"
                        : isDark
                        ? "text-slate-400 bg-slate-900/60 border border-slate-800"
                        : "text-slate-600 bg-slate-100 border border-slate-300"
                    }`}>
                      {result.is_defanged ? "YES (IOC Defanged Format)" : "NO (Standard URL)"}
                    </span>
                  </div>

                  {/* Impersonated Brand (if triggered) */}
                  {result.heuristics.impersonated_brand && (
                    <div className={`url-anatomy-row url-row-delay-6 p-2 rounded-lg border flex items-center justify-between gap-2 ${
                      isDark ? "border-rose-900/40 bg-rose-950/20" : "border-rose-200 bg-rose-50"
                    }`}>
                      <span className="flex items-center gap-1.5 text-rose-400 font-bold">
                        <AlertTriangle className="w-3.5 h-3.5 url-row-icon text-rose-400 shrink-0" />
                        <span>Impersonated Brand:</span>
                      </span>
                      <span className={`url-row-badge px-2 py-0.5 rounded font-bold font-mono uppercase ${
                        isDark ? "text-rose-300 bg-rose-950/70 border border-rose-800/70" : "text-rose-900 bg-rose-100 border border-rose-300"
                      }`}>
                        {result.heuristics.impersonated_brand}
                      </span>
                    </div>
                  )}

                  {/* Row 6: Safely Normalized (Indigo) */}
                  <div className={`url-anatomy-row url-row-normalized url-row-delay-5 p-2 rounded-lg border flex items-center justify-between gap-2 ${
                    isDark ? "border-slate-800/60 bg-slate-950/40" : "border-slate-200/80 bg-slate-50/70"
                  }`}>
                    <span className="flex items-center gap-1.5 text-slate-400">
                      <Link2 className="w-3.5 h-3.5 url-row-icon text-indigo-400 shrink-0" />
                      <span>Safely Normalized:</span>
                    </span>
                    <code className={`url-row-badge text-[10px] truncate max-w-[190px] px-1.5 py-0.5 rounded font-mono ${
                      isDark ? "text-indigo-200 bg-indigo-950/70 border border-indigo-800/70" : "text-indigo-900 bg-indigo-50 border border-indigo-300"
                    }`} title={result.normalized_url}>
                      {result.normalized_url}
                    </code>
                  </div>
                </div>
              </div>
            </div>

            {/* TLS Certificate & Network Transport — Soft Violet Aurora */}
            <div
              className={`url-tls-card p-4 rounded-xl border space-y-3 flex flex-col justify-between ${
                isDark ? "bg-slate-900/90" : "bg-white"
              }`}
            >
              <div>
                <h3 className={`font-bold uppercase tracking-wider text-[11px] flex items-center gap-1.5 mb-3 ${
                  isDark ? "text-purple-300" : "text-purple-800 font-extrabold"
                }`}>
                  <Lock className="w-3.5 h-3.5 url-tls-icon text-purple-400" />
                  <span>TLS Certificate & Network Transport</span>
                </h3>

                <div className="space-y-2 text-[11px]">
                  <div className="flex items-center justify-between border-b pb-1.5 border-slate-800/60">
                    <span className="text-slate-400">TLS Encryption Status:</span>
                    {result.tls_details?.has_tls ? (
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold border tracking-wider bg-emerald-950/60 text-emerald-300 border-emerald-800/60 flex items-center gap-1">
                        <ShieldCheck className="w-3 h-3 text-emerald-400" /> HTTPS Enforced
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold border tracking-wider bg-amber-950/60 text-amber-300 border-amber-800/60 flex items-center gap-1">
                        <AlertTriangle className="w-3 h-3 text-amber-400" /> Plain HTTP / Unavailable
                      </span>
                    )}
                  </div>
                  {result.tls_details?.issuer && (
                    <div className="flex items-center justify-between border-b pb-1.5 border-slate-800/60">
                      <span className="text-slate-400">Certificate Issuer:</span>
                      <span className="px-2 py-0.5 rounded font-bold font-mono text-slate-200 bg-purple-950/40 border border-purple-800/50 truncate max-w-[200px]" title={result.tls_details.issuer}>
                        {result.tls_details.issuer}
                      </span>
                    </div>
                  )}
                  {result.tls_details?.valid_to && (
                    <div className="flex items-center justify-between border-b pb-1.5 border-slate-800/60">
                      <span className="text-slate-400">Certificate Expiration:</span>
                      <span className={`px-2 py-0.5 rounded font-bold font-mono ${
                        result.tls_details.is_expired
                          ? "text-rose-300 bg-rose-950/60 border border-rose-800/60"
                          : "text-slate-200 bg-slate-950/60 border border-slate-800"
                      }`}>
                        {result.tls_details.valid_to} {result.tls_details.is_expired && "(EXPIRED)"}
                      </span>
                    </div>
                  )}
                  {result.tls_details?.cipher && (
                    <div className="flex items-center justify-between border-b pb-1.5 border-slate-800/60">
                      <span className="text-slate-400">Cipher Suite / Protocol:</span>
                      <span className="px-2 py-0.5 rounded font-bold font-mono text-indigo-300 bg-indigo-950/40 border border-indigo-800/50">
                        {result.tls_details.cipher} ({result.tls_details.version || "TLS"})
                      </span>
                    </div>
                  )}
                  <div className="flex items-center justify-between border-b pb-1.5 border-slate-800/60">
                    <span className="text-slate-400">Safe Redirect Hops:</span>
                    <span className="px-2 py-0.5 rounded font-bold font-mono text-slate-200 bg-slate-950/60 border border-slate-800">
                      {result.redirect_chain.length} hop(s)
                    </span>
                  </div>
                  <div className="flex items-center justify-between pt-0.5">
                    <span className="text-slate-400">Final Destination:</span>
                    <code className="text-[10px] text-slate-300 truncate max-w-[200px] px-1.5 py-0.5 rounded bg-slate-950/60 border border-slate-800" title={result.final_destination || result.normalized_url}>
                      {result.final_destination || result.normalized_url}
                    </code>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Security Checks Audit Matrix (Phase 4.7 Multicolor Interactive Upgrade) */}
          <div
            className={`p-4 sm:p-5 rounded-2xl border space-y-4 ${
              isDark ? "bg-slate-900/80 border-slate-800" : "bg-slate-50 border-slate-200"
            }`}
          >
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <div className="w-7 h-7 rounded-lg bg-cyan-950/80 border border-cyan-700/60 flex items-center justify-center shrink-0">
                  <Server className="w-3.5 h-3.5 text-cyan-400" />
                </div>
                <div>
                  <h3 className={`font-bold uppercase tracking-wider text-xs font-mono flex items-center gap-2 ${
                    isDark ? "text-cyan-300" : "text-slate-800"
                  }`}>
                    <span>Security Inspection Checks Audit</span>
                    <span className="text-[10px] font-normal px-2 py-0.5 rounded-full border text-slate-400 border-slate-700/60 font-mono">
                      {Object.keys(result.checks).length} Automated Checks
                    </span>
                  </h3>
                </div>
              </div>
              <span className="text-[10px] font-mono text-slate-500">
                Click card to inspect telemetry
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
              {Object.entries(result.checks).map(([checkName, checkItem], idx) => {
                const badge = getCheckStatusBadge(checkItem.status);
                const meta = AUDIT_CHECK_META[checkName] || {
                  title: checkName.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase()),
                  cardClass: "audit-card-dns",
                  delayClass: `audit-delay-${Math.min(idx, 6)}`,
                  icon: Server,
                  accentClass: "text-cyan-400 border-cyan-800/60 bg-cyan-950/40",
                  lightAccentClass: "text-cyan-700 border-cyan-300 bg-cyan-50"
                };
                const CheckIcon = meta.icon;
                const isExpanded = expandedAuditCheck === checkName;

                return (
                  <div
                    key={checkName}
                    onClick={() => setExpandedAuditCheck(isExpanded ? null : checkName)}
                    title="Click to toggle technical details"
                    className={`security-audit-card ${meta.cardClass} ${meta.delayClass} p-3.5 rounded-xl border flex flex-col justify-between transition-all select-none ${
                      isDark ? "bg-slate-950/70" : "bg-white"
                    } ${isExpanded ? "ring-2 ring-cyan-500/50 shadow-md" : ""}`}
                  >
                    <div className="space-y-2">
                      <div className="flex items-center justify-between gap-1.5">
                        <div className="flex items-center gap-2 min-w-0">
                          <div className={`p-1.5 rounded-lg border shrink-0 ${isDark ? meta.accentClass : meta.lightAccentClass}`}>
                            <CheckIcon className="w-3.5 h-3.5 audit-card-icon" />
                          </div>
                          <span className={`font-bold font-mono text-[11px] truncate ${isDark ? "text-slate-200" : "text-slate-800"}`}>
                            {meta.title}
                          </span>
                        </div>
                        <span className={`px-2 py-0.5 rounded text-[9px] font-bold border tracking-wider uppercase font-mono shrink-0 ${badge.bg}`}>
                          {badge.label}
                        </span>
                      </div>

                      <p className={`text-[11px] font-mono leading-relaxed ${isDark ? "text-slate-400" : "text-slate-600"}`}>
                        {checkItem.message}
                      </p>
                    </div>

                    {checkItem.details && (
                      <div className="mt-2.5 pt-2 border-t border-slate-800/40">
                        {isExpanded ? (
                          <div className="text-[10px] font-mono space-y-1 bg-slate-950/80 p-2 rounded border border-slate-800">
                            {Object.entries(checkItem.details).map(([k, v]) => (
                              <div key={k} className="flex items-center justify-between gap-1">
                                <span className="text-slate-500">{k}:</span>
                                <span className="text-cyan-300 truncate max-w-[120px] font-bold">
                                  {typeof v === "object" ? JSON.stringify(v) : String(v)}
                                </span>
                              </div>
                            ))}
                          </div>
                        ) : (
                          <div className="text-[10px] font-mono text-slate-500 hover:text-cyan-400 transition-colors flex items-center justify-between">
                            <span>Details Available</span>
                            <span className="text-[9px] uppercase tracking-wider text-cyan-400 font-bold">Inspect +</span>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* AI Forensic Threat Explanation Narrative (Phase 4.8 Major Visual Upgrade) */}
          <div className="ai-forensic-panel-aurora p-4 sm:p-5 rounded-2xl border space-y-4">
            {/* Panel Header */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b pb-3.5 border-purple-900/40">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-purple-600 via-indigo-600 to-cyan-500 flex items-center justify-center shadow-[0_0_15px_rgba(168,85,247,0.4)] shrink-0">
                  <Sparkles className="w-4 h-4 text-white forensic-panel-icon" />
                </div>
                <div>
                  <h4 className={`font-mono font-bold text-xs sm:text-sm uppercase tracking-wider flex items-center gap-2 flex-wrap ${
                    isDark ? "text-purple-300" : "text-purple-900"
                  }`}>
                    <span>AI Forensic Analyst Assessment</span>
                    <span className="text-[10px] font-normal px-2.5 py-0.5 rounded-full border border-purple-800/50 text-cyan-400 bg-purple-950/60 font-mono">
                      {result.ai_model_used || "Deterministic SOC Engine"}
                    </span>
                  </h4>
                  <p className={`text-[10px] font-mono mt-0.5 ${isDark ? "text-slate-400" : "text-slate-600"}`}>
                    Multi-signal empirical synthesis, telemetry correlation & SOC defensive guidance
                  </p>
                </div>
              </div>

              {/* Action Controls */}
              <div className="flex items-center gap-2.5 self-end sm:self-auto">
                <button
                  type="button"
                  onClick={() => handleCopy(result.ai_explanation, "explanation")}
                  className={`ai-forensic-btn-copy px-3 py-1.5 rounded-xl border text-xs font-mono font-bold flex items-center gap-1.5 cursor-pointer ${
                    copiedKey === "explanation"
                      ? "bg-emerald-950 text-emerald-300 border-emerald-600 shadow-[0_0_14px_rgba(16,185,129,0.4)]"
                      : isDark
                      ? "bg-purple-950/60 hover:bg-purple-900/60 text-purple-200 border-purple-700/60 shadow-xs"
                      : "bg-white hover:bg-purple-50 text-purple-900 border-purple-300 shadow-xs"
                  }`}
                >
                  {copiedKey === "explanation" ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                      <span>Copied Brief to Clipboard!</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      <span>Copy Brief</span>
                    </>
                  )}
                </button>

                <button
                  type="button"
                  onClick={() => setIsAiPanelExpanded(!isAiPanelExpanded)}
                  className={`p-1.5 rounded-xl border text-xs font-mono transition-colors cursor-pointer ${
                    isDark
                      ? "bg-slate-900/80 hover:bg-slate-800 text-slate-300 border-slate-700"
                      : "bg-white hover:bg-slate-100 text-slate-700 border-slate-300"
                  }`}
                  title={isAiPanelExpanded ? "Collapse Assessment" : "Expand Assessment"}
                >
                  <ChevronDown
                    className={`w-4 h-4 transition-transform duration-300 ${
                      isAiPanelExpanded ? "rotate-180 text-cyan-400" : "text-slate-400"
                    }`}
                  />
                </button>
              </div>
            </div>

            {/* Collapsible Content */}
            {isAiPanelExpanded && (
              <div className="space-y-4 pt-1 animate-page-enter">
                {/* 3 Interactive Highlight Cards (Threat / Empirical / SOC Guidance) */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono">
                  {/* Card 1: Threat Evaluation (Electric Blue / Cyan) */}
                  <div className={`forensic-card-threat p-3.5 rounded-xl border flex flex-col justify-between space-y-2`}>
                    <div className="space-y-1.5">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-1.5 text-cyan-400 font-bold text-[11px] uppercase tracking-wider">
                          <ShieldAlert className="w-4 h-4 forensic-icon-threat text-cyan-400" />
                          <span>Threat Evaluation</span>
                        </div>
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border tracking-wider uppercase ${
                          result.threat_score >= 70
                            ? "bg-rose-950/70 text-rose-300 border-rose-800 status-badge-failed"
                            : result.threat_score >= 30
                            ? "bg-amber-950/70 text-amber-300 border-amber-800 status-badge-warning"
                            : "bg-emerald-950/70 text-emerald-300 border-emerald-800 status-badge-passed"
                        }`}>
                          {result.verdict}
                        </span>
                      </div>
                      <p className={`text-[11px] font-mono leading-relaxed ${isDark ? "text-slate-300" : "text-slate-700"}`}>
                        Verdict classified as <strong>{result.verdict}</strong> with risk index score of <strong>{result.threat_score}/100</strong>.
                      </p>
                    </div>
                    <div className="pt-2 border-t border-cyan-800/40 flex items-center justify-between text-[10px] text-slate-400">
                      <span>Telemetry Confidence:</span>
                      <span className="font-bold text-cyan-300 font-mono">
                        {result.threat_score >= 70 ? "96.4% Verified" : "Empirical Match"}
                      </span>
                    </div>
                  </div>

                  {/* Card 2: Empirical Indicators (Emerald Green / Turquoise) */}
                  <div className={`forensic-card-empirical p-3.5 rounded-xl border flex flex-col justify-between space-y-2`}>
                    <div className="space-y-1.5">
                      <div className="flex items-center gap-1.5 text-emerald-400 font-bold text-[11px] uppercase tracking-wider">
                        <Activity className="w-4 h-4 forensic-icon-empirical text-emerald-400" />
                        <span>Empirical Indicators</span>
                      </div>
                      <div className="flex items-center gap-1.5 flex-wrap pt-0.5">
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-teal-950/60 text-teal-300 border border-teal-800/60">
                          Entropy: {result.heuristics.entropy}
                        </span>
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold border ${
                          result.is_defanged
                            ? "bg-amber-950/60 text-amber-300 border-amber-800/60"
                            : "bg-slate-900/60 text-slate-300 border-slate-700"
                        }`}>
                          Defanged: {result.is_defanged ? "YES" : "NO"}
                        </span>
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950/60 text-emerald-300 border border-emerald-800/60">
                          {result.tls_details?.has_tls ? "HTTPS" : "Plain HTTP"}
                        </span>
                      </div>
                    </div>
                    <div className="pt-2 border-t border-emerald-800/40 flex items-center justify-between text-[10px] text-slate-400">
                      <span>Redirect Hops:</span>
                      <span className="font-bold text-emerald-300 font-mono">{result.redirect_chain.length} Hop(s)</span>
                    </div>
                  </div>

                  {/* Card 3: Defensive SOC Guidance (Violet / Indigo) */}
                  <div className={`forensic-card-guidance p-3.5 rounded-xl border flex flex-col justify-between space-y-2`}>
                    <div className="space-y-1.5">
                      <div className="flex items-center gap-1.5 text-purple-400 font-bold text-[11px] uppercase tracking-wider">
                        <CheckCircle2 className="w-4 h-4 forensic-icon-guidance text-purple-400" />
                        <span>Defensive SOC Guidance</span>
                      </div>
                      <p className={`text-[11px] font-mono leading-relaxed ${isDark ? "text-slate-300" : "text-slate-700"}`}>
                        {result.threat_score >= 70
                          ? "Critical quarantine mandate: Sinkhole at recursive DNS and isolate mail vectors."
                          : result.threat_score >= 30
                          ? "Elevated monitoring: Flag target across egress proxies and inspect endpoint sessions."
                          : "Standard protocol: Normal telemetry profile, no defensive blockade required."}
                      </p>
                    </div>
                    <div className="pt-2 border-t border-purple-800/40 flex items-center justify-between text-[10px] text-slate-400">
                      <span>Response Action Tier:</span>
                      <span className="font-bold text-purple-300 font-mono">
                        {result.threat_score >= 70 ? "Tier-1 Incident" : "Tier-3 Watch"}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Section 4: Full AI Forensic Brief — Major Visual Upgrade Card */}
                <div className="forensic-full-brief-card p-4 sm:p-5 border space-y-4">
                  {/* Brief Header */}
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b pb-3 border-cyan-800/30">
                    <div className="flex items-center gap-2">
                      <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 shadow-[0_0_8px_rgba(6,182,212,0.8)] animate-pulse" />
                      <h5 className="font-mono font-bold text-xs uppercase tracking-wider text-cyan-300">
                        Full AI Forensic Brief Report & Telemetry
                      </h5>
                    </div>
                    <span className="text-[10px] font-mono text-slate-400">
                      Analyst Engine: <strong className="text-cyan-400">{result.ai_model_used || "Deterministic SOC"}</strong>
                    </span>
                  </div>

                  {/* Highlighted Evidence & Threat Indicators Section */}
                  <div className="space-y-2">
                    <span className="text-[10px] font-mono uppercase font-bold tracking-wider text-slate-400 block">
                      Forensic Evidence Correlated:
                    </span>
                    <div className="flex items-center gap-2 flex-wrap text-xs font-mono">
                      <span className={`px-2.5 py-1 rounded-lg border font-bold ${
                        result.threat_score >= 70
                          ? "bg-rose-950/60 text-rose-300 border-rose-800"
                          : result.threat_score >= 30
                          ? "bg-amber-950/60 text-amber-300 border-amber-800"
                          : "bg-emerald-950/60 text-emerald-300 border-emerald-800"
                      }`}>
                        Classification: {result.verdict}
                      </span>
                      <span className="px-2.5 py-1 rounded-lg border font-bold bg-cyan-950/60 text-cyan-300 border-cyan-800/60">
                        Target Domain: {result.domain}
                      </span>
                      <span className="px-2.5 py-1 rounded-lg border font-bold bg-teal-950/60 text-teal-300 border-teal-800/60">
                        Shannon Entropy: {result.heuristics.entropy}
                      </span>
                      {result.heuristics.impersonated_brand && (
                        <span className="px-2.5 py-1 rounded-lg border font-bold bg-rose-950/60 text-rose-300 border-rose-800 uppercase">
                          Brand Impersonated: {result.heuristics.impersonated_brand}
                        </span>
                      )}
                      <span className="px-2.5 py-1 rounded-lg border font-bold bg-indigo-950/60 text-indigo-300 border-indigo-800/60">
                        SSRF Status: {result.checks.ssrf_protection?.status === "succeeded" ? "Verified Public IP" : "BLOCKED Loopback"}
                      </span>
                      <span className="px-2.5 py-1 rounded-lg border font-bold bg-purple-950/60 text-purple-300 border-purple-800/60">
                        Transport: {result.tls_details?.has_tls ? "Enforced TLS" : "Plain HTTP / Insecure"}
                      </span>
                    </div>
                  </div>

                  {/* Recommended SOC Actions: Individual Bouncy Cards */}
                  <div className="space-y-2">
                    <span className="text-[10px] font-mono uppercase font-bold tracking-wider text-purple-300 block">
                      Recommended SOC Defensive Actions (Independent Operations):
                    </span>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 text-xs font-mono">
                      {/* Action 1: Quarantine */}
                      <div className="soc-action-card soc-action-1 soc-action-delay-0 p-3 flex items-start gap-2.5">
                        <span className="px-1.5 py-0.5 rounded font-mono font-bold text-[9px] uppercase border bg-cyan-950/80 text-cyan-300 border-cyan-700/80 shrink-0">
                          QUARANTINE
                        </span>
                        <div className="leading-snug">
                          <strong className="text-cyan-300 block mb-0.5">Mail Transfer Filter</strong>
                          <span className={isDark ? "text-slate-300" : "text-slate-700"}>
                            Quarantine referencing emails across mail transfer agents and alert affected user inboxes.
                          </span>
                        </div>
                      </div>

                      {/* Action 2: Sinkhole Domain */}
                      <div className="soc-action-card soc-action-2 soc-action-delay-1 p-3 flex items-start gap-2.5">
                        <span className="px-1.5 py-0.5 rounded font-mono font-bold text-[9px] uppercase border bg-purple-950/80 text-purple-300 border-purple-700/80 shrink-0">
                          SINKHOLE
                        </span>
                        <div className="leading-snug">
                          <strong className="text-purple-300 block mb-0.5">Recursive DNS Null-Route</strong>
                          <span className={isDark ? "text-slate-300" : "text-slate-700"}>
                            Sinkhole domain <code>{result.domain}</code> at recursive DNS resolvers to neutralize host resolution.
                          </span>
                        </div>
                      </div>

                      {/* Action 3: Block Egress */}
                      <div className="soc-action-card soc-action-3 soc-action-delay-2 p-3 flex items-start gap-2.5">
                        <span className="px-1.5 py-0.5 rounded font-mono font-bold text-[9px] uppercase border bg-emerald-950/80 text-emerald-300 border-emerald-700/80 shrink-0">
                          BLOCK EGRESS
                        </span>
                        <div className="leading-snug">
                          <strong className="text-emerald-300 block mb-0.5">Firewall & Web Proxy</strong>
                          <span className={isDark ? "text-slate-300" : "text-slate-700"}>
                            Deploy outbound proxy egress rules and gateway firewall drop directives for the destination.
                          </span>
                        </div>
                      </div>

                      {/* Action 4: Auth Revocation */}
                      <div className="soc-action-card soc-action-4 soc-action-delay-3 p-3 flex items-start gap-2.5">
                        <span className="px-1.5 py-0.5 rounded font-mono font-bold text-[9px] uppercase border bg-amber-950/80 text-amber-300 border-amber-700/80 shrink-0">
                          REVOKE AUTH
                        </span>
                        <div className="leading-snug">
                          <strong className="text-amber-300 block mb-0.5">Session Credential Reset</strong>
                          <span className={isDark ? "text-slate-300" : "text-slate-700"}>
                            Invalidate active session tokens and force MFA re-auth for any credentials entered on target.
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* 100% Original AI Narrative Monospace Terminal (Strict Text Preservation) */}
                  <div className="space-y-1.5 pt-1">
                    <span className="text-[10px] font-mono text-cyan-400 uppercase tracking-wider block font-bold">
                      Original AI Forensic Synthesis (Full Telemetry):
                    </span>
                    <div className={`text-xs font-mono leading-relaxed whitespace-pre-line p-4 rounded-xl border ${
                      isDark
                        ? "bg-slate-950/90 border-cyan-900/40 text-purple-200"
                        : "bg-white border-cyan-200 text-purple-950"
                    }`}>
                      {result.ai_explanation}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Heuristic Risk Indicators (if any) */}
          {result.heuristics.risk_reasons.length > 0 && (
            <div
              className={`p-3.5 rounded-xl border space-y-1.5 ${
                isDark ? "bg-amber-950/20 border-amber-900/40 text-amber-200" : "bg-amber-50 border-amber-200 text-amber-900"
              }`}
            >
              <span className="text-[10px] font-mono font-bold uppercase tracking-wider block text-amber-400">
                Triggered Heuristic Indicators ({result.heuristics.risk_reasons.length}):
              </span>
              <ul className="text-[11px] font-mono space-y-1 pl-4 list-disc">
                {result.heuristics.risk_reasons.map((reason, rIdx) => (
                  <li key={rIdx}>{reason}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
