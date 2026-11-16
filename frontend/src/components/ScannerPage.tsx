import React, { useState, useRef } from "react";
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Link2,
  FileText,
  Sparkles,
  ArrowRight,
  Info,
  MessageSquareCode,
  History
} from "lucide-react";
import { api } from "../api/client";
import { useTheme } from "../context/ThemeContext";
import type { ScanResult } from "../types";
import { getThreatLevelConfig } from "../utils/formatters";
import { formatIST } from "../utils/dateFormatter";

interface ScannerPageProps {
  onLaunchAgent: (content: string, headers?: string, scanId?: string) => void;
  onLaunchCopilot?: (content: string, headers?: string, scanId?: string) => void;
  onScanCompleted?: (result: ScanResult) => void;
  onNavigateToHistory?: () => void;
}

const PRESET_SAMPLES = [
  {
    label: "Phishing Attack (Password Expiry)",
    type: "phishing",
    subject: "URGENT: Microsoft 365 Password Expiration Notice",
    sender: "security-service@m1crosoft-auth-portal.com",
    body: `Dear user,

Your Office 365 corporate password is set to expire in 2 hours.
Failure to update will result in immediate suspension of mailbox and OneDrive sync.

Please click the secure portal link below to retain your current credentials:
https://m1crosoft-auth-portal.com/login?session=9928374

Security Operations Center`
  },
  {
    label: "Financial Coercion (Fake PayPal)",
    type: "phishing",
    subject: "Security Notification: Unauthorized $749.00 USD Debit",
    sender: "service@paypa1-dispute-center.xyz",
    body: `We noticed an unauthorized login attempt to your PayPal wallet from Lagos, Nigeria.
A charge of $749.00 USD to 'Crypto Gateway Ltd' was temporarily authorized.

If you did not authorize this payment, cancel it immediately at:
http://192.168.1.188/cancel-transaction

PayPal Fraud Resolution Team`
  },
  {
    label: "Commercial Spam (SEO Promotion)",
    type: "spam",
    subject: "Exclusive 70% Discount: Skyrocket your Google Ranking",
    sender: "promo@global-marketing-leads.com",
    body: `Dear Webmaster,

Do you want guaranteed #1 Google rankings?
Our verified backlink packages guarantee 500,000 visitors per month or your money back!
Claim your free trial coupon code: WINNER2026.

Click here to unsubscribe.`
  },
  {
    label: "Legitimate Corporate Sync",
    type: "safe",
    subject: "Sprint Review & Engineering Roadmap Sync",
    sender: "team-lead@company.com",
    body: `Hi team,

Please find the agenda for our bi-weekly roadmap review scheduled for tomorrow at 10:00 AM.
We will review current bug triage metrics and sprint deliverables.

See you all in the engineering channel.`
  }
];

export const ScannerPage: React.FC<ScannerPageProps> = ({
  onLaunchAgent,
  onLaunchCopilot,
  onScanCompleted,
  onNavigateToHistory
}) => {
  const { isDark } = useTheme();
  const [emailContent, setEmailContent] = useState("");
  const [subject, setSubject] = useState("");
  const [sender, setSender] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const resultRef = useRef<HTMLDivElement>(null);

  const handleScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (loading) return; // Prevent accidental duplicate scan submissions

    // Remove focus from email editor to dismiss popovers and extensions
    textareaRef.current?.blur();

    if (!emailContent.trim()) {
      setError("Please enter email text to analyze.");
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const scanData = await api.scanEmail(
        emailContent.trim(),
        subject.trim() || undefined,
        sender.trim() || undefined
      );
      setResult(scanData);

      // Notify parent to refresh detection history immediately
      if (onScanCompleted) {
        onScanCompleted(scanData);
      }

      // Ensure scanner result is brought into view smoothly without obstruction
      setTimeout(() => {
        resultRef.current?.scrollIntoView({ behavior: "smooth", block: "nearest" });
      }, 50);
    } catch (err: any) {
      setError(err.message || "Failed to scan email.");
    } finally {
      setLoading(false);
    }
  };

  const loadPreset = (preset: typeof PRESET_SAMPLES[0]) => {
    setSubject(preset.subject);
    setSender(preset.sender);
    setEmailContent(preset.body);
    setResult(null);
    setError(null);
  };

  const threatCfg = result ? getThreatLevelConfig(result.threat_level) : null;

  return (
    <div className="space-y-8">
      {/* Page Title & Preset Selectors */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1
            className={`text-2xl font-bold flex items-center gap-2 ${
              isDark ? "text-white" : "text-slate-900 font-extrabold"
            }`}
          >
            <ShieldCheck className={`w-7 h-7 ${isDark ? "text-cyan-400" : "text-sky-600"}`} />
            Live Email Threat Scanner
          </h1>
          <p className={`text-sm ${isDark ? "text-slate-400" : "text-slate-600"}`}>
            Enterprise dual-model analysis, lexical URL defanging, and heuristic threat scoring
          </p>
        </div>

        {/* Quick Sample Presets */}
        <div className="flex flex-wrap items-center gap-2">
          <span className={`text-xs font-mono uppercase tracking-wider ${isDark ? "text-slate-500" : "text-slate-600"}`}>
            Load Threat Sample:
          </span>
          {PRESET_SAMPLES.map((p, idx) => (
            <button
              key={idx}
              type="button"
              onClick={() => loadPreset(p)}
              className={`text-xs px-2.5 py-1.5 rounded-lg border transition-all font-medium cursor-pointer ${
                isDark
                  ? "bg-slate-900 border-slate-800 hover:border-cyan-500/50 hover:bg-slate-800 text-slate-300"
                  : "bg-white border-slate-300 hover:border-sky-400 hover:bg-slate-50 text-slate-700 shadow-xs"
              }`}
            >
              {p.label}
            </button>
          ))}
        </div>
      </div>

      {/* Main Grid: Input Form on Left, Instant Result on Right */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Left Column: Input Form (5 cols on large) */}
        <div className="lg:col-span-5 space-y-4">
          <form
            onSubmit={handleScan}
            className={`rounded-xl p-6 border space-y-4 shadow-xl transition-colors ${
              isDark
                ? "bg-[#0E1726]/80 border-slate-800"
                : "bg-white border-slate-200 shadow-sm"
            }`}
          >
            <h2
              className={`text-sm font-semibold uppercase font-mono tracking-wider flex items-center gap-2 ${
                isDark ? "text-cyan-400" : "text-sky-700 font-bold"
              }`}
            >
              <FileText className="w-4 h-4" />
              Email Ingestion Form
            </h2>

            <div className="grid grid-cols-1 gap-3">
              <div>
                <label className={`block text-xs font-mono mb-1 ${isDark ? "text-slate-400" : "text-slate-700"}`}>
                  Subject (Optional):
                </label>
                <input
                  type="text"
                  placeholder="e.g. Urgent Security Alert"
                  value={subject}
                  onChange={(e) => setSubject(e.target.value)}
                  className={`w-full px-3 py-2 border rounded-lg text-sm transition-colors focus:outline-none focus:border-cyan-500 ${
                    isDark
                      ? "bg-slate-900/90 border-slate-800 text-slate-200 placeholder-slate-600"
                      : "bg-slate-50 border-slate-300 text-slate-900 placeholder-slate-400"
                  }`}
                />
              </div>

              <div>
                <label className={`block text-xs font-mono mb-1 ${isDark ? "text-slate-400" : "text-slate-700"}`}>
                  Sender (Optional):
                </label>
                <input
                  type="text"
                  placeholder="e.g. alert@paypa1.com"
                  value={sender}
                  onChange={(e) => setSender(e.target.value)}
                  className={`w-full px-3 py-2 border rounded-lg text-sm transition-colors focus:outline-none focus:border-cyan-500 ${
                    isDark
                      ? "bg-slate-900/90 border-slate-800 text-slate-200 placeholder-slate-600"
                      : "bg-slate-50 border-slate-300 text-slate-900 placeholder-slate-400"
                  }`}
                />
              </div>

              <div>
                <label className={`block text-xs font-mono mb-1 ${isDark ? "text-slate-400" : "text-slate-700"}`}>
                  Email Body:
                </label>
                <textarea
                  ref={textareaRef}
                  rows={8}
                  placeholder="Paste email text or phishing notice here..."
                  value={emailContent}
                  onChange={(e) => setEmailContent(e.target.value)}
                  data-gramm="false"
                  data-enable-grammarly="false"
                  spellCheck={false}
                  className={`w-full px-3 py-2 border rounded-lg text-xs font-mono transition-colors focus:outline-none focus:border-cyan-500 resize-y ${
                    isDark
                      ? "bg-slate-900/90 border-slate-800 text-slate-200 placeholder-slate-600"
                      : "bg-slate-50 border-slate-300 text-slate-900 placeholder-slate-400"
                  }`}
                  required
                />
              </div>
            </div>

            {error && (
              <div className="p-3 rounded-lg bg-rose-950/60 border border-rose-500/40 text-rose-300 text-xs flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                <span>{error}</span>
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className={`w-full py-3 px-4 rounded-lg font-semibold text-sm transition-all flex items-center justify-center gap-2 disabled:opacity-50 cursor-pointer cyber-card-hover ${
                isDark
                  ? "bg-gradient-to-r from-purple-600 via-indigo-600 to-cyan-500 hover:from-purple-500 hover:to-cyan-400 text-white shadow-[0_0_20px_rgba(6,182,212,0.3)]"
                  : "bg-gradient-to-r from-sky-600 to-indigo-600 hover:from-sky-500 hover:to-indigo-500 text-white shadow-sm"
              }`}
            >
              {loading ? (
                <>
                  <div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin"></div>
                  <span>Executing Multi-Engine Threat Scan...</span>
                </>
              ) : (
                <>
                  <ShieldAlert className="w-4 h-4" />
                  <span>Execute Threat Scan</span>
                </>
              )}
            </button>
          </form>
        </div>

        {/* Right Column: Scan Result (7 cols on large) */}
        <div ref={resultRef} className="lg:col-span-7 relative z-20">
          {result && threatCfg ? (
            <div
              className={`rounded-xl p-6 border ${threatCfg.border} ${
                isDark ? threatCfg.bg : "bg-white shadow-md"
              } space-y-6 shadow-2xl transition-colors`}
            >
              {/* Verdict Header */}
              <div
                className={`flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b ${
                  isDark ? "border-slate-800/80" : "border-slate-200"
                }`}
              >
                <div>
                  <div className="flex items-center gap-2 mb-1 flex-wrap">
                    <span className={`text-xs px-2.5 py-0.5 rounded font-mono font-bold border ${threatCfg.badgeBg}`}>
                      {threatCfg.label}
                    </span>
                    <span className={`text-xs font-mono ${isDark ? "text-slate-400" : "text-slate-500"}`}>
                      ID: {result.id.slice(0, 8)}
                    </span>
                    <span className={`text-xs font-mono px-2 py-0.5 rounded border ${
                      isDark ? "bg-slate-900/80 border-slate-700/60 text-cyan-300" : "bg-sky-50 border-sky-300 text-sky-800 font-semibold"
                    }`}>
                      Scanned: {formatIST(result.created_at)}
                    </span>
                  </div>
                  <h3 className={`text-xl font-bold tracking-wide ${isDark ? "text-white" : "text-slate-900"}`}>
                    {result.verdict}
                  </h3>
                </div>

                {/* Score Dial */}
                <div className="flex items-center gap-3">
                  <div className="text-right">
                    <span className={`block text-2xl font-black font-mono ${isDark ? "text-white" : "text-slate-900"}`}>
                      {result.risk_score}
                      <span className={`text-xs font-normal ${isDark ? "text-slate-400" : "text-slate-500"}`}> / 100</span>
                    </span>
                    <span className={`text-[10px] uppercase font-mono tracking-widest ${isDark ? "text-slate-400" : "text-slate-500"}`}>
                      Risk Score
                    </span>
                  </div>
                </div>
              </div>

              {/* Multi-Engine Contribution Breakdown */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div
                  className={`p-3 rounded-lg border ${
                    isDark ? "bg-slate-900/80 border-slate-800" : "bg-slate-50 border-slate-200"
                  }`}
                >
                  <span className={`text-[11px] font-mono block ${isDark ? "text-slate-400" : "text-slate-600"}`}>
                    Phishing Likelihood
                  </span>
                  <span className={`text-lg font-bold font-mono ${isDark ? "text-white" : "text-slate-900"}`}>
                    {(result.phishing_probability * 100).toFixed(1)}%
                  </span>
                </div>
                <div
                  className={`p-3 rounded-lg border ${
                    isDark ? "bg-slate-900/80 border-slate-800" : "bg-slate-50 border-slate-200"
                  }`}
                >
                  <span className={`text-[11px] font-mono block ${isDark ? "text-slate-400" : "text-slate-600"}`}>
                    Spam Likelihood
                  </span>
                  <span className={`text-lg font-bold font-mono ${isDark ? "text-white" : "text-slate-900"}`}>
                    {(result.spam_probability * 100).toFixed(1)}%
                  </span>
                </div>
                <div
                  className={`p-3 rounded-lg border ${
                    isDark ? "bg-slate-900/80 border-slate-800" : "bg-slate-50 border-slate-200"
                  }`}
                >
                  <span className={`text-[11px] font-mono block ${isDark ? "text-slate-400" : "text-slate-600"}`}>
                    URL Risk Score
                  </span>
                  <span className={`text-lg font-bold font-mono ${isDark ? "text-white" : "text-slate-900"}`}>
                    {(result.url_risk_score * 100).toFixed(1)}%
                  </span>
                </div>
                <div
                  className={`p-3 rounded-lg border ${
                    isDark ? "bg-slate-900/80 border-slate-800" : "bg-slate-50 border-slate-200"
                  }`}
                >
                  <span className={`text-[11px] font-mono block ${isDark ? "text-slate-400" : "text-slate-600"}`}>
                    Headers Status
                  </span>
                  <span
                    className={`text-sm font-semibold capitalize truncate block ${
                      isDark ? "text-slate-200" : "text-slate-800"
                    }`}
                  >
                    {result.has_headers ? result.header_details.status : "Omitted"}
                  </span>
                </div>
              </div>

              {/* Transparent Header Verification Note */}
              {!result.has_headers && (
                <div
                  className={`p-3 rounded-lg border flex items-start gap-2.5 text-xs ${
                    isDark
                      ? "bg-slate-900/60 border-slate-800/80 text-slate-400"
                      : "bg-sky-50 border-sky-200 text-sky-800"
                  }`}
                >
                  <Info className="w-4 h-4 text-cyan-500 shrink-0 mt-0.5" />
                  <span>
                    <strong>Transparent Header Notice:</strong> Email was analyzed from plain body text. SPF/DKIM/DMARC authentication checks require transport headers and were safely not evaluated.
                  </span>
                </div>
              )}

              {/* Extracted & Defanged URLs */}
              <div className="space-y-2">
                <h4
                  className={`text-xs font-mono uppercase tracking-wider flex items-center gap-1.5 ${
                    isDark ? "text-slate-400" : "text-slate-600"
                  }`}
                >
                  <Link2 className="w-3.5 h-3.5 text-cyan-500" />
                  Detected & Defanged URLs ({result.detected_urls.length})
                </h4>
                {result.detected_urls.length === 0 ? (
                  <p className="text-xs text-slate-500 italic">No embedded URLs found in this message.</p>
                ) : (
                  <div className="space-y-2 max-h-44 overflow-y-auto pr-1">
                    {result.detected_urls.map((u, idx) => (
                      <div
                        key={idx}
                        className={`p-2.5 rounded border text-xs flex flex-col gap-1 ${
                          isDark
                            ? "bg-slate-900/90 border-slate-800"
                            : "bg-slate-50 border-slate-200"
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <code className={`font-mono truncate max-w-sm ${isDark ? "text-cyan-300" : "text-sky-700"}`}>
                            {u.defanged_url}
                          </code>
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                              u.is_suspicious ? "bg-rose-500/20 text-rose-400" : "bg-emerald-500/20 text-emerald-400"
                            }`}
                          >
                            Entropy: {u.entropy} {u.is_suspicious ? "• SUSPICIOUS" : "• Standard"}
                          </span>
                        </div>
                        {u.risk_reasons.length > 0 && (
                          <div className="text-[11px] text-rose-500 font-medium">
                            Markers: {u.risk_reasons.join(", ")}
                          </div>
                        )}
                        <div className={`text-[10px] ${isDark ? "text-slate-500" : "text-slate-500"}`}>
                          {u.verification_note}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Explainable AI (XAI) Keyword Attribution */}
              {result.xai_report && (
                <div className="space-y-2">
                  <h4
                    className={`text-xs font-mono uppercase tracking-wider flex items-center gap-1.5 ${
                      isDark ? "text-slate-400" : "text-slate-600"
                    }`}
                  >
                    <Sparkles className="w-3.5 h-3.5 text-purple-500" />
                    Explainable AI (XAI) Trigger Tokens
                  </h4>
                  <div className="flex flex-wrap gap-1.5">
                    {result.xai_report.top_phish_words?.map((w, idx) => (
                      <span
                        key={idx}
                        className="px-2 py-0.5 rounded text-xs font-mono bg-purple-500/20 text-purple-400 border border-purple-500/30"
                      >
                        {w}
                      </span>
                    ))}
                    {result.xai_report.top_spam_words?.map((w, idx) => (
                      <span
                        key={idx}
                        className="px-2 py-0.5 rounded text-xs font-mono bg-indigo-500/20 text-indigo-400 border border-indigo-500/30"
                      >
                        {w}
                      </span>
                    ))}
                    {!result.xai_report.top_phish_words?.length && !result.xai_report.top_spam_words?.length && (
                      <span className="text-xs text-slate-500 italic">No significant malicious tokens detected.</span>
                    )}
                  </div>
                </div>
              )}

              {/* SOC Recommendations */}
              {result.recommendations && result.recommendations.length > 0 && (
                <div
                  className={`p-4 rounded-xl border ${
                    isDark
                      ? "bg-[#0E1726]/60 border-slate-800/80"
                      : "bg-slate-50 border-slate-200"
                  }`}
                >
                  <div className="flex items-center gap-2 mb-2.5">
                    <ShieldCheck className={`w-4 h-4 ${isDark ? "text-cyan-400" : "text-cyan-600"}`} />
                    <span className={`text-xs font-mono uppercase tracking-wider font-semibold ${
                      isDark ? "text-slate-300" : "text-slate-700"
                    }`}>
                      SOC Recommendations
                    </span>
                    <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full ${
                      isDark ? "bg-slate-800 text-slate-400 border border-slate-700/60" : "bg-slate-200 text-slate-600 font-medium"
                    }`}>
                      {result.recommendations.length} Action{result.recommendations.length === 1 ? "" : "s"}
                    </span>
                  </div>
                  <ul className="space-y-1.5">
                    {result.recommendations.map((rec, idx) => (
                      <li
                        key={idx}
                        className={`text-xs flex items-start gap-2.5 leading-relaxed ${
                          isDark ? "text-slate-300" : "text-slate-700"
                        }`}
                      >
                        <span className={`inline-block w-1.5 h-1.5 rounded-full mt-1.5 shrink-0 ${
                          isDark ? "bg-cyan-400" : "bg-cyan-600"
                        }`} />
                        <span>{rec}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Action Toolbar */}
              <div
                className={`pt-5 border-t ${
                  isDark ? "border-slate-800/80" : "border-slate-200"
                }`}
              >
                <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-3 w-full">
                  {onNavigateToHistory && (
                    <button
                      type="button"
                      onClick={onNavigateToHistory}
                      className={`w-full h-11 px-3.5 rounded-xl border text-xs font-mono font-bold inline-flex items-center justify-center gap-2 transition-all cursor-pointer whitespace-nowrap sm:col-span-1 xl:col-span-1 ${
                        isDark
                          ? "bg-slate-800/90 hover:bg-slate-700 text-slate-200 border-slate-700 shadow-xs hover:border-slate-600"
                          : "bg-slate-100 hover:bg-slate-200 text-slate-800 border-slate-300 shadow-xs hover:border-slate-400"
                      }`}
                      title="View in Detection History"
                    >
                      <History className="w-4 h-4 text-cyan-400 shrink-0" />
                      <span>View in Detection History</span>
                    </button>
                  )}

                  {onLaunchCopilot && (
                    <button
                      type="button"
                      onClick={() =>
                        onLaunchCopilot(
                          emailContent,
                          result.has_headers ? JSON.stringify(result.header_details) : "none",
                          result.id
                        )
                      }
                      className={`w-full h-11 px-3.5 rounded-xl border text-xs font-mono font-bold inline-flex items-center justify-center gap-2 transition-all cursor-pointer whitespace-nowrap sm:col-span-1 xl:col-span-1 ${
                        isDark
                          ? "bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-300 border-cyan-500/40 shadow-[0_0_12px_rgba(6,182,212,0.2)] hover:border-cyan-400/60"
                          : "bg-sky-50 hover:bg-sky-100 text-sky-800 border-sky-300 shadow-xs hover:border-sky-400"
                      }`}
                      title="Consult Sentinel Copilot"
                    >
                      <MessageSquareCode className="w-4 h-4 text-cyan-500 shrink-0" />
                      <span>Consult Sentinel Copilot</span>
                    </button>
                  )}

                  <button
                    type="button"
                    onClick={() =>
                      onLaunchAgent(
                        emailContent,
                        result.has_headers ? JSON.stringify(result.header_details) : "none",
                        result.id
                      )
                    }
                    className="w-full h-11 px-4 rounded-xl bg-gradient-to-r from-purple-600 via-indigo-600 to-purple-600 hover:from-purple-500 hover:via-indigo-500 hover:to-purple-500 text-white font-mono font-bold text-xs inline-flex items-center justify-center gap-2 shadow-[0_0_16px_rgba(168,85,247,0.35)] hover:shadow-[0_0_20px_rgba(168,85,247,0.5)] border border-purple-400/30 transition-all cursor-pointer whitespace-nowrap sm:col-span-2 xl:col-span-1 group"
                    title="Launch Deep AI Agent"
                  >
                    <Sparkles className="w-4 h-4 text-purple-200 shrink-0" />
                    <span>Launch Deep AI Agent</span>
                    <ArrowRight className="w-4 h-4 text-purple-200 shrink-0 transition-transform group-hover:translate-x-0.5" />
                  </button>
                </div>
              </div>
            </div>
          ) : (
            <div
              className={`h-full min-h-[400px] rounded-xl border border-dashed flex flex-col items-center justify-center p-8 text-center transition-colors ${
                isDark
                  ? "border-slate-800 bg-[#0E1726]/40"
                  : "border-slate-300 bg-white shadow-xs"
              }`}
            >
              <ShieldAlert className={`w-12 h-12 mb-3 ${isDark ? "text-slate-700" : "text-slate-400"}`} />
              <h3 className={`font-semibold mb-1 ${isDark ? "text-slate-400" : "text-slate-700"}`}>
                Awaiting Security Scan
              </h3>
              <p className={`text-xs max-w-sm ${isDark ? "text-slate-600" : "text-slate-500"}`}>
                Provide an email body or load a threat sample above and click Execute Threat Scan to generate forensic intelligence.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
