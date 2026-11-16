import React, { useState, useEffect } from "react";
import {
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  Copy,
  Check,
  Download,
  Printer,
  ChevronDown,
  ChevronUp,
  Terminal,
  ExternalLink,
  Layers,
  Clock,
  FileText,
  Search,
  Globe,
  AlertTriangle,
  RefreshCw
} from "lucide-react";
import { useTheme } from "../context/ThemeContext";
import type { AgentInvestigation, UrlThreatIntelResponse } from "../types";
import { api } from "../api/client";
import { formatIST, safeIsoUtc } from "../utils/dateFormatter";

interface InteractiveSocReportProps {
  investigation: AgentInvestigation;
  emailText?: string;
  headersText?: string;
  scanId?: string;
}

export const InteractiveSocReport: React.FC<InteractiveSocReportProps> = ({
  investigation,
  emailText = "",
  headersText = "none",
  scanId
}) => {
  const { isDark } = useTheme();

  // Accordion section collapse state
  const [collapsedSections, setCollapsedSections] = useState<Record<string, boolean>>({
    telemetry: false,
    urls: false,
    timeline: false,
    findings: false
  });

  // Tool JSON expanded state
  const [expandedSteps, setExpandedSteps] = useState<Record<number, boolean>>({});

  // Deep URL threat intelligence drawer state: { urlIndex: UrlThreatIntelResponse | null }
  const [urlIntelData, setUrlIntelData] = useState<Record<string, UrlThreatIntelResponse>>({});
  const [loadingUrlIntel, setLoadingUrlIntel] = useState<Record<string, boolean>>({});

  // Active URLs state: initialized from investigation or extracted from emailText
  const [activeUrls, setActiveUrls] = useState<any[]>([]);
  const [isExtractingUrls, setIsExtractingUrls] = useState<boolean>(false);
  const [urlExtractionError, setUrlExtractionError] = useState<string | null>(null);
  const [expandedUrlCards, setExpandedUrlCards] = useState<Record<string, boolean>>({});
  const [copiedUrlKey, setCopiedUrlKey] = useState<string | null>(null);

  const handleCopyDefangedUrl = (defangedUrl: string, key: string, e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(defangedUrl);
    setCopiedUrlKey(key);
    setTimeout(() => setCopiedUrlKey(null), 2000);
  };

  const toggleUrlCard = (key: string) => {
    setExpandedUrlCards((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const getVerdictBadge = (verdict?: string, isSuspicious?: boolean) => {
    const v = (verdict || (isSuspicious ? "SUSPICIOUS" : "UNKNOWN")).toUpperCase();
    if (v === "MALICIOUS") {
      return {
        label: "MALICIOUS",
        badgeClass: isDark
          ? "bg-rose-950/80 text-rose-300 border-rose-800"
          : "bg-rose-100 text-rose-800 border-rose-200"
      };
    }
    if (v === "SUSPICIOUS") {
      return {
        label: "SUSPICIOUS",
        badgeClass: isDark
          ? "bg-amber-950/80 text-amber-300 border-amber-800"
          : "bg-amber-100 text-amber-800 border-amber-200"
      };
    }
    if (v === "CLEAN") {
      return {
        label: "CLEAN",
        badgeClass: isDark
          ? "bg-emerald-950/80 text-emerald-300 border-emerald-800"
          : "bg-emerald-100 text-emerald-800 border-emerald-200"
      };
    }
    if (v === "NOT_ANALYZED" || v === "NOT ANALYZED") {
      return {
        label: "NOT ANALYZED",
        badgeClass: isDark
          ? "bg-slate-800 text-slate-400 border-slate-700"
          : "bg-slate-100 text-slate-600 border-slate-300"
      };
    }
    return {
      label: "UNKNOWN",
      badgeClass: isDark
        ? "bg-slate-800 text-indigo-300 border-slate-700"
        : "bg-slate-100 text-indigo-800 border-slate-300"
    };
  };

  // Action feedback states
  const [copied, setCopied] = useState(false);
  const [exported, setExported] = useState(false);

  // Status evaluator for timeline execution steps
  const getStepStatus = (st: { tool: string; output: any }): "success" | "warning" | "failed" | "running" => {
    const out = st.output;
    if (!out) return "success";
    if (typeof out === "object") {
      if (out.error || out.failed || out.status === "failed") {
        return "failed";
      }
      if (
        out.is_phishing === true ||
        out.is_spam === true ||
        out.threat_detected === true ||
        out.flagged === true ||
        (typeof out.risk_score === "number" && out.risk_score >= 60) ||
        (typeof out.threat_score === "number" && out.threat_score >= 60) ||
        (Array.isArray(out.suspicious_urls) && out.suspicious_urls.length > 0) ||
        (Array.isArray(out.flags) && out.flags.length > 0)
      ) {
        return "warning";
      }
    }
    return "success";
  };

  // SOC Defensive Recommendations
  const defaultRecommendations = [
    "Quarantine email from all recipient mailboxes immediately",
    "Block identified sender IP and sender domain at mail gateway",
    "Defang and blackhole extracted malicious URLs in DNS resolver",
    "Force password reset and revoke active OAuth tokens for targeted accounts",
    "Submit indicators of compromise (IOCs) to internal SIEM / threat intelligence feed"
  ];

  const toggleSection = (section: string) => {
    setCollapsedSections((prev) => ({ ...prev, [section]: !prev[section] }));
  };

  const toggleStep = (stepNum: number) => {
    setExpandedSteps((prev) => ({ ...prev, [stepNum]: !prev[stepNum] }));
  };

  const toggleAllSections = () => {
    const anyCollapsed = Object.values(collapsedSections).some(Boolean);
    setCollapsedSections({
      telemetry: !anyCollapsed,
      urls: !anyCollapsed,
      timeline: !anyCollapsed,
      findings: !anyCollapsed
    });
  };

  // Inspect URL deep threat intelligence
  const handleInspectUrl = async (rawUrl: string, key: string) => {
    if (urlIntelData[key]) return; // already loaded
    setLoadingUrlIntel((prev) => ({ ...prev, [key]: true }));
    try {
      const res = await api.analyzeUrl(rawUrl, true);
      setUrlIntelData((prev) => ({ ...prev, [key]: res }));
    } catch (err) {
      console.error("Failed to deep inspect URL:", err);
    } finally {
      setLoadingUrlIntel((prev) => ({ ...prev, [key]: false }));
    }
  };

  // Helper to safely extract original email received date from headers or body
  const extractEmailReceivedDate = (headers: string, email: string): { dateStr: string | null; isPresent: boolean } => {
    const combined = `${headers}\n${email}`;
    const match = combined.match(/^Date:\s*(.+)$/im);
    if (match && match[1]) {
      const rawDate = match[1].trim();
      const parsed = new Date(rawDate);
      if (!isNaN(parsed.getTime())) {
        return { dateStr: formatIST(parsed), isPresent: true };
      }
      return { dateStr: rawDate, isPresent: true };
    }
    return { dateStr: null, isPresent: false };
  };

  const emailDateInfo = extractEmailReceivedDate(headersText, emailText);

  // Copy Complete Report
  const handleCopyReport = () => {
    const reportText = `=====================================================
MAILSENTINEL AI - SOC INCIDENT INVESTIGATION REPORT
=====================================================
Verdict: ${investigation.verdict}
Threat Score: ${investigation.risk_score} / 100 (${investigation.threat_level})
Model: ${investigation.model_used} (${investigation.agent_mode})
Investigation Finalized: ${formatIST(investigation.created_at || new Date())}
Timestamp (UTC): ${safeIsoUtc(investigation.created_at || new Date())}
Display Timezone: Asia/Kolkata (IST - UTC+05:30)
Original Email Received: ${emailDateInfo.isPresent ? `${emailDateInfo.dateStr} (Header Date)` : "Not present in transport headers"}
Scan Reference: ${scanId || "None"}

SUMMARY FINDINGS:
${investigation.final_report}

TOOL EXECUTION TIMELINE:
${investigation.steps.map((s) => `[Step ${s.step}] ${s.tool}():\n${JSON.stringify(s.output, null, 2)}`).join("\n\n")}

DEFENSIVE ACTIONS RECOMMENDED:
${defaultRecommendations.map((r) => `• ${r}`).join("\n")}
=====================================================`;

    navigator.clipboard.writeText(reportText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2500);
  };

  // Export JSON file
  const handleExportJson = () => {
    const payload = {
      investigation,
      evidence: {
        email_content: emailText,
        headers: headersText,
        scan_id: scanId,
        email_received_timestamp: emailDateInfo.isPresent ? emailDateInfo.dateStr : null,
        email_received_status: emailDateInfo.isPresent ? "extracted_from_header" : "omitted_in_headers"
      },
      recommendations: defaultRecommendations,
      investigation_finalized_ist: formatIST(investigation.created_at || new Date()),
      exported_at_utc: new Date().toISOString(),
      exported_at_ist: formatIST(new Date()),
      display_timezone: "Asia/Kolkata (IST - UTC+05:30)"
    };
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(payload, null, 2));
    const downloadAnchor = document.createElement("a");
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `mailsentinel-soc-investigation-${scanId || "report"}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
    setExported(true);
    setTimeout(() => setExported(false), 2500);
  };

  // Trigger Print / PDF
  const handlePrintPdf = () => {
    window.print();
  };

  // Extract empirical tool outputs
  const spamStep = investigation.steps.find((s) => s.tool === "analyze_spam_probability")?.output || {};
  const phishStep = investigation.steps.find((s) => s.tool === "analyze_phishing_probability")?.output || {};
  const urlsStep = investigation.steps.find((s) => s.tool === "inspect_email_urls")?.output || {};
  const headersStep = (investigation.steps.find((s) => s.tool === "inspect_email_headers")?.output || {}) as {
    spf?: string;
    dkim?: string;
    dmarc?: string;
    sender_domain?: string;
  };

  const spamProb = spamStep.spam_probability ?? 0.0;
  const phishProb = phishStep.phishing_probability ?? 0.0;
  const detectedUrls = urlsStep.inspected_urls || [];

  // Synchronize active URLs from investigation steps or auto-extract from evidence payload
  useEffect(() => {
    if (detectedUrls && detectedUrls.length > 0) {
      setActiveUrls(detectedUrls);
    } else if (emailText && emailText.trim()) {
      setIsExtractingUrls(true);
      setUrlExtractionError(null);
      api.extractAndAnalyzeUrls(emailText, false)
        .then((res) => {
          if (res && res.length > 0) {
            setActiveUrls(res);
          } else {
            setActiveUrls([]);
          }
        })
        .catch((err) => {
          console.warn("Background URL extraction encountered an issue:", err);
          setUrlExtractionError("Failed to automatically extract URLs from evidence text.");
        })
        .finally(() => setIsExtractingUrls(false));
    } else {
      setActiveUrls([]);
    }
  }, [detectedUrls, emailText]);

  // Gauge calculation
  const score = Math.min(100, Math.max(0, investigation.risk_score));
  const circumference = 2 * Math.PI * 40; // r=40
  const strokeDashoffset = circumference - (score / 100) * circumference;

  const scoreColor =
    score >= 75 ? "#EF4444" : score >= 40 ? "#F59E0B" : "#10B981";

  const getSeverityCategory = (level: string = "") => {
    const l = level.toUpperCase();
    if (l === "MALICIOUS" || l === "DANGEROUS" || l === "CRITICAL") return "malicious";
    if (l === "SUSPICIOUS") return "suspicious";
    if (l === "CLEAN" || l === "SAFE") return "clean";
    return "unknown";
  };
  const severityCategory = getSeverityCategory(investigation.threat_level);

  return (
    <div className="space-y-6 print:space-y-4">
      {/* Top Header & Actions Bar */}
      <div
        className={`soc-report-container p-4 sm:p-5 rounded-2xl border flex flex-col sm:flex-row sm:items-center justify-between gap-4 shadow-sm transition-all ${
          isDark ? "bg-[#0E1726] border-purple-500/30" : "bg-white border-purple-200 shadow-xs"
        }`}
      >
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-purple-500 animate-pulse"></span>
            <span className={`text-xs font-mono uppercase font-bold tracking-wider ${isDark ? "text-purple-300" : "text-purple-800"}`}>
              Interactive SOC Assessment
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-purple-500/10 text-purple-400 border border-purple-500/20">
              Verified Telemetry
            </span>
          </div>
          <h2 className={`text-lg sm:text-xl font-bold ${isDark ? "text-white" : "text-slate-900 font-extrabold"}`}>
            SOC Incident Assessment Report
          </h2>
        </div>

        {/* Action Buttons: Copy, PDF, JSON, Collapse All (Phase 4.4 Distinct Color Identity) */}
        <div className="flex items-center flex-wrap gap-2 text-xs font-mono print:hidden">
          <button
            onClick={handleCopyReport}
            className="soc-report-action soc-btn-copy px-3 py-1.5 rounded-lg border font-bold flex items-center gap-1.5 cursor-pointer"
            title="Copy structured text report"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-cyan-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? "Copied!" : "Copy Report"}</span>
          </button>

          <button
            onClick={handlePrintPdf}
            className="soc-report-action soc-btn-print px-3 py-1.5 rounded-lg border font-bold flex items-center gap-1.5 cursor-pointer"
            title="Export or print PDF report"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>Print PDF</span>
          </button>

          <button
            onClick={handleExportJson}
            className="soc-report-action soc-btn-export px-3 py-1.5 rounded-lg border font-bold flex items-center gap-1.5 cursor-pointer"
            title="Download full JSON report"
          >
            {exported ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Download className="w-3.5 h-3.5" />}
            <span>{exported ? "Exported!" : "Export JSON"}</span>
          </button>

          <button
            onClick={toggleAllSections}
            className="soc-report-action soc-btn-toggle px-3 py-1.5 rounded-lg border font-bold flex items-center gap-1.5 cursor-pointer"
            title={!Object.values(collapsedSections).some(Boolean) ? "Collapse all report sections" : "Expand all report sections"}
            aria-expanded={!Object.values(collapsedSections).some(Boolean)}
          >
            <ChevronDown
              className={`w-3.5 h-3.5 transition-transform duration-300 ${
                !Object.values(collapsedSections).some(Boolean) ? "rotate-180" : ""
              }`}
            />
            <span>Toggle All</span>
          </button>
        </div>
      </div>

      {/* Threat Verdict & Animated Score Gauge Card */}
      <div
        className={`soc-threat-card soc-threat-card-${severityCategory} p-6 rounded-2xl border shadow-md transition-all grid grid-cols-1 md:grid-cols-12 gap-6 items-center ${
          isDark ? "bg-[#0E1726] border-slate-800" : "bg-white border-slate-200 shadow-xs"
        }`}
      >
        {/* Left: Verdict details */}
        <div className="md:col-span-8 space-y-3">
          <div className="flex items-center gap-2 flex-wrap">
            <span
              className={`soc-verdict-pulse soc-verdict-pulse-${severityCategory} px-3 py-1 rounded-full font-mono font-bold text-xs border ${
                investigation.threat_level === "SAFE"
                  ? "bg-emerald-950/60 text-emerald-300 border-emerald-700/60"
                  : investigation.threat_level === "SUSPICIOUS"
                  ? "bg-amber-950/60 text-amber-300 border-amber-700/60"
                  : "bg-rose-950/60 text-rose-300 border-rose-700/60"
              }`}
            >
              {investigation.threat_level} THREAT
            </span>
            <span className="text-xs font-mono text-slate-400">
              Provenance: <strong>{investigation.model_used}</strong> ({investigation.agent_mode})
            </span>
            <span className={`text-xs font-mono px-2 py-0.5 rounded border ${
              isDark ? "bg-slate-900 border-slate-700 text-cyan-300" : "bg-sky-50 border-sky-300 text-sky-800 font-semibold"
            }`}>
              Finalized: {formatIST(investigation.created_at || new Date())}
            </span>
          </div>

          {/* Email Received provenance timestamp */}
          <div className="flex items-center gap-2 text-xs font-mono">
            <span className={isDark ? "text-slate-400" : "text-slate-600"}>
              Email Received:{" "}
              {emailDateInfo.isPresent ? (
                <strong className={isDark ? "text-slate-200" : "text-slate-800"}>
                  {emailDateInfo.dateStr} (from header)
                </strong>
              ) : (
                <span className="italic text-slate-500">Not present in email transport headers</span>
              )}
            </span>
          </div>

          <div className="flex items-center gap-3">
            {investigation.threat_level === "SAFE" ? (
              <ShieldCheck className="w-8 h-8 text-emerald-400 shrink-0" />
            ) : (
              <ShieldAlert className="w-8 h-8 text-rose-500 shrink-0" />
            )}
            <h3 className={`text-xl sm:text-2xl font-extrabold ${isDark ? "text-white" : "text-slate-900"}`}>
              {investigation.verdict || "Investigation Finalized"}
            </h3>
          </div>

          <p className={`text-xs font-medium leading-relaxed ${isDark ? "text-slate-300" : "text-slate-700"}`}>
            Empirical multi-tier analysis completed in {investigation.steps_count} distinct steps with verified passive tool calls.
          </p>
        </div>

        {/* Right: Circular Gauge */}
        <div className="md:col-span-4 flex flex-col items-center justify-center p-3">
          <div className={`soc-score-gauge soc-score-gauge-${severityCategory} relative w-28 h-28 flex items-center justify-center`}>
            <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
              <circle
                cx="50"
                cy="50"
                r="40"
                stroke={isDark ? "#1E293B" : "#E2E8F0"}
                strokeWidth="8"
                fill="transparent"
              />
              <circle
                cx="50"
                cy="50"
                r="40"
                stroke={scoreColor}
                strokeWidth="8"
                strokeDasharray={circumference}
                strokeDashoffset={strokeDashoffset}
                strokeLinecap="round"
                fill="transparent"
                style={{ transition: "stroke-dashoffset 0.8s cubic-bezier(0.16, 1, 0.3, 1)" }}
              />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
              <span className={`text-2xl font-mono font-extrabold ${isDark ? "text-white" : "text-slate-900"}`}>
                {score}
              </span>
              <span className="text-[10px] font-mono uppercase text-slate-400 font-bold">
                / 100 Score
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Dual Machine Learning Likelihood Visualizations */}
      <div
        className={`telemetry-container-glow p-5 rounded-2xl border transition-colors space-y-4 ${
          isDark ? "bg-[#0E1726] border-slate-800" : "bg-white border-slate-200 shadow-xs"
        }`}
      >
        <div className="flex items-center justify-between">
          <button
            onClick={() => toggleSection("telemetry")}
            className="flex items-center gap-2 font-mono text-xs uppercase font-bold tracking-wider cursor-pointer text-left"
          >
            <Layers className="w-4 h-4 text-purple-400" />
            <span className={isDark ? "text-purple-300" : "text-purple-800"}>
              Dual-Engine Machine Learning Telemetry
            </span>
          </button>
          <button onClick={() => toggleSection("telemetry")} className="p-1 text-slate-400">
            {collapsedSections.telemetry ? <ChevronDown className="w-4 h-4" /> : <ChevronUp className="w-4 h-4" />}
          </button>
        </div>

        {!collapsedSections.telemetry && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5 pt-2 animate-page-enter">
            {/* Spam Classifier */}
            <div
              className={`telemetry-card-spam p-4 rounded-xl border space-y-2.5 ${
                isDark ? "bg-slate-900/80 border-slate-800" : "bg-slate-50 border-slate-200"
              }`}
            >
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="font-bold flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-cyan-400 shadow-[0_0_8px_rgba(6,182,212,0.8)]" />
                  <span className={isDark ? "text-cyan-300" : "text-sky-900"}>Spam Likelihood</span>
                </span>
                <span className={`font-bold text-sm ${isDark ? "text-cyan-400" : "text-sky-700"}`}>
                  {(spamProb * 100).toFixed(1)}%
                </span>
              </div>
              {/* Progress bar with soft radial track glow and cyan aura */}
              <div className="w-full h-3 rounded-full bg-slate-800/90 p-0.5 border border-slate-700/60 overflow-hidden relative">
                <div
                  className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-blue-500 transition-all duration-500 progress-bar-aura-spam"
                  style={{ width: `${Math.min(100, Math.max(2, spamProb * 100))}%` }}
                />
              </div>
              <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
                <span>Model: TF-IDF + Logistic Reg</span>
                <span className={spamStep.is_spam ? "text-cyan-400 font-bold" : "text-slate-400"}>
                  Verdict: {spamStep.is_spam ? "SPAM DETECTED" : "CLEAN"}
                </span>
              </div>
              {spamStep.detected_triggers && spamStep.detected_triggers.length > 0 && (
                <div className="flex items-center gap-1.5 flex-wrap pt-1">
                  <span className="text-[10px] font-mono text-slate-500 font-bold">Triggers:</span>
                  {spamStep.detected_triggers.slice(0, 5).map((tr: string, i: number) => (
                    <span
                      key={i}
                      className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                        isDark
                          ? "bg-cyan-950/40 text-cyan-300 border-cyan-800/50"
                          : "bg-sky-100 text-sky-800 border-sky-200 font-semibold"
                      }`}
                    >
                      {tr}
                    </span>
                  ))}
                </div>
              )}
            </div>

            {/* Phishing Classifier */}
            <div
              className={`telemetry-card-phish p-4 rounded-xl border space-y-2.5 ${
                isDark ? "bg-slate-900/80 border-slate-800" : "bg-slate-50 border-slate-200"
              }`}
            >
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="font-bold flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-amber-400 shadow-[0_0_8px_rgba(245,158,11,0.8)]" />
                  <span className={isDark ? "text-amber-300" : "text-amber-900"}>Phishing / Credential Theft</span>
                </span>
                <span className={`font-bold text-sm ${isDark ? "text-amber-400" : "text-amber-700"}`}>
                  {(phishProb * 100).toFixed(1)}%
                </span>
              </div>
              {/* Progress bar with soft radial track glow and amber-orange aura */}
              <div className="w-full h-3 rounded-full bg-slate-800/90 p-0.5 border border-slate-700/60 overflow-hidden relative">
                <div
                  className="h-full rounded-full bg-gradient-to-r from-amber-500 to-orange-500 transition-all duration-500 progress-bar-aura-phish"
                  style={{ width: `${Math.min(100, Math.max(2, phishProb * 100))}%` }}
                />
              </div>
              <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
                <span>Model: TF-IDF + Logistic Reg</span>
                <span className={phishStep.is_phishing ? "text-amber-400 font-bold" : "text-slate-400"}>
                  Verdict: {phishStep.is_phishing ? "PHISHING DETECTED" : "CLEAN"}
                </span>
              </div>
              {phishStep.detected_triggers && phishStep.detected_triggers.length > 0 && (
                <div className="flex items-center gap-1.5 flex-wrap pt-1">
                  <span className="text-[10px] font-mono text-slate-500 font-bold">Triggers:</span>
                  {phishStep.detected_triggers.slice(0, 5).map((tr: string, i: number) => (
                    <span
                      key={i}
                      className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                        isDark
                          ? "bg-amber-950/40 text-amber-300 border-amber-800/50"
                          : "bg-amber-100 text-amber-800 border-amber-200 font-semibold"
                      }`}
                    >
                      {tr}
                    </span>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* URL Threat Intelligence Section */}
      <div
        className={`url-threat-container-glow p-5 rounded-2xl border transition-colors space-y-4 ${
          isDark ? "bg-[#0E1726] border-slate-800" : "bg-white border-slate-200 shadow-xs"
        }`}
      >
        <div className="flex items-center justify-between">
          <button
            onClick={() => toggleSection("urls")}
            className="flex items-center gap-2 font-mono text-xs uppercase font-bold tracking-wider cursor-pointer text-left"
          >
            <ExternalLink className="w-4 h-4 text-cyan-400" />
            <span className={isDark ? "text-cyan-300" : "text-sky-800"}>
              URL Threat Intelligence ({activeUrls.length} Detected)
            </span>
          </button>
          <div className="flex items-center gap-2">
            {isExtractingUrls && (
              <span className="text-[11px] font-mono text-cyan-400 flex items-center gap-1.5 animate-pulse">
                <RefreshCw className="w-3 h-3 animate-spin" />
                Scanning Evidence URLs...
              </span>
            )}
            <button onClick={() => toggleSection("urls")} className="p-1 text-slate-400">
              {collapsedSections.urls ? <ChevronDown className="w-4 h-4" /> : <ChevronUp className="w-4 h-4" />}
            </button>
          </div>
        </div>

        {!collapsedSections.urls && (
          <div className="space-y-3 pt-1 animate-page-enter">
            {urlExtractionError && (
              <div className="p-3 rounded-lg border text-xs font-mono flex items-center gap-2 bg-rose-950/40 border-rose-500/30 text-rose-300">
                <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                <span>{urlExtractionError}</span>
              </div>
            )}

            {activeUrls.length === 0 ? (
              <p className="text-xs text-slate-500 italic p-3 rounded-lg border border-dashed border-slate-800">
                No embedded URLs were found in this evidence payload.
              </p>
            ) : (
              activeUrls.map((u: any, idx: number) => {
                const key = `url-${idx}`;
                const deepIntel = urlIntelData[key];
                const isLoadingIntel = loadingUrlIntel[key];
                const isExpanded = !!expandedUrlCards[key];

                const defangedUrl = u.defanged_url || u.raw_url_defanged || "";
                const normalizedUrl =
                  u.normalized_url ||
                  defangedUrl.replace(/hxxps?:\/\//i, (m: string) => m.toLowerCase().includes("s") ? "https://" : "http://").replace(/\[\.\]/g, ".");
                const domain = u.domain || (normalizedUrl ? new URL(normalizedUrl.startsWith("http") ? normalizedUrl : `http://${normalizedUrl}`).hostname : "");
                const verdict = deepIntel?.verdict || u.threat_classification || u.verdict || (u.is_suspicious ? "SUSPICIOUS" : "UNKNOWN");
                const verdictBadge = getVerdictBadge(verdict, u.is_suspicious);

                const riskVal =
                  typeof u.risk_score === "number"
                    ? u.risk_score
                    : typeof deepIntel?.confidence === "number"
                    ? deepIntel.confidence
                    : typeof u.confidence === "number"
                    ? u.confidence
                    : 0;
                const riskPercent = (riskVal > 1 ? riskVal : riskVal * 100).toFixed(0);

                const indicators: string[] =
                  deepIntel?.threat_reasons || u.indicators || u.risk_reasons || u.threat_reasons || [];
                const analyzedTimestamp =
                  deepIntel?.analyzed_at || u.analyzed_at || investigation.created_at || new Date().toISOString();

                return (
                  <div
                    key={idx}
                    className={`url-threat-card-glow rounded-xl border text-xs font-mono transition-all overflow-hidden ${
                      isDark ? "bg-slate-900/90 border-slate-800" : "bg-slate-50 border-slate-200"
                    }`}
                  >
                    {/* Collapsible Card Header Bar */}
                    <div
                      onClick={() => toggleUrlCard(key)}
                      className={`p-3.5 flex items-center justify-between flex-wrap gap-2.5 cursor-pointer transition-colors ${
                        isDark ? "hover:bg-slate-800/40" : "hover:bg-slate-100/70"
                      }`}
                    >
                      <div className="flex items-center gap-2.5 min-w-0 flex-1">
                        <div className="p-1 rounded bg-cyan-950/60 text-cyan-400 border border-cyan-800/40 shrink-0">
                          <Globe className="w-3.5 h-3.5" />
                        </div>
                        <div className="min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <code className={`font-bold break-all ${isDark ? "text-cyan-300" : "text-sky-700"}`}>
                              {defangedUrl}
                            </code>
                          </div>
                          <span className="text-[11px] text-slate-400 block truncate">
                            Domain: <strong className="text-slate-300">{domain}</strong>
                          </span>
                        </div>
                      </div>

                      <div className="flex items-center gap-2 shrink-0">
                        {/* Threat Classification Badge */}
                        <span
                          className={`px-2.5 py-0.5 rounded font-bold text-[10px] border tracking-wider uppercase ${verdictBadge.badgeClass}`}
                        >
                          {verdictBadge.label}
                        </span>

                        {/* Risk Score Pill */}
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                            Number(riskPercent) >= 70
                              ? "bg-rose-950/60 text-rose-300 border-rose-800"
                              : Number(riskPercent) >= 35
                              ? "bg-amber-950/60 text-amber-300 border-amber-800"
                              : "bg-slate-800 text-slate-300 border-slate-700"
                          }`}
                        >
                          Risk: {riskPercent}%
                        </span>

                        {/* Copy Defanged URL Action Button */}
                        <button
                          type="button"
                          onClick={(e) => handleCopyDefangedUrl(defangedUrl, key, e)}
                          title="Copy Defanged URL"
                          className={`p-1.5 rounded border transition-colors cursor-pointer ${
                            copiedUrlKey === key
                              ? "bg-emerald-950 text-emerald-300 border-emerald-700"
                              : isDark
                              ? "bg-slate-800 hover:bg-slate-700 text-slate-300 border-slate-700"
                              : "bg-white hover:bg-slate-100 text-slate-700 border-slate-300"
                          }`}
                        >
                          {copiedUrlKey === key ? (
                            <Check className="w-3.5 h-3.5 text-emerald-400" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>

                        {/* Deep Intel Trigger */}
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            handleInspectUrl(normalizedUrl, key);
                          }}
                          disabled={isLoadingIntel}
                          className="px-2.5 py-1 rounded bg-cyan-950/80 text-cyan-300 border border-cyan-800 hover:bg-cyan-900 text-[10px] font-bold flex items-center gap-1 cursor-pointer disabled:opacity-60"
                        >
                          <Search className="w-3 h-3" />
                          <span>
                            {isLoadingIntel ? "Analyzing..." : deepIntel ? "Re-Inspect" : "Deep Threat Intel"}
                          </span>
                        </button>

                        {/* Expand/Collapse Chevron */}
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            toggleUrlCard(key);
                          }}
                          className="p-1 text-slate-400 hover:text-slate-200"
                        >
                          {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                        </button>
                      </div>
                    </div>

                    {/* Expandable URL Evidence Details */}
                    {isExpanded && (
                      <div
                        className={`p-3.5 border-t space-y-3 animate-page-enter ${
                          isDark ? "bg-slate-950/60 border-slate-800" : "bg-white/80 border-slate-200"
                        }`}
                      >
                        {/* Grid: Defanged URL vs Normalized URL */}
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                          <div className={`p-2.5 rounded border ${isDark ? "bg-slate-900 border-slate-800" : "bg-slate-50 border-slate-200"}`}>
                            <span className="text-[10px] font-bold uppercase text-slate-400 block mb-1">
                              1. Original Defanged URL:
                            </span>
                            <code className="text-xs break-all text-amber-300 selection:bg-amber-900/50 block">
                              {defangedUrl}
                            </code>
                          </div>
                          <div className={`p-2.5 rounded border ${isDark ? "bg-slate-900 border-slate-800" : "bg-slate-50 border-slate-200"}`}>
                            <span className="text-[10px] font-bold uppercase text-slate-400 block mb-1">
                              2. Safely Normalized URL (Safe Display Only):
                            </span>
                            <code className="text-xs break-all text-slate-300 selection:bg-slate-800 block select-all">
                              {normalizedUrl}
                            </code>
                          </div>
                        </div>

                        {/* Telemetry Summary Row */}
                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px] font-mono">
                          <div className={`p-2 rounded border ${isDark ? "bg-slate-900/70 border-slate-800" : "bg-slate-50 border-slate-200"}`}>
                            <span className="text-slate-400 block text-[10px]">Domain / Host</span>
                            <span className="font-bold text-slate-200 truncate block">{domain}</span>
                          </div>
                          <div className={`p-2 rounded border ${isDark ? "bg-slate-900/70 border-slate-800" : "bg-slate-50 border-slate-200"}`}>
                            <span className="text-slate-400 block text-[10px]">Shannon Entropy</span>
                            <span className="font-bold text-cyan-300">{u.entropy || deepIntel?.heuristics?.entropy || "N/A"}</span>
                          </div>
                          <div className={`p-2 rounded border ${isDark ? "bg-slate-900/70 border-slate-800" : "bg-slate-50 border-slate-200"}`}>
                            <span className="text-slate-400 block text-[10px]">SSRF Protection</span>
                            <span className={`font-bold ${deepIntel?.ssrf_blocked ? "text-rose-400" : "text-emerald-400"}`}>
                              {deepIntel ? (deepIntel.ssrf_blocked ? "BLOCKED" : "CLEAN") : "ENFORCED"}
                            </span>
                          </div>
                          <div className={`p-2 rounded border ${isDark ? "bg-slate-900/70 border-slate-800" : "bg-slate-50 border-slate-200"}`}>
                            <span className="text-slate-400 block text-[10px]">Analysis Timestamp</span>
                            <span className="text-slate-300 text-[10px] block truncate">
                              {formatIST(analyzedTimestamp)}
                            </span>
                          </div>
                        </div>

                        {/* Detection Indicators */}
                        {indicators.length > 0 && (
                          <div className={`p-2.5 rounded border space-y-1 ${isDark ? "bg-amber-950/20 border-amber-900/40 text-amber-200" : "bg-amber-50 border-amber-200 text-amber-900"}`}>
                            <span className="text-[10px] font-bold uppercase tracking-wider block text-amber-400">
                              Detection Indicators ({indicators.length}):
                            </span>
                            <ul className="text-[11px] space-y-0.5 pl-3 list-disc">
                              {indicators.map((ind: string, iIdx: number) => (
                                <li key={iIdx}>{ind}</li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>
        )}
      </div>

      {/* Expandable Forensic Incident Report Narrative (Phase 4.4 Aurora Glow & Green/Cyan Identity) */}
      <div
        className={`soc-forensic-narrative p-5 rounded-2xl border space-y-4 ${
          isDark
            ? "bg-[#0E1726] border-slate-800"
            : "bg-white border-emerald-100 shadow-xs"
        }`}
      >
        <div className="flex items-center justify-between">
          <button
            onClick={() => toggleSection("findings")}
            aria-expanded={!collapsedSections.findings}
            className="flex items-center gap-2.5 font-mono text-xs uppercase font-bold tracking-wider cursor-pointer text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400 rounded-md p-0.5"
          >
            <div className="w-7 h-7 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center">
              <FileText className="w-4 h-4 text-emerald-400 soc-narrative-icon" />
            </div>
            <span className={isDark ? "text-emerald-300" : "text-emerald-800 font-extrabold"}>
              SOC Forensic Incident Assessment Narrative
            </span>
          </button>
          <button
            onClick={() => toggleSection("findings")}
            aria-expanded={!collapsedSections.findings}
            aria-label="Toggle Forensic Narrative"
            className="p-1.5 rounded-lg text-slate-400 hover:text-emerald-400 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400"
          >
            <ChevronDown
              className={`w-4 h-4 transition-transform duration-300 ${
                collapsedSections.findings ? "" : "rotate-180"
              }`}
            />
          </button>
        </div>

        {!collapsedSections.findings && (
          <div
            className={`p-4 rounded-xl border text-xs whitespace-pre-wrap font-sans leading-relaxed transition-all ${
              isDark
                ? "bg-slate-900/80 border-slate-800 text-slate-200"
                : "bg-emerald-50/40 border-emerald-200/60 text-slate-900 font-medium"
            }`}
          >
            {investigation.final_report}
          </div>
        )}
      </div>

      {/* Tool Execution Timeline Accordion (Phase 4.4 Violet/Cyan Aurora & Status Illumination) */}
      <div
        className={`soc-timeline-container p-5 rounded-2xl border space-y-4 ${
          isDark ? "bg-[#0E1726] border-slate-800" : "bg-white border-purple-100 shadow-xs"
        }`}
      >
        <div className="flex items-center justify-between">
          <button
            onClick={() => toggleSection("timeline")}
            aria-expanded={!collapsedSections.timeline}
            className="flex items-center gap-2.5 font-mono text-xs uppercase font-bold tracking-wider cursor-pointer text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400 rounded-md p-0.5"
          >
            <div className="w-7 h-7 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center">
              <Terminal className="w-4 h-4 text-cyan-400" />
            </div>
            <span className={isDark ? "text-cyan-300" : "text-sky-800 font-extrabold"}>
              Structured Tool Execution Timeline ({investigation.steps.length} Steps)
            </span>
          </button>
          <button
            onClick={() => toggleSection("timeline")}
            aria-expanded={!collapsedSections.timeline}
            aria-label="Toggle Tool Execution Timeline"
            className="p-1.5 rounded-lg text-slate-400 hover:text-cyan-400 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400"
          >
            <ChevronDown
              className={`w-4 h-4 transition-transform duration-300 ${
                collapsedSections.timeline ? "" : "rotate-180"
              }`}
            />
          </button>
        </div>

        {!collapsedSections.timeline && (
          <div className="relative space-y-3 pt-1 animate-page-enter">
            {/* Timeline connector: subtle violet-to-cyan gradient line */}
            <div className="absolute left-[19px] top-4 bottom-4 w-0.5 bg-gradient-to-b from-purple-500/40 via-indigo-500/40 to-cyan-500/40 hidden sm:block pointer-events-none" />

            {investigation.steps.map((st) => {
              const status = getStepStatus(st);
              const isExpanded = !!expandedSteps[st.step];

              return (
                <div
                  key={st.step}
                  className={`soc-timeline-step soc-timeline-step-${status} relative p-3.5 sm:pl-12 rounded-xl border text-xs font-mono space-y-2 cursor-pointer select-none transition-all ${
                    isDark
                      ? "bg-slate-900/90 border-slate-800"
                      : "bg-slate-50/80 border-slate-200"
                  }`}
                  onClick={() => toggleStep(st.step)}
                >
                  {/* Step number badge aligned with connector line */}
                  <div className="hidden sm:flex absolute left-2.5 top-3.5 soc-step-badge w-5 h-5 rounded-full items-center justify-center text-[10px] font-bold border transition-transform shadow-xs z-10">
                    <span
                      className={`w-full h-full rounded-full flex items-center justify-center font-bold ${
                        status === "failed"
                          ? "bg-red-500/20 text-red-400 border-red-500/50"
                          : status === "warning"
                          ? "bg-amber-500/20 text-amber-400 border-amber-500/50"
                          : "bg-purple-500/20 text-purple-300 border-purple-500/50"
                      }`}
                    >
                      {st.step}
                    </span>
                  </div>

                  <div className="flex items-center justify-between gap-2 flex-wrap">
                    <div className="flex items-center gap-2">
                      <span className="sm:hidden font-bold text-purple-400">#{st.step}</span>
                      <span className={`font-bold ${isDark ? "text-purple-300" : "text-purple-700"}`}>
                        {st.tool}()
                      </span>
                    </div>

                    <div className="flex items-center gap-3">
                      {status === "failed" ? (
                        <span className="text-[10px] text-red-400 font-semibold flex items-center gap-1">
                          <AlertTriangle className="w-3 h-3 text-red-400" /> Error Flagged
                        </span>
                      ) : status === "warning" ? (
                        <span className="text-[10px] text-amber-400 font-semibold flex items-center gap-1">
                          <AlertTriangle className="w-3 h-3 text-amber-400" /> Pattern Flagged
                        </span>
                      ) : (
                        <span className="text-[10px] text-emerald-400 font-semibold flex items-center gap-1">
                          <CheckCircle2 className="w-3 h-3 text-emerald-400" /> Output Captured
                        </span>
                      )}

                      <ChevronDown
                        className={`w-3.5 h-3.5 text-slate-400 transition-transform duration-200 ${
                          isExpanded ? "rotate-180" : ""
                        }`}
                      />
                    </div>
                  </div>

                  {isExpanded && (
                    <pre
                      onClick={(e) => e.stopPropagation()}
                      className={`text-[11px] overflow-x-auto p-2.5 rounded border leading-relaxed select-text mt-2 ${
                        isDark
                          ? "text-slate-300 bg-slate-950/80 border-slate-900"
                          : "text-slate-900 bg-white border-slate-300 font-medium"
                      }`}
                    >
                      {JSON.stringify(st.output, null, 2)}
                    </pre>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Investigation Provenance Footer */}
      <div
        className={`p-4 rounded-xl border flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs font-mono transition-colors ${
          isDark ? "bg-[#0A101D] border-slate-800 text-slate-400" : "bg-slate-100 border-slate-300 text-slate-600"
        }`}
      >
        <div className="flex items-center gap-2 flex-wrap">
          <Clock className="w-3.5 h-3.5 text-cyan-400" />
          <span>Investigation Finalized: {formatIST(investigation.created_at || new Date())}</span>
          {headersStep.sender_domain && (
            <span className={`text-[10px] px-2 py-0.5 rounded border ${isDark ? "bg-slate-900 border-slate-800 text-slate-300" : "bg-white border-slate-300 text-slate-700 font-bold"}`}>
              Domain: {headersStep.sender_domain}
            </span>
          )}
        </div>
        <div className="flex items-center gap-3">
          <span>Scan ID: {scanId ? scanId.substring(0, 8) + "..." : "Standalone"}</span>
          <span>Engine: MailSentinel AI Tier-3 SOC</span>
        </div>
      </div>
    </div>
  );
};
