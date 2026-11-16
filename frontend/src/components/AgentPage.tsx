import React, { useState } from "react";
import {
  BrainCircuit,
  Terminal,
  Play,
  CheckCircle2,
  AlertCircle,
  Cpu,
  RotateCcw,
  Sparkles,
  Zap,
  Layers,
  Globe,
  Mail
} from "lucide-react";
import { api } from "../api/client";
import { useTheme } from "../context/ThemeContext";
import type { AgentInvestigation, AgentStep } from "../types";
import { InteractiveSocReport } from "./InteractiveSocReport";
import { CustomUrlScanner } from "./CustomUrlScanner";

export type AgentExecutionState =
  | "IDLE"
  | "CONNECTING"
  | "RUNNING"
  | "TOOL_EXECUTION"
  | "COMPLETED"
  | "FAILED"
  | "TIMEOUT";

interface AgentPageProps {
  initialContent?: string;
  initialHeaders?: string;
  initialScanId?: string;
}

const PRESET_PAYLOADS = [
  {
    label: "Credential Harvest Phish",
    email: "URGENT SECURITY NOTICE: Your corporate Microsoft 365 credentials expire in 2 hours. Validate your session immediately at https://login.microsoft365-verify.xyz/auth or account will be suspended.",
    headers: "Received: from mail.attacker-domain.xyz (198.51.100.24)\nAuthentication-Results: spf=fail dkim=fail dmarc=fail\nFrom: security@office365-alert.com"
  },
  {
    label: "CEO Wire Fraud BEC",
    email: "Hi team, I am currently in an executive meeting with our legal counsel. Please process a confidential wire transfer of $48,500 immediately to our acquisition vendor escrow account. Details attached. Do not call my cell.",
    headers: "none"
  },
  {
    label: "Legitimate Security Alert",
    email: "Google Security Alert: A new login was detected on your account from Chrome on Windows. If this was you, no action is required. If not, review your security settings at https://myaccount.google.com/security.",
    headers: "Received: from mail-sor-f65.google.com (209.85.220.65)\nAuthentication-Results: spf=pass dkim=pass dmarc=pass\nFrom: no-reply@accounts.google.com"
  }
];

export const AgentPage: React.FC<AgentPageProps> = ({
  initialContent = "",
  initialHeaders = "none",
  initialScanId
}) => {
  const { isDark } = useTheme();
  const [emailText, setEmailText] = useState(initialContent);
  const [headersText, setHeadersText] = useState(initialHeaders);
  const [agentState, setAgentState] = useState<AgentExecutionState>("IDLE");
  const [statusMessage, setStatusMessage] = useState<string>("");
  const [activeTool, setActiveTool] = useState<string | null>(null);
  const [streamedSteps, setStreamedSteps] = useState<AgentStep[]>([]);
  const [investigation, setInvestigation] = useState<AgentInvestigation | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [activeSection, setActiveSection] = useState<"email" | "url">("email");

  const isLoading = agentState === "CONNECTING" || agentState === "RUNNING" || agentState === "TOOL_EXECUTION";

  const handleInvestigate = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (isSubmitting || isLoading) return; // Prevent double submission

    if (!emailText.trim()) {
      setError("Please provide untrusted email text for the AI agent to forensically examine.");
      setAgentState("FAILED");
      return;
    }

    setIsSubmitting(true);
    setAgentState("CONNECTING");
    setStatusMessage("Connecting to SOC backend...");
    setError(null);
    setStreamedSteps([]);
    setInvestigation(null);
    setActiveTool(null);

    const abortController = new AbortController();
    const timeoutId = setTimeout(() => {
      abortController.abort();
      setAgentState("TIMEOUT");
      setError("Threat investigation timed out after 20 seconds. Please check backend connection and retry.");
      setIsSubmitting(false);
    }, 20000);

    try {
      // Use progressive SSE streaming with graceful fallback
      const finalResult = await api.investigateEmailStream(
        emailText,
        headersText,
        (evt) => {
          if (evt.event === "CONNECTING") {
            setAgentState("CONNECTING");
            setStatusMessage(evt.message || "Connecting to SOC backend...");
          } else if (evt.event === "RUNNING") {
            setAgentState("RUNNING");
            setStatusMessage(evt.message || "Initializing threat investigation...");
          } else if (evt.event === "TOOL_EXECUTION") {
            setAgentState("TOOL_EXECUTION");
            setStatusMessage(evt.message || `Executing tool: ${evt.tool}...`);
            setActiveTool(evt.tool || null);
          } else if (evt.event === "TOOL_COMPLETE") {
            if (evt.tool && evt.output) {
              setStreamedSteps((prev) => {
                const existing = prev.filter((s) => s.step !== evt.step);
                return [...existing, { step: evt.step || prev.length + 1, tool: evt.tool!, output: evt.output }];
              });
            }
          } else if (evt.event === "REPORTING") {
            setStatusMessage(evt.message || "Preparing final SOC investigation report...");
            setActiveTool(null);
          } else if (evt.event === "COMPLETED" && evt.data) {
            setInvestigation(evt.data);
            setAgentState("COMPLETED");
            setStatusMessage("Investigation complete.");
          }
        },
        initialScanId,
        abortController.signal
      );

      clearTimeout(timeoutId);
      if (finalResult) {
        setInvestigation(finalResult);
        setAgentState("COMPLETED");
        setStatusMessage("Investigation complete.");
      }
    } catch (err: any) {
      clearTimeout(timeoutId);
      console.error("Agent investigation error:", err);
      const isTimeout = err.name === "AbortError" || err.message?.includes("timed out");
      setAgentState(isTimeout ? "TIMEOUT" : "FAILED");
      setError(
        err.message ||
          "AI agent threat investigation failed. Verify backend service is online."
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleRetry = () => {
    handleInvestigate();
  };

  const handleApplyPreset = (preset: typeof PRESET_PAYLOADS[0]) => {
    setEmailText(preset.email);
    setHeadersText(preset.headers);
    setError(null);
  };

  return (
    <div className="space-y-6">
      {/* Title & Metadata Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1
            className={`text-2xl font-bold flex items-center gap-2.5 ${
              isDark ? "text-white" : "text-slate-900 font-extrabold"
            }`}
          >
            <div className="w-9 h-9 rounded-lg bg-gradient-to-tr from-purple-600 via-indigo-600 to-cyan-500 flex items-center justify-center shadow-[0_0_15px_rgba(168,85,247,0.35)]">
              <BrainCircuit className="w-5 h-5 text-white" />
            </div>
            <span>Autonomous Threat Investigator Agent</span>
          </h1>
          <p className={`text-xs mt-1 ${isDark ? "text-slate-400" : "text-slate-600 font-medium"}`}>
            Empirical SOC investigation agent powered by Scikit-Learn TF-IDF, URL entropy, RFC822 parser & Google Gemini 3.1.
          </p>
        </div>

        {/* Engine Specs Badges */}
        <div className="flex items-center flex-wrap gap-2 text-xs font-mono">
          <span
            className={`px-2.5 py-1 rounded-full border flex items-center gap-1.5 ${
              isDark
                ? "bg-purple-950/50 border-purple-500/30 text-purple-300"
                : "bg-purple-50 border-purple-200 text-purple-900 font-bold"
            }`}
          >
            <Sparkles className="w-3 h-3 text-purple-400" />
            Gemini 3.1 Flash-Lite
          </span>
          <span
            className={`px-2.5 py-1 rounded-full border flex items-center gap-1.5 ${
              isDark
                ? "bg-cyan-950/50 border-cyan-500/30 text-cyan-300"
                : "bg-sky-50 border-sky-200 text-sky-900 font-bold"
            }`}
          >
            <Layers className="w-3 h-3 text-cyan-400" />
            5 Empirical Tools
          </span>
          <span
            className={`px-2.5 py-1 rounded-full border flex items-center gap-1.5 ${
              isDark
                ? "bg-emerald-950/50 border-emerald-500/30 text-emerald-300"
                : "bg-emerald-50 border-emerald-200 text-emerald-900 font-bold"
            }`}
          >
            <Zap className="w-3 h-3 text-emerald-400" />
            Sub-2s Response
          </span>
        </div>
      </div>

      {/* Investigation Section Switcher */}
      <div className="flex items-center gap-3 border-b border-slate-800/80 pb-3 relative">
        <button
          type="button"
          onClick={() => setActiveSection("email")}
          aria-selected={activeSection === "email"}
          role="tab"
          className={`investigation-nav-tab px-4 py-2 rounded-xl text-xs font-mono font-bold flex items-center gap-2 cursor-pointer relative ${
            activeSection === "email"
              ? "investigation-nav-tab-active investigation-nav-tab-email-active"
              : isDark
              ? "bg-slate-900/80 text-slate-400 hover:text-slate-200 border border-slate-800"
              : "bg-slate-100 text-slate-600 hover:text-slate-900 border border-slate-200"
          }`}
        >
          <Mail className="w-4 h-4 shrink-0" />
          <span>Email & Header Investigation</span>
          {activeSection === "email" && (
            <div className="investigation-tab-indicator investigation-tab-indicator-email" />
          )}
        </button>

        <button
          type="button"
          onClick={() => setActiveSection("url")}
          aria-selected={activeSection === "url"}
          role="tab"
          className={`investigation-nav-tab px-4 py-2 rounded-xl text-xs font-mono font-bold flex items-center gap-2 cursor-pointer relative ${
            activeSection === "url"
              ? "investigation-nav-tab-active investigation-nav-tab-url-active"
              : isDark
              ? "bg-slate-900/80 text-slate-400 hover:text-slate-200 border border-slate-800"
              : "bg-slate-100 text-slate-600 hover:text-slate-900 border border-slate-200"
          }`}
        >
          <Globe className="w-4 h-4 shrink-0" />
          <span>Custom URL Threat Scanner</span>
          <span className={`text-[10px] px-1.5 py-0.2 rounded font-bold uppercase ${
            activeSection === "url"
              ? "bg-white/20 text-white"
              : isDark
              ? "bg-purple-950 text-purple-300 border border-purple-800"
              : "bg-purple-100 text-purple-800"
          }`}>
            AI Tool
          </span>
          {activeSection === "url" && (
            <div className="investigation-tab-indicator investigation-tab-indicator-url" />
          )}
        </button>
      </div>

      {activeSection === "url" ? (
        <div key="url-panel" className="investigation-panel-enter">
          <CustomUrlScanner />
        </div>
      ) : (
        <div key="email-panel" className="investigation-panel-enter space-y-6">
          {/* Preset Security Scenarios */}
          <div
            className={`p-3 rounded-xl border flex flex-wrap items-center gap-2 text-xs transition-colors ${
              isDark ? "bg-[#0E1726]/60 border-slate-800" : "bg-white border-slate-200 shadow-xs"
            }`}
          >
            <span className={`font-mono font-bold mr-1 ${isDark ? "text-slate-400" : "text-slate-700"}`}>
              Forensic Presets:
            </span>
            {PRESET_PAYLOADS.map((p, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => handleApplyPreset(p)}
                className={`px-3 py-1 rounded-lg border text-xs font-mono font-medium transition-all cursor-pointer ${
                  isDark
                    ? "bg-slate-900/90 border-slate-700 text-slate-300 hover:text-cyan-300 hover:border-cyan-500/50"
                    : "bg-slate-50 border-slate-300 text-slate-800 hover:bg-sky-50 hover:text-sky-900 hover:border-sky-400 font-semibold"
                }`}
              >
                {p.label}
              </button>
            ))}
          </div>

      {/* Main Grid: Input Console vs Results Timeline */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Target Input Form */}
        <div className="lg:col-span-5 space-y-4">
          <form
            onSubmit={handleInvestigate}
            className={`rounded-xl p-5 border space-y-4 shadow-sm transition-colors ${
              isDark ? "bg-[#0E1726] border-slate-800" : "bg-white border-slate-200 shadow-xs"
            }`}
          >
            <div className="flex items-center justify-between">
              <h2
                className={`text-xs font-semibold uppercase font-mono tracking-wider flex items-center gap-2 ${
                  isDark ? "text-purple-400" : "text-purple-700 font-bold"
                }`}
              >
                <Cpu className="w-4 h-4" />
                Target Evidence Input
              </h2>
              {initialScanId && (
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950/60 text-cyan-300 border border-cyan-800">
                  Scan: {initialScanId.substring(0, 8)}...
                </span>
              )}
            </div>

            <div>
              <label className={`block text-xs font-mono mb-1 font-medium ${isDark ? "text-slate-300" : "text-slate-700"}`}>
                Untrusted Email Evidence Payload:
              </label>
              <textarea
                rows={9}
                placeholder="Paste suspicious email text, headers, or body here..."
                value={emailText}
                onChange={(e) => setEmailText(e.target.value)}
                disabled={isLoading}
                className={`w-full px-3 py-2 border rounded-lg text-xs font-mono transition-colors focus:outline-none focus:border-purple-500 ${
                  isDark
                    ? "bg-slate-900/90 border-slate-800 text-slate-200 placeholder-slate-500"
                    : "bg-slate-50 border-slate-300 text-slate-900 placeholder-slate-400"
                }`}
                required
              />
            </div>

            <div>
              <label className={`block text-xs font-mono mb-1 font-medium ${isDark ? "text-slate-300" : "text-slate-700"}`}>
                RFC822 Transport Headers (Optional):
              </label>
              <input
                type="text"
                value={headersText}
                onChange={(e) => setHeadersText(e.target.value)}
                disabled={isLoading}
                placeholder="Received: from ... or 'none'"
                className={`w-full px-3 py-2 border rounded-lg text-xs font-mono transition-colors focus:outline-none focus:border-purple-500 ${
                  isDark
                    ? "bg-slate-900/90 border-slate-800 text-slate-200 placeholder-slate-500"
                    : "bg-slate-50 border-slate-300 text-slate-900 placeholder-slate-400"
                }`}
              />
            </div>

            {/* Error Message & Retry Prompt */}
            {error && (
              <div
                className={`p-3.5 rounded-lg border text-xs flex flex-col gap-2 ${
                  agentState === "TIMEOUT"
                    ? "bg-amber-950/40 border-amber-500/40 text-amber-200"
                    : "bg-rose-950/60 border-rose-500/40 text-rose-200"
                }`}
              >
                <div className="flex items-start gap-2">
                  <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                  <div className="flex-1 font-medium leading-relaxed">{error}</div>
                </div>
                <div className="flex justify-end pt-1">
                  <button
                    type="button"
                    onClick={handleRetry}
                    className="flex items-center gap-1.5 px-3 py-1 rounded bg-rose-600 hover:bg-rose-500 text-white font-mono font-bold text-xs transition-colors cursor-pointer"
                  >
                    <RotateCcw className="w-3 h-3" />
                    Retry Investigation
                  </button>
                </div>
              </div>
            )}

            {/* Launch / Status Button */}
            <button
              type="submit"
              disabled={isLoading || isSubmitting}
              className={`w-full py-3 px-4 rounded-lg font-bold text-sm transition-all flex items-center justify-center gap-2 cursor-pointer disabled:opacity-60 disabled:cursor-not-allowed ${
                isDark
                  ? "bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white shadow-[0_0_20px_rgba(168,85,247,0.3)]"
                  : "bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white shadow-sm"
              }`}
            >
              {isLoading ? (
                <>
                  <div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin"></div>
                  <span className="font-mono text-xs font-bold">
                    {statusMessage || "Agent Reasoner Executing Tools..."}
                  </span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-current" />
                  <span>Launch Autonomous Agent Investigation</span>
                </>
              )}
            </button>
          </form>
        </div>

        {/* Right Column: Execution Timeline & Forensic Results */}
        <div className="lg:col-span-7 space-y-5">
          {/* Active Execution State Indicator Banner */}
          {isLoading && (
            <div
              className={`p-4 rounded-xl border flex items-center justify-between shadow-sm animate-pulse ${
                isDark
                  ? "bg-[#0E1726] border-purple-500/40 text-purple-300"
                  : "bg-purple-50 border-purple-200 text-purple-900"
              }`}
            >
              <div className="flex items-center gap-3">
                <div className="w-3 h-3 rounded-full bg-purple-500 animate-ping"></div>
                <div className="space-y-0.5">
                  <div className="text-xs font-mono font-bold uppercase tracking-wider">
                    Stage: {agentState}
                  </div>
                  <div className="text-xs font-medium">{statusMessage}</div>
                </div>
              </div>
              {activeTool && (
                <div className="text-xs font-mono px-2.5 py-1 rounded bg-purple-900/40 border border-purple-700 font-bold">
                  {activeTool}()
                </div>
              )}
            </div>
          )}

          {/* Investigation Result Display */}
          {investigation ? (
            <InteractiveSocReport
              investigation={investigation}
              emailText={emailText}
              headersText={headersText}
              scanId={initialScanId}
            />
          ) : streamedSteps.length > 0 ? (
            /* Live Streamed Steps while running */
            <div
              className={`rounded-xl p-5 border space-y-3 transition-colors ${
                isDark ? "bg-[#0E1726] border-slate-800" : "bg-white border-slate-200 shadow-xs"
              }`}
            >
              <h3
                className={`text-xs font-semibold uppercase font-mono tracking-wider flex items-center gap-2 ${
                  isDark ? "text-cyan-400" : "text-sky-700 font-bold"
                }`}
              >
                <Terminal className="w-4 h-4 animate-spin text-cyan-400" />
                Live Tool Execution Stream ({streamedSteps.length} Completed)
              </h3>
              <div className="space-y-3">
                {streamedSteps.map((st, idx) => (
                  <div
                    key={idx}
                    className={`p-3 rounded-lg border text-xs font-mono space-y-1.5 ${
                      isDark ? "bg-slate-900/90 border-slate-800" : "bg-slate-50 border-slate-200"
                    }`}
                  >
                    <div className="flex items-center justify-between font-bold">
                      <span className={isDark ? "text-purple-400" : "text-purple-700"}>
                        Step {st.step}: {st.tool}()
                      </span>
                      <span className="text-[10px] text-emerald-500 flex items-center gap-1 font-semibold">
                        <CheckCircle2 className="w-3 h-3" /> Captured
                      </span>
                    </div>
                    <pre
                      className={`text-[11px] overflow-x-auto p-2 rounded border ${
                        isDark ? "text-slate-300 bg-slate-950/80 border-slate-900" : "text-slate-800 bg-white border-slate-300"
                      }`}
                    >
                      {JSON.stringify(st.output, null, 2)}
                    </pre>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            /* Empty State */
            <div
              className={`h-full min-h-[380px] rounded-xl border border-dashed flex flex-col items-center justify-center p-8 text-center transition-colors ${
                isDark ? "border-slate-800 bg-[#0E1726]/40" : "border-slate-300 bg-white shadow-xs"
              }`}
            >
              <div className="w-14 h-14 rounded-2xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center mb-3">
                <BrainCircuit className={`w-8 h-8 ${isDark ? "text-purple-400" : "text-purple-600"}`} />
              </div>
              <h3 className={`font-bold mb-1 ${isDark ? "text-slate-200" : "text-slate-800"}`}>
                Awaiting AI Agent Launch
              </h3>
              <p className={`text-xs max-w-sm leading-relaxed ${isDark ? "text-slate-400" : "text-slate-600"}`}>
                Paste suspicious email evidence or choose a preset scenario above, then click <strong>Launch Autonomous Agent Investigation</strong> to inspect the empirical tool timeline.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  )}
</div>
  );
};
