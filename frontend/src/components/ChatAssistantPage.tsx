import React, { useState, useEffect, useRef } from "react";
import {
  Bot,
  Send,
  Plus,
  Trash2,
  Terminal,
  Paperclip,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Cpu,
  ShieldCheck,
  Sparkles,
  Zap,
  Copy,
  Check,
  ThumbsUp,
  ThumbsDown,
  RotateCcw,
  Search,
  PanelLeft,
  X,
  MessageSquare
} from "lucide-react";
import { api } from "../api/client";
import { RichMessageRenderer } from "./RichMessageRenderer";
import { useTheme } from "../context/ThemeContext";
import type { ChatSessionSummary, ChatMessage } from "../types";
import { formatIST, formatRelativeIST } from "../utils/dateFormatter";

interface ChatAssistantPageProps {
  initialEmailContent?: string;
  initialHeaders?: string;
  initialScanId?: string;
}

const QUICK_PROMPTS = [
  "How does an email phishing attack work? Provide a workflow diagram.",
  "Analyze this email for phishing & spoofing indicators",
  "Explain DMARC alignment policies p=reject vs p=quarantine",
  "Explain why this email received an elevated threat score",
  "Draft a defensive verification reply to a suspicious invoice request",
  "What is the system architecture of MailSentinel AI?"
];

export const ChatAssistantPage: React.FC<ChatAssistantPageProps> = ({
  initialEmailContent = "",
  initialHeaders = "none",
  initialScanId
}) => {
  const { isDark } = useTheme();
  const [sessions, setSessions] = useState<ChatSessionSummary[]>([]);
  const [activeSessionId, setActiveSessionId] = useState<string | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [inputMessage, setInputMessage] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [emailEvidence, setEmailEvidence] = useState(initialEmailContent);
  const [headersEvidence, setHeadersEvidence] = useState(initialHeaders);
  const [showEvidenceDrawer, setShowEvidenceDrawer] = useState(Boolean(initialEmailContent));
  const [showMobileSidebar, setShowMobileSidebar] = useState(false);
  const [loading, setLoading] = useState(false);
  const [expandedTools, setExpandedTools] = useState<Record<string, boolean>>({});
  const [copiedMessageId, setCopiedMessageId] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<Record<string, "helpful" | "not_helpful">>({});
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const activeQuickPrompts = QUICK_PROMPTS;

  // Load chat sessions on mount
  useEffect(() => {
    loadSessions();
  }, []);

  // When initialEmailContent changes, update state and open drawer
  useEffect(() => {
    if (initialEmailContent) {
      setEmailEvidence(initialEmailContent);
      setHeadersEvidence(initialHeaders || "none");
      setShowEvidenceDrawer(true);
      setInputMessage("Please analyze this email evidence and explain any threat indicators.");
    }
  }, [initialEmailContent, initialHeaders]);

  // Scroll to bottom when messages update
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, loading]);

  const loadSessions = async () => {
    try {
      const data = await api.getChatSessions();
      setSessions(data);
      if (data.length > 0 && !activeSessionId) {
        selectSession(data[0].id);
      }
    } catch (err) {
      console.error("Failed to load chat sessions:", err);
    }
  };

  const selectSession = async (sessionId: string) => {
    setActiveSessionId(sessionId);
    try {
      const detail = await api.getChatSessionDetail(sessionId);
      setMessages(detail.messages);
    } catch (err) {
      console.error("Failed to load session details:", err);
    }
  };

  const handleNewConversation = () => {
    setActiveSessionId(null);
    setMessages([]);
    setInputMessage("");
    setShowMobileSidebar(false);
  };

  const handleDeleteSession = async (sessionId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      await api.deleteChatSession(sessionId);
      const remaining = sessions.filter((s) => s.id !== sessionId);
      setSessions(remaining);
      if (activeSessionId === sessionId) {
        if (remaining.length > 0) {
          selectSession(remaining[0].id);
        } else {
          handleNewConversation();
        }
      }
    } catch (err) {
      console.error("Failed to delete session:", err);
    }
  };

  const handleCopyMessage = async (msgId: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedMessageId(msgId);
      setTimeout(() => setCopiedMessageId(null), 2000);
    } catch (e) {
      console.error("Copy failed", e);
    }
  };

  const handleFeedback = (msgId: string, type: "helpful" | "not_helpful") => {
    setFeedback((prev) => ({
      ...prev,
      [msgId]: prev[msgId] === type ? undefined! : type
    }));
  };

  const handleSendMessage = async (e?: React.FormEvent, customPrompt?: string) => {
    if (e) e.preventDefault();
    const promptToSend = customPrompt || inputMessage.trim();
    if (!promptToSend) return;

    if (!customPrompt) {
      setInputMessage("");
    }

    // Optimistically append user message
    const tempUserMsg: ChatMessage = {
      id: "temp-" + Date.now(),
      role: "user",
      content: promptToSend,
      created_at: new Date().toISOString()
    };

    const assistantTempId = "res-" + Date.now();
    const tempAssistantMsg: ChatMessage = {
      id: assistantTempId,
      role: "assistant",
      content: "",
      created_at: new Date().toISOString()
    };

    setMessages((prev) => [...prev, tempUserMsg, tempAssistantMsg]);
    setLoading(true);

    let streamedAccumulator = "";
    try {
      const res = await api.sendChatMessageStream(
        promptToSend,
        activeSessionId || undefined,
        emailEvidence.trim() || undefined,
        headersEvidence.trim() || undefined,
        initialScanId,
        (token: string) => {
          streamedAccumulator += token;
          setMessages((prev) =>
            prev.map((msg) =>
              msg.id === assistantTempId ? { ...msg, content: streamedAccumulator } : msg
            )
          );
        },
        "en-US"
      );

      setMessages((prev) =>
        prev.map((msg) =>
          msg.id === assistantTempId
            ? {
                ...msg,
                content: res.reply || streamedAccumulator,
                tool_calls: {
                  tools: res.tools_invoked,
                  mode: res.mode,
                  operational_status: res.operational_status,
                  disclaimer: res.disclaimer,
                  model_used: res.model_used,
                  latency_ms: res.latency_ms,
                  evidence: res.evidence
                },
                created_at: res.created_at
              }
            : msg
        )
      );

      // If this was a new session, update active session ID and refresh session list
      if (!activeSessionId) {
        setActiveSessionId(res.session_id);
        loadSessions();
      }
    } catch (err: any) {
      setMessages((prev) =>
        prev.map((msg) =>
          msg.id === assistantTempId
            ? {
                ...msg,
                content: `⚠️ **Security Engine Notice**: ${err.message || "Failed to process conversational query."}`
              }
            : msg
        )
      );
    } finally {
      setLoading(false);
    }
  };

  const handleRegenerateLast = () => {
    for (let i = messages.length - 1; i >= 0; i--) {
      if (messages[i].role === "user") {
        handleSendMessage(undefined, messages[i].content);
        break;
      }
    }
  };

  const toggleToolExpand = (msgId: string) => {
    setExpandedTools((prev) => ({ ...prev, [msgId]: !prev[msgId] }));
  };

  const filteredSessions = sessions.filter((s) =>
    s.title.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="flex flex-col h-[calc(100vh-100px)] min-h-[640px] space-y-4">
      {/* Title & Top Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 shrink-0">
        <div className="flex items-center gap-3">
          {/* Mobile Sidebar Toggle Button */}
          <button
            onClick={() => setShowMobileSidebar(!showMobileSidebar)}
            className={`lg:hidden p-2 rounded-lg border transition-colors flex items-center justify-center ${
              isDark
                ? "bg-slate-900 border-slate-800 text-emerald-400 hover:bg-slate-800"
                : "bg-white border-slate-300 text-emerald-700 hover:bg-slate-100 shadow-xs"
            }`}
            title="Toggle Sessions History"
          >
            <PanelLeft className="w-4 h-4" />
          </button>

          <div>
            <h1
              className={`text-xl sm:text-2xl font-bold flex items-center gap-2 tracking-tight ${
                isDark ? "text-white" : "text-slate-950 font-extrabold"
              }`}
            >
              <Bot className={`w-6 h-6 sm:w-7 sm:h-7 ${isDark ? "text-cyan-400" : "text-sky-600"}`} />
              Sentinel Copilot &bull; Cybersecurity SOC Advisor
            </h1>
            <p className={`text-xs sm:text-sm font-medium ${isDark ? "text-slate-400" : "text-slate-700"}`}>
              Tier-3 SOC threat analysis, phishing forensics, and interactive architectural diagrams.
            </p>
          </div>
        </div>

        {/* Operational Security Badges */}
        <div className="hidden sm:flex items-center space-x-2 text-xs font-mono">
          <span
            className={`px-2.5 py-1 rounded-md flex items-center gap-1.5 border font-semibold ${
              isDark
                ? "bg-slate-900 border-slate-800 text-cyan-300"
                : "bg-white border-slate-200 text-sky-800 shadow-xs"
            }`}
          >
            <ShieldCheck className="w-3.5 h-3.5 text-cyan-500" />
            Zero-Trust Filter
          </span>
          <span
            className={`px-2.5 py-1 rounded-md flex items-center gap-1.5 border font-semibold ${
              isDark
                ? "bg-emerald-950/40 border-emerald-500/30 text-emerald-300 shadow-[0_0_10px_rgba(16,185,129,0.15)]"
                : "bg-emerald-50 border-emerald-300 text-emerald-900 shadow-xs"
            }`}
          >
            <Sparkles className="w-3.5 h-3.5 text-emerald-600" />
            Gemini 3.1 Flash-Lite
          </span>
        </div>
      </div>

      {/* Main Container Layout */}
      <div className="flex-1 grid grid-cols-1 lg:grid-cols-12 gap-5 min-h-0 relative">
        {/* Left Sidebar: Conversation History with Professional Emerald Accents */}
        <div
          className={`
            fixed inset-y-0 left-0 z-40 w-72 lg:static lg:w-auto lg:col-span-3 lg:z-auto
            rounded-xl border flex flex-col overflow-hidden transition-all duration-200 shadow-xl lg:shadow-none
            ${isDark ? "bg-[#0E1726] border-slate-800" : "bg-white border-slate-200 shadow-sm"}
            ${showMobileSidebar ? "translate-x-0" : "-translate-x-full lg:translate-x-0"}
          `}
        >
          {/* Sidebar Top: New Chat & Header */}
          <div
            className={`p-3.5 border-b space-y-2.5 ${
              isDark ? "border-slate-800 bg-[#0A101D]/70" : "border-slate-200 bg-slate-50/80"
            }`}
          >
            <div className="flex items-center justify-between">
              <span
                className={`text-xs font-mono uppercase font-bold tracking-wider flex items-center gap-1.5 ${
                  isDark ? "text-slate-300" : "text-slate-800 font-bold"
                }`}
              >
                <MessageSquare className="w-3.5 h-3.5 text-emerald-500" />
                Investigation Sessions
              </span>
              <button
                onClick={() => setShowMobileSidebar(false)}
                className={`lg:hidden p-1 rounded-md ${isDark ? "text-slate-400 hover:text-white" : "text-slate-600 hover:text-slate-900"}`}
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Emerald Accent New Chat Button */}
            <button
              onClick={handleNewConversation}
              className={`w-full py-2.5 px-3 rounded-lg font-semibold text-xs flex items-center justify-center gap-2 transition-all cursor-pointer shadow-xs ${
                isDark
                  ? "bg-emerald-600 hover:bg-emerald-500 text-white shadow-[0_0_15px_rgba(16,185,129,0.3)] hover:shadow-[0_0_20px_rgba(16,185,129,0.45)]"
                  : "bg-emerald-600 hover:bg-emerald-700 text-white shadow-xs font-bold"
              }`}
            >
              <Plus className="w-4 h-4 stroke-[2.5]" />
              <span>New Investigation</span>
            </button>

            {/* Search Filter for History */}
            <div className="relative">
              <Search
                className={`w-3.5 h-3.5 absolute left-2.5 top-2.5 ${isDark ? "text-slate-500" : "text-slate-600"}`}
              />
              <input
                type="text"
                placeholder="Search history..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className={`w-full pl-8 pr-3 py-1.5 rounded-lg text-xs font-sans transition-colors focus:outline-none focus:border-emerald-500 border ${
                  isDark
                    ? "bg-slate-900 border-slate-800 text-slate-200 placeholder-slate-500"
                    : "bg-white border-slate-300 text-slate-900 placeholder-slate-500 font-medium"
                }`}
              />
            </div>
          </div>

          {/* Session List */}
          <div className="flex-1 overflow-y-auto p-2 space-y-1.5">
            {filteredSessions.map((s) => {
              const isActive = s.id === activeSessionId;
              return (
                <div
                  key={s.id}
                  onClick={() => {
                    selectSession(s.id);
                    setShowMobileSidebar(false);
                  }}
                  className={`p-3 rounded-lg text-xs font-sans cursor-pointer transition-all flex items-center justify-between group relative border ${
                    isActive
                      ? isDark
                        ? "bg-emerald-950/40 text-emerald-200 border-emerald-500/50 shadow-[0_0_12px_rgba(16,185,129,0.25)] font-semibold"
                        : "bg-emerald-50 text-emerald-950 border-emerald-400 shadow-xs font-bold"
                      : isDark
                      ? "text-slate-300 border-transparent hover:bg-slate-900/60 hover:border-emerald-500/30 hover:shadow-[0_0_8px_rgba(16,185,129,0.15)]"
                      : "text-slate-800 border-transparent hover:bg-slate-100 hover:border-emerald-300 hover:text-slate-950 font-medium"
                  }`}
                >
                  {/* Green vertical active indicator bar */}
                  {isActive && (
                    <div className="absolute left-0 top-2 bottom-2 w-1 rounded-r-md bg-emerald-500 shadow-[0_0_8px_#10b981]" />
                  )}

                  <div className="truncate pr-2 pl-1.5 flex-1">
                    <div className="truncate font-semibold text-xs leading-snug" title={s.title}>
                      {s.title}
                    </div>
                    <div
                      className={`text-[10px] font-mono mt-1 ${
                        isActive
                          ? isDark
                            ? "text-emerald-400"
                            : "text-emerald-800 font-semibold"
                          : isDark
                          ? "text-slate-400"
                          : "text-slate-600 font-medium"
                      }`}
                      title={`Last updated: ${formatIST(s.updated_at)}`}
                    >
                      {formatRelativeIST(s.updated_at)} &bull;{" "}
                      {s.message_count} msgs
                    </div>
                  </div>

                  <button
                    onClick={(e) => handleDeleteSession(s.id, e)}
                    className="opacity-0 group-hover:opacity-100 hover:text-rose-500 p-1.5 rounded transition-opacity"
                    title="Delete Session"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              );
            })}

            {filteredSessions.length === 0 && (
              <div className={`p-6 text-center text-xs ${isDark ? "text-slate-500" : "text-slate-600 font-medium"}`}>
                {searchQuery ? "No matching conversations found." : "No active sessions yet."}
              </div>
            )}
          </div>
        </div>

        {/* Mobile Sidebar Backdrop Overlay */}
        {showMobileSidebar && (
          <div
            onClick={() => setShowMobileSidebar(false)}
            className="fixed inset-0 z-30 bg-black/60 backdrop-blur-xs lg:hidden"
          />
        )}

        {/* Right Main Chat Interface */}
        <div
          className={`lg:col-span-9 rounded-xl border flex flex-col overflow-hidden transition-colors ${
            isDark ? "bg-[#0E1726] border-slate-800" : "bg-white border-slate-200 shadow-sm"
          }`}
        >
          {/* Top Forensic Evidence Drawer Toggle */}
          <div
            className={`p-3 border-b flex items-center justify-between text-xs font-mono transition-colors shrink-0 ${
              isDark ? "border-slate-800/80 bg-slate-900/40" : "border-slate-200 bg-slate-50"
            }`}
          >
            <button
              onClick={() => setShowEvidenceDrawer(!showEvidenceDrawer)}
              className={`flex items-center gap-1.5 transition-colors font-semibold ${
                isDark ? "text-cyan-400 hover:text-cyan-300" : "text-sky-800 hover:text-sky-950 font-bold"
              }`}
            >
              <Paperclip className="w-3.5 h-3.5 text-cyan-500" />
              <span>Attach Email Evidence & Transport Headers</span>
              {showEvidenceDrawer ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
            </button>

            {emailEvidence && (
              <span className="text-[10px] px-2 py-0.5 rounded font-bold bg-emerald-500/10 text-emerald-600 border border-emerald-500/30">
                Evidence Attached ({emailEvidence.length} chars)
              </span>
            )}
          </div>

          {/* Collapsible Evidence Input Drawer */}
          {showEvidenceDrawer && (
            <div
              className={`p-4 border-b space-y-3 text-xs font-mono transition-colors shrink-0 ${
                isDark ? "border-slate-800 bg-[#0A101D]" : "border-slate-200 bg-slate-100"
              }`}
            >
              <div>
                <label className={`block text-[11px] mb-1 font-semibold ${isDark ? "text-slate-400" : "text-slate-800"}`}>
                  Untrusted Email Body / Content (Forensically Quarantined):
                </label>
                <textarea
                  rows={3}
                  value={emailEvidence}
                  onChange={(e) => setEmailEvidence(e.target.value)}
                  placeholder="Paste untrusted email snippet here..."
                  className={`w-full px-3 py-2 border rounded-lg focus:outline-none focus:border-cyan-500 font-mono text-xs ${
                    isDark
                      ? "bg-slate-900 border-slate-800 text-slate-200"
                      : "bg-white border-slate-300 text-slate-900 font-medium"
                  }`}
                />
              </div>
              <div>
                <label className={`block text-[11px] mb-1 font-semibold ${isDark ? "text-slate-400" : "text-slate-800"}`}>
                  RFC822 Transport Headers (Optional):
                </label>
                <input
                  type="text"
                  value={headersEvidence}
                  onChange={(e) => setHeadersEvidence(e.target.value)}
                  placeholder="e.g. Received: from ... (or 'none')"
                  className={`w-full px-3 py-2 border rounded-lg focus:outline-none focus:border-cyan-500 font-mono text-xs ${
                    isDark
                      ? "bg-slate-900 border-slate-800 text-slate-200"
                      : "bg-white border-slate-300 text-slate-900 font-medium"
                  }`}
                />
              </div>
            </div>
          )}

          {/* Messages Viewport */}
          <div className="flex-1 overflow-y-auto p-4 sm:p-6 space-y-4">
            {messages.length === 0 ? (
              <div className="h-full flex flex-col items-center justify-center text-center p-6 space-y-4">
                <div
                  className={`w-14 h-14 rounded-2xl flex items-center justify-center shadow-lg ${
                    isDark
                      ? "bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 shadow-[0_0_20px_rgba(6,182,212,0.2)]"
                      : "bg-sky-50 border border-sky-200 text-sky-700"
                  }`}
                >
                  <Bot className="w-8 h-8" />
                </div>
                <div>
                  <h3 className={`text-base font-bold ${isDark ? "text-slate-200" : "text-slate-950 font-extrabold"}`}>
                    Sentinel Cybersecurity Copilot is Ready
                  </h3>
                  <p className={`text-xs max-w-md mt-1.5 font-medium ${isDark ? "text-slate-400" : "text-slate-700"}`}>
                    Ask email security questions, generate phishing attack lifecycle diagrams, review SPF/DKIM/DMARC policies, or explore MailSentinel AI architecture.
                  </p>
                </div>

                {/* Quick Prompts */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 max-w-2xl w-full pt-4">
                  {activeQuickPrompts.map((prompt, idx) => (
                    <button
                      key={idx}
                      onClick={() => handleSendMessage(undefined, prompt)}
                      className={`text-left p-3 rounded-lg border text-xs transition-all flex items-center gap-2 group cursor-pointer ${
                        isDark
                          ? "bg-slate-900/80 hover:bg-slate-800/80 border-slate-800 text-slate-300 hover:text-cyan-300 hover:border-cyan-500/40 hover:shadow-[0_0_12px_rgba(6,182,212,0.15)]"
                          : "bg-slate-50 hover:bg-sky-50 border-slate-200 text-slate-800 hover:text-sky-900 hover:border-sky-300 shadow-xs font-medium"
                      }`}
                    >
                      <Cpu className="w-4 h-4 text-cyan-500 shrink-0 group-hover:scale-110 transition-transform" />
                      <span className="line-clamp-2">{prompt}</span>
                    </button>
                  ))}
                </div>
              </div>
            ) : (
              messages.map((m) => {
                const isUser = m.role === "user";
                const isAssistant = m.role === "assistant";
                const hasTools = m.tool_calls?.tools && m.tool_calls.tools.length > 0;
                const isExpanded = expandedTools[m.id];
                const isCopied = copiedMessageId === m.id;
                const currentFeedback = feedback[m.id];

                return (
                  <div key={m.id} className={`flex flex-col ${isUser ? "items-end" : "items-start"} animate-message-fade-in`}>
                    <div
                      className={`w-full max-w-3xl rounded-xl p-4 text-xs font-sans leading-relaxed shadow-md transition-all ${
                        isUser
                          ? isDark
                            ? "bg-gradient-to-r from-purple-600 to-indigo-600 text-white rounded-br-none shadow-[0_0_15px_rgba(147,51,234,0.2)]"
                            : "bg-gradient-to-r from-sky-600 to-indigo-600 text-white rounded-br-none shadow-sm font-medium"
                          : isDark
                          ? "bg-slate-900/95 border border-slate-800 text-slate-200 rounded-bl-none space-y-2 shadow-[0_4px_20px_rgba(0,0,0,0.3)]"
                          : "bg-white border border-slate-200 text-slate-900 rounded-bl-none space-y-2 shadow-sm"
                      }`}
                    >
                      {/* Redesigned AI Response Header: Compact & High-Contrast Metadata Pills */}
                      {isAssistant && (
                        <div
                          className={`flex flex-wrap items-center justify-between gap-2 pb-2 mb-2 border-b ${
                            isDark ? "border-slate-800" : "border-slate-200"
                          }`}
                        >
                          <div className="flex flex-wrap items-center gap-1.5">
                            {/* Identity Badge */}
                            <span
                              className={`flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold border ${
                                isDark
                                  ? "bg-cyan-950/40 text-cyan-300 border-cyan-500/30"
                                  : "bg-sky-100 text-sky-900 border-sky-300 font-extrabold"
                              }`}
                            >
                              <Bot className="w-3 h-3 text-cyan-500" />
                              <span>Sentinel Copilot</span>
                            </span>

                            {/* Model Name Pill */}
                            {m.tool_calls?.model_used && (
                              <span
                                className={`flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono font-bold border ${
                                  isDark
                                    ? "bg-purple-950/40 text-purple-300 border-purple-500/30"
                                    : "bg-purple-100 text-purple-900 border-purple-300 font-extrabold"
                                }`}
                              >
                                <Sparkles className="w-3 h-3 text-purple-500" />
                                <span>{m.tool_calls.model_used}</span>
                              </span>
                            )}

                            {/* Latency Pill */}
                            {m.tool_calls?.latency_ms !== undefined && m.tool_calls?.latency_ms !== null && (
                              <span
                                className={`flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono font-bold border ${
                                  isDark
                                    ? "bg-emerald-950/40 text-emerald-400 border-emerald-500/30"
                                    : "bg-emerald-100 text-emerald-900 border-emerald-300 font-extrabold"
                                }`}
                              >
                                <Zap className="w-3 h-3 text-emerald-500" />
                                <span>{m.tool_calls.latency_ms}ms</span>
                              </span>
                            )}

                            {/* Security Tools Executed Pill */}
                            {hasTools && (
                              <button
                                onClick={() => toggleToolExpand(m.id)}
                                className={`flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold border cursor-pointer transition-colors ${
                                  isDark
                                    ? "bg-slate-800 text-cyan-300 border-slate-700 hover:border-cyan-400"
                                    : "bg-slate-100 text-slate-900 border-slate-300 hover:border-sky-500 font-extrabold"
                                }`}
                                title="Toggle tool execution trace"
                              >
                                <Terminal className="w-3 h-3 text-cyan-500" />
                                <span>{m.tool_calls?.tools?.length || 0} Tools Executed</span>
                                {isExpanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                              </button>
                            )}

                            {/* Fallback Mode Badges */}
                            {m.tool_calls?.mode === "deterministic_fallback" && (
                              <span
                                className={`px-2 py-0.5 rounded-full text-[10px] font-mono font-bold border ${
                                  isDark
                                    ? "bg-amber-950/40 text-amber-300 border-amber-500/30"
                                    : "bg-amber-100 text-amber-900 border-amber-300 font-extrabold"
                                }`}
                              >
                                Deterministic Mode
                              </span>
                            )}
                            {m.tool_calls?.mode === "domain_restriction" && (
                              <span
                                className={`px-2 py-0.5 rounded-full text-[10px] font-mono font-bold border ${
                                  isDark
                                    ? "bg-sky-950/40 text-sky-300 border-sky-500/30"
                                    : "bg-sky-100 text-sky-900 border-sky-300 font-extrabold"
                                }`}
                              >
                                Scope Guardrail
                              </span>
                            )}
                          </div>

                          <span
                            className={`text-[10px] font-mono font-medium ${isDark ? "text-slate-400" : "text-slate-600 font-semibold"}`}
                            title={`IST Timestamp: ${formatIST(m.created_at)}`}
                          >
                            {formatIST(m.created_at)}
                          </span>
                        </div>
                      )}

                      {/* Message Content: Clean, Normal Full Display Without Any Collapse/Expand Obfuscation */}
                      <div className="py-1">
                        {isUser ? (
                          <div className="whitespace-pre-wrap leading-relaxed font-sans">{m.content}</div>
                        ) : (
                          <RichMessageRenderer content={m.content} />
                        )}
                        {loading && m.id.startsWith("res-") && m.content === "" && (
                          <span className="inline-block w-2 h-4 bg-cyan-400 ml-1 animate-pulse align-middle rounded-sm" />
                        )}
                      </div>

                      {/* Tool Execution Trace Accordion */}
                      {hasTools && isExpanded && (
                        <div className="pt-2 border-t border-slate-800 font-mono">
                          <div className="mt-2 space-y-1.5">
                            {m.tool_calls?.tools?.map((t: any, tidx: number) => (
                              <div
                                key={tidx}
                                className={`p-2 rounded border text-[10px] ${
                                  isDark ? "bg-slate-950 border-slate-800" : "bg-slate-50 border-slate-200"
                                }`}
                              >
                                <div className="text-purple-600 font-bold flex items-center gap-1">
                                  <CheckCircle2 className="w-3 h-3 text-emerald-500" />
                                  <span>{t.tool}()</span>
                                </div>
                                <pre
                                  className={`overflow-x-auto mt-1 p-1.5 rounded border ${
                                    isDark ? "text-slate-300 bg-slate-900 border-slate-800" : "text-slate-800 bg-white border-slate-200 font-medium"
                                  }`}
                                >
                                  {JSON.stringify(t.output, null, 2)}
                                </pre>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Assistant Action Bar: Copy, Regenerate, Helpful / Not Helpful Feedback */}
                      {isAssistant && (
                        <div
                          className={`pt-2.5 mt-2 border-t flex flex-wrap items-center justify-between text-xs ${
                            isDark ? "border-slate-800/80 text-slate-300" : "border-slate-200 text-slate-800 font-medium"
                          }`}
                        >
                          <div className="flex items-center space-x-1.5">
                            <button
                              onClick={() => handleCopyMessage(m.id, m.content)}
                              className={`p-1.5 rounded-md transition-all flex items-center gap-1.5 border text-xs font-semibold cursor-pointer ${
                                isCopied
                                  ? "bg-emerald-500/20 text-emerald-500 border-emerald-500/50"
                                  : isDark
                                  ? "hover:bg-slate-800 text-slate-300 hover:text-cyan-300 border-slate-800"
                                  : "hover:bg-slate-100 text-slate-800 hover:text-sky-900 border-slate-200 shadow-xs"
                              }`}
                              title="Copy Full Response"
                            >
                              {isCopied ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
                              <span>{isCopied ? "Copied!" : "Copy"}</span>
                            </button>

                            <button
                              onClick={handleRegenerateLast}
                              className={`p-1.5 rounded-md transition-all flex items-center gap-1.5 border text-xs font-semibold cursor-pointer ${
                                isDark
                                  ? "hover:bg-slate-800 text-slate-300 hover:text-cyan-300 border-slate-800"
                                  : "hover:bg-slate-100 text-slate-800 hover:text-sky-900 border-slate-200 shadow-xs"
                              }`}
                              title="Regenerate Response"
                            >
                              <RotateCcw className="w-3.5 h-3.5" />
                              <span>Regenerate</span>
                            </button>
                          </div>

                          {/* Helpful Feedback Actions */}
                          <div className="flex items-center space-x-1.5">
                            <span className={`text-[11px] font-semibold mr-1 ${isDark ? "text-slate-400" : "text-slate-700"}`}>
                              Was this helpful?
                            </span>
                            <button
                              onClick={() => handleFeedback(m.id, "helpful")}
                              className={`p-1.5 rounded-md transition-colors border cursor-pointer ${
                                currentFeedback === "helpful"
                                  ? "bg-emerald-500/20 text-emerald-600 border-emerald-500/60 font-bold"
                                  : isDark
                                  ? "hover:bg-slate-800 text-slate-400 hover:text-emerald-400 border-slate-800"
                                  : "hover:bg-slate-100 text-slate-700 hover:text-emerald-800 border-slate-200"
                              }`}
                              title="Mark as Helpful"
                            >
                              <ThumbsUp className="w-3.5 h-3.5" />
                            </button>
                            <button
                              onClick={() => handleFeedback(m.id, "not_helpful")}
                              className={`p-1.5 rounded-md transition-colors border cursor-pointer ${
                                currentFeedback === "not_helpful"
                                  ? "bg-rose-500/20 text-rose-600 border-rose-500/60 font-bold"
                                  : isDark
                                  ? "hover:bg-slate-800 text-slate-400 hover:text-rose-400 border-slate-800"
                                  : "hover:bg-slate-100 text-slate-700 hover:text-rose-800 border-slate-200"
                              }`}
                              title="Mark as Not Helpful"
                            >
                              <ThumbsDown className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </div>
                      )}
                    </div>

                    <span
                      className={`text-[9px] font-mono mt-1 px-1 font-medium ${isDark ? "text-slate-400" : "text-slate-600"}`}
                      title={`IST Timestamp: ${formatIST(m.created_at)}`}
                    >
                      {formatIST(m.created_at)}
                    </span>
                  </div>
                );
              })
            )}

            {loading && (
              <div
                className={`flex items-center gap-2 text-xs font-mono p-3 rounded-xl border w-fit ${
                  isDark
                    ? "bg-slate-900/60 border-slate-800 text-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.15)]"
                    : "bg-white border-slate-200 text-sky-800 shadow-xs font-semibold"
                }`}
              >
                <div className="w-3.5 h-3.5 border-2 border-cyan-500/20 border-t-cyan-500 rounded-full animate-spin"></div>
                <span>Sentinel Copilot synthesizing forensic intelligence...</span>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          {/* Sticky Input Bar at Bottom */}
          <div
            className={`p-3.5 border-t transition-colors shrink-0 ${
              isDark ? "border-slate-800 bg-[#0B111F]" : "border-slate-200 bg-slate-50"
            }`}
          >
            <form onSubmit={(e) => handleSendMessage(e)} className="flex gap-2">
              <input
                type="text"
                value={inputMessage}
                onChange={(e) => setInputMessage(e.target.value)}
                placeholder="Ask Sentinel Copilot (e.g. 'How does phishing attack work with a diagram?')..."
                className={`flex-1 px-4 py-2.5 border rounded-lg text-xs font-sans transition-colors focus:outline-none focus:border-cyan-500 ${
                  isDark
                    ? "bg-slate-900/90 border-slate-800 text-slate-100 placeholder-slate-500"
                    : "bg-white border-slate-300 text-slate-950 placeholder-slate-500 font-medium"
                }`}
              />
              <button
                type="submit"
                disabled={loading || !inputMessage.trim()}
                className={`px-4 py-2.5 rounded-lg font-semibold text-xs shadow-md transition-all flex items-center gap-1.5 disabled:opacity-40 cursor-pointer ${
                  isDark
                    ? "bg-gradient-to-r from-purple-600 via-indigo-600 to-cyan-500 hover:from-purple-500 hover:to-cyan-400 text-white cyber-glow-cyan"
                    : "bg-gradient-to-r from-sky-600 to-indigo-600 hover:from-sky-500 hover:to-indigo-500 text-white shadow-xs font-bold"
                }`}
              >
                <Send className="w-3.5 h-3.5" />
                <span className="hidden sm:inline">Send</span>
              </button>
            </form>
          </div>
        </div>
      </div>
    </div>
  );
};
