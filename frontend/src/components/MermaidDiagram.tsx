import React, { useEffect, useRef, useState, useCallback } from "react";
import mermaid from "mermaid";
import { Check, Copy, AlertCircle, Maximize2, Minimize2, Download, RefreshCw, Code2 } from "lucide-react";
import { useTheme } from "../context/ThemeContext";

interface MermaidDiagramProps {
  chart: string;
  title?: string;
}

// Global pre-warming flag to ensure flowchart module is imported early
let isPrewarmed = false;
async function prewarmMermaid() {
  if (isPrewarmed || typeof window === "undefined") return;
  try {
    mermaid.initialize({
      startOnLoad: false,
      securityLevel: "loose",
      suppressErrorRendering: true
    });
    if (typeof mermaid.setParseErrorHandler === "function") {
      mermaid.setParseErrorHandler(() => {});
    }
    await mermaid.parse("flowchart TD\nStart-->End", { suppressErrors: true });
    isPrewarmed = true;
  } catch {
    // Non-blocking pre-warm
  }
}

/**
 * Sanitizes and normalizes LLM-generated Mermaid code.
 * Fixes unquoted brackets with special characters, removes stray backticks/HTML,
 * and ensures a recognized diagram directive is present.
 */
export function sanitizeMermaidCode(raw: string): string {
  if (!raw) return "";

  // 1. Strip markdown fences and language annotations if embedded inside string
  let cleaned = raw
    .replace(/^```[a-zA-Z0-9_\-\s]*\n?/gm, "")
    .replace(/```$/gm, "")
    .trim();

  // 2. Strip stray HTML line breaks or tags that break strict parsers
  cleaned = cleaned.replace(/<br\s*\/?>/gi, " ").replace(/<\/?[a-z][a-z0-9]*[^<>]*>/gi, "");

  // 3. Split into lines and inspect directive
  const lines = cleaned.split("\n").map((l) => l.trimEnd());
  const firstContentIdx = lines.findIndex((l) => l.trim() && !l.trim().startsWith("%%"));
  if (firstContentIdx === -1) {
    return "";
  }

  const validStarters = [
    "flowchart",
    "graph",
    "sequenceDiagram",
    "classDiagram",
    "stateDiagram",
    "erDiagram",
    "pie",
    "gantt",
    "journey",
    "gitGraph",
    "quadrantChart",
    "architecture"
  ];

  const firstLine = lines[firstContentIdx].trim();
  const startsWithValid = validStarters.some((s) => firstLine.startsWith(s));

  if (!startsWithValid) {
    // Default to standard top-down flowchart
    lines.splice(firstContentIdx, 0, "flowchart TD");
  }

  // 4. Sanitize node labels in flowchart/graph lines
  // AI models often output: A[Step 1 (Verify)] or A[FastAPI & Auth] or A[Port: 8000]
  // Unquoted brackets with special chars () {} [] / & : # trigger syntax exceptions in Mermaid.
  const processedLines = lines.map((line) => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("%%") || validStarters.some((s) => trimmed.startsWith(s))) {
      return line;
    }

    // Replace unquoted node labels: id[some text with () or / or & or :]
    return line.replace(/(\b[A-Za-z0-9_-]+\s*)\[([^"\]\r\n]+)\]/g, (match, prefix, label) => {
      const trimmedLabel = label.trim();
      // If label contains special characters: () {} [] / & : # "
      if (/[\(\)\{\}\/&:,\#]/.test(trimmedLabel)) {
        const safeLabel = trimmedLabel.replace(/"/g, "'");
        return `${prefix}["${safeLabel}"]`;
      }
      return match;
    });
  });

  return processedLines.join("\n").trim();
}

export const MermaidDiagram: React.FC<MermaidDiagramProps> = ({ chart, title }) => {
  const { isDark } = useTheme();
  const containerRef = useRef<HTMLDivElement>(null);
  const [svgContent, setSvgContent] = useState<string>("");
  const [error, setError] = useState<string | null>(null);
  const [sanitizedCode, setSanitizedCode] = useState<string>("");
  const [copied, setCopied] = useState(false);
  const [showCode, setShowCode] = useState(false);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [isRendering, setIsRendering] = useState(false);
  const renderCountRef = useRef(0);

  // Pre-warm parser on first mount
  useEffect(() => {
    prewarmMermaid();
  }, []);

  const renderChart = useCallback(async () => {
    const currentRenderId = ++renderCountRef.current;
    setIsRendering(true);
    setError(null);

    const cleanChart = sanitizeMermaidCode(chart);
    setSanitizedCode(cleanChart);

    if (!cleanChart) {
      setError("Empty diagram definition received.");
      setIsRendering(false);
      return;
    }

    const uniqueDomId = `mmd-${Math.random().toString(36).substring(2, 9)}-${Date.now()}`;

    try {
      // 1. Initialize with suppressErrorRendering to prevent Mermaid injecting bomb icons into the DOM
      mermaid.initialize({
        startOnLoad: false,
        securityLevel: "loose",
        suppressErrorRendering: true,
        theme: isDark ? "dark" : "default",
        themeVariables: isDark
          ? {
              darkMode: true,
              background: "#0E1726",
              primaryColor: "#06B6D4",
              primaryTextColor: "#F8FAFC",
              primaryBorderColor: "#38BDF8",
              lineColor: "#38BDF8",
              secondaryColor: "#8B5CF6",
              tertiaryColor: "#1E293B",
              fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
              fontSize: "13px"
            }
          : {
              darkMode: false,
              background: "#FFFFFF",
              primaryColor: "#0284C7",
              primaryTextColor: "#0F172A",
              primaryBorderColor: "#0284C7",
              lineColor: "#0284C7",
              secondaryColor: "#7C3AED",
              tertiaryColor: "#F1F5F9",
              fontFamily: "system-ui, -apple-system, sans-serif",
              fontSize: "13px"
            }
      });

      if (typeof mermaid.setParseErrorHandler === "function") {
        mermaid.setParseErrorHandler(() => {});
      }

      // 2. Validate syntax first to prevent unhandled exceptions or broken DOM nodes
      try {
        const isValid = await mermaid.parse(cleanChart, { suppressErrors: true });
        if (isValid === false) {
          throw new Error("Mermaid syntax validation check returned false.");
        }
      } catch (parseErr: any) {
        throw new Error(parseErr?.message || "Invalid Mermaid syntax.");
      }

      // 3. Render SVG
      const { svg } = await mermaid.render(uniqueDomId, cleanChart);

      // Clean up any stray DOM elements Mermaid may have appended to document.body
      const stray = document.getElementById(`d${uniqueDomId}`) || document.getElementById(uniqueDomId);
      if (stray) stray.remove();

      if (currentRenderId === renderCountRef.current) {
        setSvgContent(svg);
        setError(null);
      }
    } catch (err: any) {
      // Always remove any orphan error elements left behind by Mermaid
      const stray = document.getElementById(`d${uniqueDomId}`) || document.getElementById(uniqueDomId);
      if (stray) stray.remove();

      // Clean up any bomb icon SVGs that Mermaid may have directly attached to body
      if (typeof document !== "undefined") {
        document.querySelectorAll('svg[id^="mermaid-"]').forEach((el) => {
          if (el.parentElement === document.body) {
            el.remove();
          }
        });
      }

      if (currentRenderId === renderCountRef.current) {
        const errMsg = err?.message || "Diagram could not be rendered.";
        if (errMsg.includes("dynamically imported module") || errMsg.includes("Failed to fetch")) {
          setError("Visual diagram renderer module loading. Click Retry Render or view diagram source below.");
        } else {
          setError(errMsg.split("\n")[0]);
        }
        setSvgContent("");
      }
    } finally {
      if (currentRenderId === renderCountRef.current) {
        setIsRendering(false);
      }
    }
  }, [chart, isDark]);

  useEffect(() => {
    renderChart();
  }, [renderChart]);

  const handleCopyCode = async () => {
    try {
      await navigator.clipboard.writeText((sanitizedCode || chart).trim());
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error("Failed to copy diagram code:", err);
    }
  };

  const handleDownloadSvg = () => {
    if (!svgContent) return;
    const blob = new Blob([svgContent], { type: "image/svg+xml" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `mailsentinel-diagram-${Date.now()}.svg`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <div
      className={`my-4 rounded-xl border transition-all overflow-hidden ${
        isDark
          ? "bg-[#0A101D] border-cyan-500/30 shadow-[0_0_15px_rgba(6,182,212,0.1)]"
          : "bg-white border-sky-200 shadow-sm"
      } ${isFullscreen ? "fixed inset-4 z-50 flex flex-col p-6 shadow-2xl" : ""}`}
    >
      {/* Header Bar */}
      <div
        className={`px-3 py-2 border-b flex items-center justify-between text-xs font-mono ${
          isDark ? "bg-[#0E1726] border-slate-800 text-slate-300" : "bg-slate-50 border-slate-200 text-slate-700"
        }`}
      >
        <div className="flex items-center space-x-2">
          <span className={`w-2 h-2 rounded-full ${error ? "bg-amber-400" : "bg-cyan-400 animate-pulse"}`}></span>
          <span className="font-bold tracking-wide">
            {title || "Cybersecurity Architecture / Workflow Diagram"}
          </span>
        </div>

        <div className="flex items-center space-x-1">
          {error && (
            <button
              onClick={() => renderChart()}
              disabled={isRendering}
              className={`p-1 rounded text-xs transition-colors flex items-center gap-1 px-2 ${
                isDark
                  ? "hover:bg-slate-800 text-cyan-400 hover:text-cyan-300"
                  : "hover:bg-slate-200 text-sky-600 hover:text-sky-700"
              }`}
              title="Retry Rendering"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isRendering ? "animate-spin" : ""}`} />
              <span className="text-[10px] hidden sm:inline">Retry</span>
            </button>
          )}

          <button
            onClick={() => setShowCode(!showCode)}
            className={`p-1 rounded text-xs transition-colors flex items-center gap-1 px-2 ${
              isDark
                ? "hover:bg-slate-800 text-slate-300 hover:text-cyan-300"
                : "hover:bg-slate-200 text-slate-600 hover:text-sky-600"
            }`}
            title="Toggle Code View"
          >
            <Code2 className="w-3.5 h-3.5" />
            <span className="text-[10px] hidden sm:inline">{showCode ? "Hide Code" : "View Code"}</span>
          </button>

          <button
            onClick={handleCopyCode}
            className={`p-1 rounded text-xs transition-colors flex items-center gap-1 px-2 ${
              isDark
                ? "hover:bg-slate-800 text-slate-300 hover:text-cyan-300"
                : "hover:bg-slate-200 text-slate-600 hover:text-sky-600"
            }`}
            title="Copy Mermaid Code"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span className="text-[10px] hidden sm:inline">{copied ? "Copied" : "Copy"}</span>
          </button>

          {svgContent && (
            <button
              onClick={handleDownloadSvg}
              className={`p-1 rounded text-xs transition-colors ${
                isDark ? "hover:bg-slate-800 text-slate-300 hover:text-cyan-300" : "hover:bg-slate-200 text-slate-600 hover:text-sky-600"
              }`}
              title="Download SVG"
            >
              <Download className="w-3.5 h-3.5" />
            </button>
          )}

          <button
            onClick={() => setIsFullscreen(!isFullscreen)}
            className={`p-1 rounded text-xs transition-colors ${
              isDark ? "hover:bg-slate-800 text-slate-300 hover:text-cyan-300" : "hover:bg-slate-200 text-slate-600 hover:text-sky-600"
            }`}
            title={isFullscreen ? "Exit Fullscreen" : "Fullscreen View"}
          >
            {isFullscreen ? <Minimize2 className="w-3.5 h-3.5" /> : <Maximize2 className="w-3.5 h-3.5" />}
          </button>
        </div>
      </div>

      {/* Code Toggle Drawer */}
      {showCode && (
        <div className={`p-3 border-b font-mono text-[11px] ${
          isDark ? "bg-[#060A12] border-slate-800 text-slate-300" : "bg-slate-100 border-slate-200 text-slate-800"
        }`}>
          <div className="flex items-center justify-between pb-1.5 text-[10px] text-slate-500 font-bold uppercase tracking-wider">
            <span>Mermaid Definition (Sanitized)</span>
          </div>
          <pre className="overflow-x-auto p-2.5 rounded bg-black/40 text-cyan-300 border border-slate-800">
            {sanitizedCode || chart}
          </pre>
        </div>
      )}

      {/* Diagram Content Area */}
      <div
        ref={containerRef}
        className={`p-4 flex-1 flex items-center justify-center overflow-x-auto min-h-[160px] ${
          isDark ? "bg-[#070B14]" : "bg-slate-50/50"
        }`}
      >
        {isRendering ? (
          <div className="flex items-center gap-2 text-xs font-mono text-cyan-400">
            <span className="w-3.5 h-3.5 border-2 border-cyan-400/30 border-t-cyan-400 rounded-full animate-spin"></span>
            <span>Rendering visual diagram...</span>
          </div>
        ) : error ? (
          <div className="w-full text-xs space-y-3 p-4 rounded-xl border border-amber-500/30 bg-amber-500/10 text-amber-300">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 font-bold font-mono">
                <AlertCircle className="w-4 h-4 text-amber-400 shrink-0" />
                <span>Diagram Architecture Preview</span>
              </div>
              <button
                onClick={() => renderChart()}
                className="px-2 py-1 rounded bg-amber-500/20 hover:bg-amber-500/30 text-amber-200 text-[10px] font-mono font-bold flex items-center gap-1 transition-colors cursor-pointer"
              >
                <RefreshCw className="w-3 h-3" />
                <span>Retry Render</span>
              </button>
            </div>
            <p className="text-[11px] text-slate-400 font-mono">
              {error}
            </p>
            <pre className="font-mono text-[11px] overflow-x-auto text-cyan-300 p-3 bg-slate-950/80 rounded-lg border border-slate-800">
              {sanitizedCode || chart}
            </pre>
          </div>
        ) : svgContent ? (
          <div
            className="w-full flex justify-center [&_svg]:max-w-full [&_svg]:h-auto transition-transform"
            dangerouslySetInnerHTML={{ __html: svgContent }}
          />
        ) : (
          <div className="text-xs font-mono text-slate-500">No visual representation available.</div>
        )}
      </div>
    </div>
  );
};
