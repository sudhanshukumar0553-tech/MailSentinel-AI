import React, { useEffect, useRef, useState, useCallback, Component, type ReactNode } from "react";
import mermaid from "mermaid";
import { Check, Copy, Maximize2, Minimize2, Download, Code2 } from "lucide-react";
import { useTheme } from "../context/ThemeContext";

interface MermaidDiagramProps {
  chart: string;
  title?: string;
}

// 1. Silent Error Diagram Override
// Replaces Mermaid's default error renderer so it NEVER draws the bomb icon SVG or error text
const silentErrorDiagram = {
  db: {
    clear() {},
    setErrorMessage() {},
    getErrorMessage() {
      return "";
    }
  },
  styles: {},
  renderer: {
    draw() {
      // Intentionally empty: suppresses rendering the bomb icon SVG into the DOM
    }
  },
  parser: {
    parse() {}
  },
  init() {}
};

// Global initialization flag
let isMermaidInitialized = false;

function ensureMermaidInitialized() {
  if (isMermaidInitialized || typeof window === "undefined") return;

  try {
    mermaid.initialize({
      startOnLoad: false,
      securityLevel: "loose",
      suppressErrorRendering: true,
      logLevel: "fatal"
    });

    if (typeof mermaid.setParseErrorHandler === "function") {
      mermaid.setParseErrorHandler(() => {});
    }

    // Register silent error diagram override
    if (typeof mermaid.registerExternalDiagrams === "function") {
      mermaid
        .registerExternalDiagrams(
          [
            {
              id: "error",
              detector: (t: string) => t.toLowerCase().trim() === "error",
              loader: async () => ({ id: "error", diagram: silentErrorDiagram })
            }
          ],
          { lazyLoad: false }
        )
        .catch(() => {});
    }

    isMermaidInitialized = true;
  } catch {
    // Non-blocking initialization
  }
}

// 2. Global MutationObserver Guard: Instantly purges any temporary Mermaid error nodes attached to document.body
if (typeof window !== "undefined" && !(window as any).__mermaid_cleanup_guard_installed) {
  (window as any).__mermaid_cleanup_guard_installed = true;

  const purgeStrayNodes = () => {
    try {
      document.querySelectorAll('body > [id^="dmermaid"], body > [id^="dmmd"], body > svg[id^="mermaid-"], .error-icon, .error-text').forEach((el) => {
        el.remove();
      });
    } catch {
      // Safe noop
    }
  };

  try {
    const observer = new MutationObserver((mutations) => {
      for (const m of mutations) {
        m.addedNodes.forEach((node) => {
          if (node instanceof HTMLElement || node instanceof SVGElement) {
            if (
              node.id?.startsWith("dmermaid") ||
              node.id?.startsWith("dmmd") ||
              node.classList?.contains("error-icon") ||
              node.querySelector?.(".error-icon, .error-text")
            ) {
              node.remove();
            }
          }
        });
      }
    });
    observer.observe(document.body, { childList: true, subtree: true });
    setInterval(purgeStrayNodes, 1000);
  } catch {
    // Safe noop
  }
}

/**
 * Sanitizes and normalizes LLM-generated Mermaid code.
 * Encloses node labels with special characters in double quotes,
 * removes stray markdown code fences, and guarantees a recognized diagram directive.
 */
export function sanitizeMermaidCode(raw: string): string {
  if (!raw) return "";

  // 1. Strip markdown fences and language headers if present inside string
  let cleaned = raw
    .replace(/^```[a-zA-Z0-9_\-\s]*\n?/gm, "")
    .replace(/```$/gm, "")
    .trim();

  // 2. Remove HTML tags that break strict parsers
  cleaned = cleaned.replace(/<br\s*\/?>/gi, " ").replace(/<\/?[a-z][a-z0-9]*[^<>]*>/gi, "");

  // 3. Inspect directive
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
    lines.splice(firstContentIdx, 0, "flowchart TD");
  }

  // 4. Sanitize node labels in flowchart/graph lines
  // AI models frequently output unquoted brackets containing (), {}, [], /, &, :, #
  const processedLines = lines.map((line) => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("%%") || validStarters.some((s) => trimmed.startsWith(s))) {
      return line;
    }

    // Auto-quote square bracket node labels: id[some text with () / & :]
    let formatted = line.replace(/(\b[A-Za-z0-9_-]+\s*)\[([^"\]\r\n]+)\]/g, (match, prefix, label) => {
      const trimmedLabel = label.trim();
      if (/[\(\)\{\}\/&:,\#]/.test(trimmedLabel)) {
        const safeLabel = trimmedLabel.replace(/"/g, "'");
        return `${prefix}["${safeLabel}"]`;
      }
      return match;
    });

    // Auto-quote stadium node labels: id([some text with () / & :])
    formatted = formatted.replace(/(\b[A-Za-z0-9_-]+\s*)\(\[([^"\]\r\n]+)\]\)/g, (match, prefix, label) => {
      const trimmedLabel = label.trim();
      if (/[\(\)\{\}\/&:,\#]/.test(trimmedLabel)) {
        const safeLabel = trimmedLabel.replace(/"/g, "'");
        return `${prefix}(["${safeLabel}"])`;
      }
      return match;
    });

    return formatted;
  });

  return processedLines.join("\n").trim();
}

/**
 * Inner Mermaid Diagram Renderer Component
 */
const MermaidDiagramInner: React.FC<MermaidDiagramProps> = ({ chart, title }) => {
  const { isDark } = useTheme();
  const containerRef = useRef<HTMLDivElement>(null);
  const [svgContent, setSvgContent] = useState<string>("");
  const [hasError, setHasError] = useState<boolean>(false);
  const [sanitizedCode, setSanitizedCode] = useState<string>("");
  const [copied, setCopied] = useState(false);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [isRendering, setIsRendering] = useState(false);
  const renderCountRef = useRef(0);

  useEffect(() => {
    ensureMermaidInitialized();
  }, []);

  const renderChart = useCallback(async () => {
    const currentRenderId = ++renderCountRef.current;
    setIsRendering(true);
    setHasError(false);

    const cleanChart = sanitizeMermaidCode(chart);
    setSanitizedCode(cleanChart);

    if (!cleanChart) {
      setHasError(true);
      setIsRendering(false);
      return;
    }

    const uniqueDomId = `mmd-${Math.random().toString(36).substring(2, 9)}-${Date.now()}`;

    try {
      ensureMermaidInitialized();

      // Configure theme dynamically
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

      // 1. Strict syntax pre-validation
      try {
        const isValid = await mermaid.parse(cleanChart, { suppressErrors: true });
        if (isValid === false) {
          throw new Error("Syntax check returned false");
        }
      } catch {
        throw new Error("Invalid diagram syntax");
      }

      // 2. Render SVG
      const { svg } = await mermaid.render(uniqueDomId, cleanChart);

      // Verify returned SVG does not contain Mermaid error artifacts
      if (svg.includes("error-icon") || svg.includes("Syntax error in text")) {
        throw new Error("Render produced an error diagram");
      }

      // Clean up any stray DOM elements Mermaid may have attached to body
      const stray = document.getElementById(`d${uniqueDomId}`) || document.getElementById(uniqueDomId);
      if (stray) stray.remove();

      if (currentRenderId === renderCountRef.current) {
        setSvgContent(svg);
        setHasError(false);
      }
    } catch {
      // Immediate cleanup of any temporary elements in document.body
      try {
        const stray = document.getElementById(`d${uniqueDomId}`) || document.getElementById(uniqueDomId);
        if (stray) stray.remove();
        document.querySelectorAll('body > [id^="dmermaid"], body > [id^="dmmd"], body > svg[id^="mermaid-"]').forEach((el) => {
          el.remove();
        });
      } catch {
        // Safe noop
      }

      if (currentRenderId === renderCountRef.current) {
        setHasError(true);
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
    } catch {
      // Safe noop
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

  // Requirement 5: Clean, minimal fallback message: "Diagram temporarily unavailable."
  // Never displays bomb icons, error screens, or repeated error components.
  if (hasError) {
    return (
      <div
        className={`my-2 px-3.5 py-2.5 rounded-lg border text-xs font-mono flex items-center justify-between select-none ${
          isDark
            ? "bg-[#0A101D] border-slate-800/80 text-slate-400"
            : "bg-slate-50 border-slate-200 text-slate-600"
        }`}
      >
        <div className="flex items-center gap-2">
          <Code2 className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
          <span className="font-medium text-[11px] text-slate-300">Diagram temporarily unavailable.</span>
        </div>

        <button
          onClick={handleCopyCode}
          className="text-[11px] text-cyan-400 hover:text-cyan-300 font-mono transition-colors cursor-pointer flex items-center gap-1"
          title="Copy Diagram Source Code"
        >
          {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
          <span>{copied ? "Copied" : "Copy Source"}</span>
        </button>
      </div>
    );
  }

  // Normal Valid Diagram Rendering
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
          <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
          <span className="font-bold tracking-wide">
            {title || "Cybersecurity Architecture / Workflow Diagram"}
          </span>
        </div>

        <div className="flex items-center space-x-1">
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

      {/* Diagram Content Area */}
      <div
        ref={containerRef}
        className={`p-4 flex-1 flex items-center justify-center overflow-x-auto min-h-[140px] ${
          isDark ? "bg-[#070B14]" : "bg-slate-50/50"
        }`}
      >
        {isRendering && !svgContent ? (
          <div className="flex items-center gap-2 text-xs font-mono text-cyan-400">
            <span className="w-3.5 h-3.5 border-2 border-cyan-400/30 border-t-cyan-400 rounded-full animate-spin"></span>
            <span>Rendering visual diagram...</span>
          </div>
        ) : svgContent ? (
          <div
            className="w-full flex justify-center [&_svg]:max-w-full [&_svg]:h-auto transition-transform"
            dangerouslySetInnerHTML={{ __html: svgContent }}
          />
        ) : (
          <div className="text-xs font-mono text-slate-500">Diagram temporarily unavailable.</div>
        )}
      </div>
    </div>
  );
};

interface ErrorBoundaryProps {
  children: ReactNode;
}

interface ErrorBoundaryState {
  hasError: boolean;
}

/**
 * React Error Boundary around Mermaid rendering to catch any uncaught exceptions
 */
class MermaidErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(): ErrorBoundaryState {
    return { hasError: true };
  }

  componentDidCatch(error: any) {
    console.warn("Caught Mermaid rendering exception in Error Boundary:", error);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="my-2 px-3.5 py-2.5 rounded-lg border border-slate-800 bg-[#0A101D] text-slate-400 text-xs font-mono flex items-center gap-2 select-none">
          <Code2 className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
          <span className="text-[11px] text-slate-300">Diagram temporarily unavailable.</span>
        </div>
      );
    }
    return this.props.children;
  }
}

export const MermaidDiagram: React.FC<MermaidDiagramProps> = (props) => {
  return (
    <MermaidErrorBoundary>
      <MermaidDiagramInner {...props} />
    </MermaidErrorBoundary>
  );
};
