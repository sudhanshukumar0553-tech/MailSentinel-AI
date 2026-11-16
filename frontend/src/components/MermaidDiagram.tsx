import React, { useEffect, useRef, useState } from "react";
import mermaid from "mermaid";
import { Check, Copy, AlertCircle, Maximize2, Minimize2, Download } from "lucide-react";
import { useTheme } from "../context/ThemeContext";

interface MermaidDiagramProps {
  chart: string;
  title?: string;
}

export const MermaidDiagram: React.FC<MermaidDiagramProps> = ({ chart, title }) => {
  const { isDark } = useTheme();
  const containerRef = useRef<HTMLDivElement>(null);
  const [svgContent, setSvgContent] = useState<string>("");
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [uniqueId] = useState(() => `mermaid-${Math.random().toString(36).substring(2, 9)}`);

  useEffect(() => {
    let isMounted = true;

    const renderChart = async () => {
      try {
        setError(null);
        mermaid.initialize({
          startOnLoad: false,
          securityLevel: "loose",
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

        // Clean up code string
        const cleanChart = chart.trim();
        const renderId = `${uniqueId}-${Date.now()}`;
        const { svg } = await mermaid.render(renderId, cleanChart);

        if (isMounted) {
          setSvgContent(svg);
        }
      } catch (err: any) {
        if (isMounted) {
          console.warn("Mermaid diagram rendering error:", err);
          setError(err?.message || "Failed to render diagram");
        }
      }
    };

    renderChart();

    return () => {
      isMounted = false;
    };
  }, [chart, isDark, uniqueId]);

  const handleCopyCode = async () => {
    try {
      await navigator.clipboard.writeText(chart.trim());
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
      {/* Header bar */}
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
            <span className="text-[10px] hidden sm:inline">{copied ? "Copied" : "Copy Code"}</span>
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

      {/* Diagram Content */}
      <div
        ref={containerRef}
        className={`p-4 flex-1 flex items-center justify-center overflow-x-auto min-h-[160px] ${
          isDark ? "bg-[#070B14]" : "bg-slate-50/50"
        }`}
      >
        {error ? (
          <div className="text-xs space-y-2 p-3 rounded-lg border border-amber-500/30 bg-amber-500/10 text-amber-300">
            <div className="flex items-center gap-1.5 font-bold">
              <AlertCircle className="w-4 h-4 text-amber-400" />
              <span>Diagram Rendering Notice</span>
            </div>
            <pre className="font-mono text-[11px] overflow-x-auto text-slate-300 p-2 bg-slate-900/60 rounded">
              {chart}
            </pre>
          </div>
        ) : svgContent ? (
          <div
            className="w-full flex justify-center [&_svg]:max-w-full [&_svg]:h-auto transition-transform"
            dangerouslySetInnerHTML={{ __html: svgContent }}
          />
        ) : (
          <div className="flex items-center gap-2 text-xs font-mono text-cyan-400">
            <span className="w-3 h-3 border-2 border-cyan-400/30 border-t-cyan-400 rounded-full animate-spin"></span>
            <span>Rendering visual diagram...</span>
          </div>
        )}
      </div>
    </div>
  );
};

