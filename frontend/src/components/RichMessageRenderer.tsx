import React, { useState } from "react";
import { MermaidDiagram } from "./MermaidDiagram";
import { Copy, Check, ShieldAlert, Info, Terminal } from "lucide-react";
import { useTheme } from "../context/ThemeContext";

interface RichMessageRendererProps {
  content: string;
}

export const RichMessageRenderer: React.FC<RichMessageRendererProps> = ({ content }) => {
  const { isDark } = useTheme();

  // Split content by code blocks: ```lang ... ```
  const parts: Array<{ type: "text" | "code" | "mermaid"; content: string; lang?: string }> = [];
  const codeBlockRegex = /```([a-zA-Z0-9_\-]*)\n([\s\S]*?)```/g;

  let lastIndex = 0;
  let match: RegExpExecArray | null;

  while ((match = codeBlockRegex.exec(content)) !== null) {
    if (match.index > lastIndex) {
      parts.push({
        type: "text",
        content: content.substring(lastIndex, match.index)
      });
    }

    const lang = (match[1] || "").toLowerCase().trim();
    const code = match[2];

    if (lang === "mermaid") {
      parts.push({
        type: "mermaid",
        content: code
      });
    } else {
      parts.push({
        type: "code",
        content: code,
        lang: lang || "text"
      });
    }

    lastIndex = match.index + match[0].length;
  }

  if (lastIndex < content.length) {
    parts.push({
      type: "text",
      content: content.substring(lastIndex)
    });
  }

  return (
    <div className="space-y-3 leading-relaxed text-xs font-sans">
      {parts.map((part, index) => {
        if (part.type === "mermaid") {
          return <MermaidDiagram key={index} chart={part.content} />;
        }

        if (part.type === "code") {
          return <CodeSnippet key={index} code={part.content} lang={part.lang} isDark={isDark} />;
        }

        return <FormattedMarkdownText key={index} text={part.content} isDark={isDark} />;
      })}
    </div>
  );
};

const CodeSnippet: React.FC<{ code: string; lang?: string; isDark: boolean }> = ({ code, lang, isDark }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (e) {
      console.error("Failed to copy code", e);
    }
  };

  return (
    <div
      className={`my-3 rounded-lg border overflow-hidden font-mono text-[11px] ${
        isDark ? "bg-[#0A101D] border-slate-800" : "bg-slate-50 border-slate-300"
      }`}
    >
      <div
        className={`px-3 py-1.5 border-b flex items-center justify-between text-[10px] ${
          isDark ? "bg-[#0E1726] border-slate-800 text-slate-400" : "bg-slate-200 border-slate-300 text-slate-800 font-bold"
        }`}
      >
        <div className="flex items-center gap-1.5 font-bold uppercase tracking-wider">
          <Terminal className="w-3 h-3 text-cyan-500" />
          <span>{lang || "snippet"}</span>
        </div>
        <button
          onClick={handleCopy}
          className={`flex items-center gap-1 transition-colors px-1.5 py-0.5 rounded cursor-pointer ${
            isDark ? "hover:bg-slate-800 hover:text-cyan-400" : "hover:bg-slate-300 text-slate-700 hover:text-slate-950"
          }`}
          title="Copy code"
        >
          {copied ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
          <span>{copied ? "Copied" : "Copy"}</span>
        </button>
      </div>
      <pre className="p-3 overflow-x-auto leading-relaxed">
        <code className={isDark ? "text-slate-200" : "text-slate-900 font-medium"}>{code.trim()}</code>
      </pre>
    </div>
  );
};

const FormattedMarkdownText: React.FC<{ text: string; isDark: boolean }> = ({ text, isDark }) => {
  // Process lines for headings, blockquotes, tables, lists, and paragraphs
  const lines = text.split("\n");
  const elements: React.ReactNode[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];
    const trimmed = line.trim();

    if (!trimmed) {
      i++;
      continue;
    }

    // Markdown Table Detection
    if (trimmed.startsWith("|") && trimmed.endsWith("|")) {
      const tableLines: string[] = [];
      while (i < lines.length && lines[i].trim().startsWith("|") && lines[i].trim().endsWith("|")) {
        tableLines.push(lines[i].trim());
        i++;
      }
      elements.push(<MarkdownTable key={`table-${i}`} lines={tableLines} isDark={isDark} />);
      continue;
    }

    // H1 Heading
    if (trimmed.startsWith("# ")) {
      elements.push(
        <h1
          key={`h1-${i}`}
          className={`text-lg font-bold mt-4 mb-2 flex items-center gap-2 ${
            isDark
              ? "bg-gradient-to-r from-white via-cyan-200 to-cyan-400 bg-clip-text text-transparent"
              : "text-slate-950 font-extrabold border-b border-slate-300 pb-1"
          }`}
        >
          <ShieldAlert className="w-4 h-4 text-cyan-500 shrink-0" />
          <span>{renderInline(trimmed.substring(2), isDark)}</span>
        </h1>
      );
      i++;
      continue;
    }

    // H2 Heading
    if (trimmed.startsWith("## ")) {
      elements.push(
        <h2
          key={`h2-${i}`}
          className={`text-base font-bold mt-3 mb-1.5 flex items-center gap-2 ${
            isDark ? "text-cyan-300" : "text-slate-900 font-extrabold"
          }`}
        >
          <span className="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
          <span>{renderInline(trimmed.substring(3), isDark)}</span>
        </h2>
      );
      i++;
      continue;
    }

    // H3 Heading
    if (trimmed.startsWith("### ")) {
      elements.push(
        <h3
          key={`h3-${i}`}
          className={`text-sm font-semibold mt-2.5 mb-1 ${
            isDark ? "text-purple-300" : "text-purple-950 font-bold"
          }`}
        >
          {renderInline(trimmed.substring(4), isDark)}
        </h3>
      );
      i++;
      continue;
    }

    // H4 Heading
    if (trimmed.startsWith("#### ")) {
      elements.push(
        <h4
          key={`h4-${i}`}
          className={`text-xs font-semibold mt-2 mb-1 uppercase tracking-wider ${
            isDark ? "text-slate-300" : "text-slate-900 font-bold"
          }`}
        >
          {renderInline(trimmed.substring(5), isDark)}
        </h4>
      );
      i++;
      continue;
    }

    // Blockquotes / Alerts
    if (trimmed.startsWith("> ")) {
      elements.push(
        <div
          key={`quote-${i}`}
          className={`my-2.5 p-3 rounded-lg border-l-4 text-xs font-medium flex items-start gap-2 ${
            isDark
              ? "bg-slate-900/80 border-cyan-500 text-cyan-200 shadow-sm"
              : "bg-sky-50 border-sky-600 text-sky-950 shadow-xs"
          }`}
        >
          <Info className="w-4 h-4 text-cyan-500 shrink-0 mt-0.5" />
          <div className="flex-1 font-medium">{renderInline(trimmed.substring(2), isDark)}</div>
        </div>
      );
      i++;
      continue;
    }

    // Horizontal Rule
    if (trimmed === "---" || trimmed === "***" || trimmed === "___") {
      elements.push(
        <hr
          key={`hr-${i}`}
          className={`my-3 border-t ${isDark ? "border-slate-800" : "border-slate-200"}`}
        />
      );
      i++;
      continue;
    }

    // Bullet List Item
    if (trimmed.startsWith("* ") || trimmed.startsWith("- ") || trimmed.startsWith("• ")) {
      elements.push(
        <div key={`li-${i}`} className="flex items-start gap-2 my-1 pl-1">
          <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 mt-1.5 shrink-0"></span>
          <span className={isDark ? "text-slate-200" : "text-slate-900 font-medium"}>
            {renderInline(trimmed.substring(2), isDark)}
          </span>
        </div>
      );
      i++;
      continue;
    }

    // Numbered List Item
    const numMatch = trimmed.match(/^(\d+)\.\s+(.*)/);
    if (numMatch) {
      elements.push(
        <div key={`num-${i}`} className="flex items-start gap-2 my-1 pl-1">
          <span className={`font-mono font-bold text-[11px] shrink-0 min-w-[16px] ${isDark ? "text-cyan-400" : "text-sky-700"}`}>
            {numMatch[1]}.
          </span>
          <span className={isDark ? "text-slate-200" : "text-slate-900 font-medium"}>
            {renderInline(numMatch[2], isDark)}
          </span>
        </div>
      );
      i++;
      continue;
    }

    // Standard paragraph
    elements.push(
      <p key={`p-${i}`} className={`my-1.5 leading-relaxed ${isDark ? "text-slate-200" : "text-slate-900 font-medium"}`}>
        {renderInline(trimmed, isDark)}
      </p>
    );
    i++;
  }

  return <div className="space-y-1">{elements}</div>;
};

const MarkdownTable: React.FC<{ lines: string[]; isDark: boolean }> = ({ lines, isDark }) => {
  if (lines.length < 2) return null;

  const headerCells = lines[0]
    .split("|")
    .map((c) => c.trim())
    .filter((c) => c.length > 0);

  // Skip delimiter line (e.g. |---|---|)
  const bodyRows = lines.slice(2).map((row) =>
    row
      .split("|")
      .map((c) => c.trim())
      .filter((c) => c.length > 0)
  );

  return (
    <div
      className={`my-3 overflow-x-auto rounded-lg border font-sans text-xs ${
        isDark ? "bg-[#0A101D] border-slate-800" : "bg-white border-slate-300 shadow-xs"
      }`}
    >
      <table className="min-w-full divide-y divide-slate-800">
        <thead className={isDark ? "bg-[#0E1726]" : "bg-slate-100"}>
          <tr>
            {headerCells.map((h, hidx) => (
              <th
                key={hidx}
                className={`px-3 py-2 text-left font-bold text-[11px] tracking-wider uppercase ${
                  isDark ? "text-cyan-300" : "text-slate-900 font-extrabold"
                }`}
              >
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className={`divide-y ${isDark ? "divide-slate-800" : "divide-slate-200"}`}>
          {bodyRows.map((row, ridx) => (
            <tr
              key={ridx}
              className={`${
                ridx % 2 === 0
                  ? isDark
                    ? "bg-slate-900/30"
                    : "bg-white"
                  : isDark
                  ? "bg-slate-900/60"
                  : "bg-slate-50"
              }`}
            >
              {row.map((cell, cidx) => (
                <td
                  key={cidx}
                  className={`px-3 py-2 text-xs font-mono whitespace-nowrap ${
                    isDark ? "text-slate-300" : "text-slate-900 font-medium"
                  }`}
                >
                  {cell}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

function renderInline(text: string, isDark: boolean): React.ReactNode[] {
  // Regex to split on bold (**bold**), code (`code`), or italics (*italic*)
  const tokens = text.split(/(\*\*.*?\*\*|`.*?`|\*.*?\*)/g);

  return tokens.map((token, idx) => {
    if (token.startsWith("**") && token.endsWith("**") && token.length >= 4) {
      return (
        <strong
          key={idx}
          className={`font-bold ${isDark ? "text-cyan-200" : "text-slate-950 font-extrabold"}`}
        >
          {token.substring(2, token.length - 2)}
        </strong>
      );
    }
    if (token.startsWith("`") && token.endsWith("`") && token.length >= 2) {
      return (
        <code
          key={idx}
          className={`px-1.5 py-0.5 rounded font-mono text-[11px] ${
            isDark
              ? "bg-slate-800 text-cyan-300 border border-slate-700"
              : "bg-slate-100 text-slate-950 border border-slate-300 font-bold"
          }`}
        >
          {token.substring(1, token.length - 1)}
        </code>
      );
    }
    if (token.startsWith("*") && token.endsWith("*") && token.length >= 2) {
      return (
        <em key={idx} className={`italic ${isDark ? "text-slate-300" : "text-slate-800 font-medium"}`}>
          {token.substring(1, token.length - 1)}
        </em>
      );
    }
    return token;
  });
}
