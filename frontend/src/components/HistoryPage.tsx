import React, { useEffect, useState } from "react";
import {
  History,
  Filter,
  Eye,
  X,
  Download,
  RefreshCw,
  AlertTriangle
} from "lucide-react";
import { api } from "../api/client";
import { useTheme } from "../context/ThemeContext";
import type { ScanResult, ThreatLevel } from "../types";
import { getThreatLevelConfig } from "../utils/formatters";
import { formatIST } from "../utils/dateFormatter";

interface HistoryPageProps {
  isActive?: boolean;
  refreshTrigger?: number;
  onNavigateToScanner?: () => void;
}

export const HistoryPage: React.FC<HistoryPageProps> = ({
  isActive = true,
  refreshTrigger = 0,
  onNavigateToScanner
}) => {
  const { isDark } = useTheme();
  const [scans, setScans] = useState<any[]>([]);
  const [filterLevel, setFilterLevel] = useState<string>("");
  const [selectedScan, setSelectedScan] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchHistory = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.getHistory(50, 0, filterLevel || undefined);
      setScans(res.scans || []);
    } catch (err: any) {
      console.error("Failed to load history:", err);
      setError(err.message || "Failed to load detection archive from server.");
    } finally {
      setLoading(false);
    }
  };

  // Re-fetch whenever tab becomes active, trigger changes, or filter changes
  useEffect(() => {
    if (isActive) {
      fetchHistory();
    }
  }, [isActive, refreshTrigger, filterLevel]);

  const viewDetail = async (id: string) => {
    try {
      const res = await api.getScanDetail(id);
      setSelectedScan(res);
    } catch (err) {
      console.error("Error retrieving scan detail:", err);
    }
  };

  const handleExportScanJson = (scan: ScanResult) => {
    const exportPayload = {
      ...scan,
      exported_at_utc: new Date().toISOString(),
      exported_at_ist: formatIST(new Date()),
      display_timezone: "Asia/Kolkata (IST - UTC+05:30)"
    };
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(exportPayload, null, 2));
    const downloadAnchor = document.createElement("a");
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `mailsentinel-scan-${scan.id}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="space-y-6">
      {/* Title & Filter Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1
            className={`text-2xl font-bold flex items-center gap-2.5 ${
              isDark ? "text-white" : "text-slate-900 font-extrabold"
            }`}
          >
            <div className="w-9 h-9 rounded-lg bg-gradient-to-tr from-cyan-600 to-blue-600 flex items-center justify-center shadow-[0_0_15px_rgba(6,182,212,0.3)]">
              <History className="w-5 h-5 text-white" />
            </div>
            <span>Detection History & Incident Archive</span>
          </h1>
          <p className={`text-xs mt-1 ${isDark ? "text-slate-400" : "text-slate-600 font-medium"}`}>
            Persistent audit log of all automated scans, heuristic evaluations, and triage outcomes.
          </p>
        </div>

        {/* Filter Dropdown & Manual Refresh Button */}
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={fetchHistory}
            disabled={loading}
            className={`p-2 rounded-lg border text-xs font-mono transition-all flex items-center justify-center cursor-pointer active:scale-95 ${
              isDark
                ? "bg-slate-900 border-slate-700 text-slate-300 hover:text-white hover:border-slate-500"
                : "bg-white border-slate-300 text-slate-700 hover:text-slate-950 shadow-xs"
            }`}
            title="Refresh Detection History"
            aria-label="Refresh Detection History"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin text-cyan-400" : "text-slate-400"}`} />
          </button>

          <div className="flex items-center gap-2">
            <Filter className={`w-4 h-4 ${isDark ? "text-slate-400" : "text-slate-500"}`} />
            <select
              value={filterLevel}
              onChange={(e) => setFilterLevel(e.target.value)}
              className={`px-3 py-1.5 rounded-lg border text-xs font-mono focus:outline-none focus:border-cyan-500 cursor-pointer transition-colors ${
                isDark
                  ? "bg-slate-900 border-slate-700 text-slate-200"
                  : "bg-white border-slate-300 text-slate-900 font-semibold shadow-xs"
              }`}
            >
              <option value="">All Threat Levels</option>
              <option value="CRITICAL">Critical Only</option>
              <option value="DANGEROUS">Dangerous Only</option>
              <option value="SUSPICIOUS">Suspicious Only</option>
              <option value="SAFE">Safe Only</option>
            </select>
          </div>
        </div>
      </div>

      {error && (
        <div className="p-3 rounded-lg bg-rose-950/60 border border-rose-500/40 text-rose-300 text-xs flex items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{error}</span>
          </div>
          <button
            onClick={fetchHistory}
            className="px-2.5 py-1 rounded bg-rose-900/60 hover:bg-rose-800 text-rose-200 text-[11px] font-mono font-bold cursor-pointer"
          >
            Retry
          </button>
        </div>
      )}

      {/* Desktop Scans Table with Sticky Header & Sticky Action Column */}
      <div
        className={`hidden md:block rounded-xl border shadow-sm transition-colors overflow-hidden ${
          isDark ? "bg-[#0E1726] border-slate-800" : "bg-white border-slate-200 shadow-xs"
        }`}
      >
        <div className="overflow-x-auto max-h-[68vh] overflow-y-auto relative">
          <table className="w-full text-left text-xs border-collapse">
            <thead
              className={`font-mono uppercase tracking-wider border-b sticky top-0 z-20 backdrop-blur-md ${
                isDark
                  ? "bg-[#0A101D]/95 text-slate-300 border-slate-800"
                  : "bg-slate-100/95 text-slate-800 border-slate-200 font-bold"
              }`}
            >
              <tr>
                <th className="py-3 px-4 min-w-[220px]">Subject</th>
                <th className="py-3 px-4 min-w-[180px]">Sender</th>
                <th className="py-3 px-4 min-w-[120px]">Threat Level</th>
                <th className="py-3 px-4 min-w-[100px]">Risk Score</th>
                <th className="py-3 px-4 min-w-[210px]">Timestamp (IST)</th>
                {/* Sticky Action Column */}
                <th
                  className={`py-3 px-4 text-center min-w-[110px] sticky right-0 z-30 shadow-[-6px_0_10px_-2px_rgba(0,0,0,0.15)] ${
                    isDark ? "bg-[#0A101D]" : "bg-slate-100"
                  }`}
                >
                  Action
                </th>
              </tr>
            </thead>
            <tbody className={`divide-y font-sans ${isDark ? "divide-slate-800/80" : "divide-slate-200"}`}>
              {loading ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-slate-400 font-mono">
                    <div className="flex items-center justify-center gap-2">
                      <div className="w-4 h-4 border-2 border-cyan-500/20 border-t-cyan-500 rounded-full animate-spin"></div>
                      <span>Loading detection archive...</span>
                    </div>
                  </td>
                </tr>
              ) : scans.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-slate-400 font-mono">
                    <p>No scan records found matching filter.</p>
                    {onNavigateToScanner && (
                      <button
                        onClick={onNavigateToScanner}
                        className="mt-2 text-xs text-cyan-400 hover:underline cursor-pointer inline-flex items-center gap-1 font-semibold"
                      >
                        Go to Live Scanner to analyze an email →
                      </button>
                    )}
                  </td>
                </tr>
              ) : (
                scans.map((scan) => {
                  const cfg = getThreatLevelConfig(scan.threat_level as ThreatLevel);
                  return (
                    <tr
                      key={scan.id}
                      className={`transition-colors group ${
                        isDark ? "hover:bg-slate-800/40" : "hover:bg-slate-50"
                      }`}
                    >
                      <td className={`py-3 px-4 font-semibold max-w-xs truncate ${isDark ? "text-slate-200" : "text-slate-900"}`}>
                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => viewDetail(scan.id)}
                            title="Inspect scan detail"
                            className="p-1 rounded text-cyan-400 hover:text-cyan-300 hover:bg-cyan-500/10 cursor-pointer"
                          >
                            <Eye className="w-3.5 h-3.5" />
                          </button>
                          <span className="truncate">{scan.subject}</span>
                        </div>
                      </td>
                      <td className={`py-3 px-4 max-w-xs truncate font-mono ${isDark ? "text-slate-400" : "text-slate-600 font-medium"}`}>
                        {scan.sender}
                      </td>
                      <td className="py-3 px-4">
                        <span className={`px-2 py-0.5 rounded font-mono font-bold text-[10px] border ${cfg.badgeBg}`}>
                          {scan.threat_level}
                        </span>
                      </td>
                      <td className={`py-3 px-4 font-mono font-bold ${isDark ? "text-white" : "text-slate-900"}`}>
                        {scan.risk_score}%
                      </td>
                      <td className={`py-3 px-4 font-mono text-xs whitespace-nowrap ${isDark ? "text-slate-400" : "text-slate-600"}`}>
                        {formatIST(scan.created_at)}
                      </td>
                      {/* Sticky Right Action Cell */}
                      <td
                        className={`py-3 px-4 text-center sticky right-0 z-10 shadow-[-6px_0_10px_-2px_rgba(0,0,0,0.15)] ${
                          isDark ? "bg-[#0E1726] group-hover:bg-[#131f33]" : "bg-white group-hover:bg-slate-50"
                        }`}
                      >
                        <button
                          onClick={() => viewDetail(scan.id)}
                          className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition-all inline-flex items-center gap-1.5 cursor-pointer border active:scale-95 ${
                            isDark
                              ? "bg-cyan-950/60 hover:bg-cyan-900/80 text-cyan-300 border-cyan-700/60 hover:shadow-[0_0_10px_rgba(6,182,212,0.3)]"
                              : "bg-sky-50 hover:bg-sky-100 text-sky-800 border-sky-300 shadow-xs"
                          }`}
                        >
                          <Eye className="w-3.5 h-3.5" />
                          <span>Inspect</span>
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Mobile Card Layout (Touch-Friendly Action Access) */}
      <div className="md:hidden space-y-3">
        {loading ? (
          <div className="p-8 text-center text-slate-400 font-mono text-xs">
            Loading detection archive...
          </div>
        ) : scans.length === 0 ? (
          <div className="p-8 text-center text-slate-400 font-mono text-xs">
            No scan records found matching filter.
          </div>
        ) : (
          scans.map((scan) => {
            const cfg = getThreatLevelConfig(scan.threat_level as ThreatLevel);
            return (
              <div
                key={scan.id}
                className={`p-4 rounded-xl border space-y-3 shadow-xs transition-colors ${
                  isDark ? "bg-[#0E1726] border-slate-800" : "bg-white border-slate-200"
                }`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="space-y-0.5 flex-1 min-w-0">
                    <h3 className={`font-bold text-sm truncate ${isDark ? "text-white" : "text-slate-900"}`}>
                      {scan.subject}
                    </h3>
                    <p className={`text-xs font-mono truncate ${isDark ? "text-slate-400" : "text-slate-600"}`}>
                      {scan.sender}
                    </p>
                  </div>
                  <span className={`px-2 py-0.5 rounded font-mono font-bold text-[10px] border shrink-0 ${cfg.badgeBg}`}>
                    {scan.threat_level}
                  </span>
                </div>

                <div className="flex items-center justify-between pt-2 border-t border-slate-800/60 text-xs font-mono">
                  <span className={isDark ? "text-slate-400" : "text-slate-600"}>
                    Score: <strong>{scan.risk_score}%</strong>
                  </span>
                  <span className={isDark ? "text-slate-400 text-[11px]" : "text-slate-600 text-[11px]"}>
                    {formatIST(scan.created_at)}
                  </span>
                </div>

                <button
                  onClick={() => viewDetail(scan.id)}
                  className={`w-full py-2 px-3 rounded-lg text-xs font-mono font-bold flex items-center justify-center gap-2 border cursor-pointer ${
                    isDark
                      ? "bg-cyan-950/60 text-cyan-300 border-cyan-700/60 hover:bg-cyan-900/80"
                      : "bg-sky-50 text-sky-800 border-sky-300 hover:bg-sky-100"
                  }`}
                >
                  <Eye className="w-4 h-4" />
                  <span>Inspect Forensic Telemetry</span>
                </button>
              </div>
            );
          })
        )}
      </div>

      {/* Forensic Inspection Modal */}
      {selectedScan && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-xs flex items-center justify-center p-3 sm:p-5">
          <div
            className={`border rounded-2xl max-w-4xl w-full max-h-[90vh] overflow-y-auto p-5 sm:p-7 space-y-6 shadow-2xl transition-colors animate-page-enter ${
              isDark
                ? "bg-[#0E1726] border-cyan-500/30 text-slate-100"
                : "bg-white border-slate-300 text-slate-900"
            }`}
          >
            {/* Modal Top Header */}
            <div className={`flex items-start justify-between pb-4 border-b ${isDark ? "border-slate-800" : "border-slate-200"}`}>
              <div className="space-y-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <span
                    className={`text-xs font-mono uppercase tracking-wider font-bold ${
                      isDark ? "text-cyan-400" : "text-sky-700 font-extrabold"
                    }`}
                  >
                    Forensic Scan Investigation
                  </span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                    ID: {selectedScan.id.substring(0, 8)}...
                  </span>
                  <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                    isDark ? "bg-cyan-950/60 text-cyan-300 border-cyan-800/60" : "bg-sky-50 text-sky-800 border-sky-300 font-semibold"
                  }`}>
                    Scanned: {formatIST(selectedScan.created_at)}
                  </span>
                </div>
                <h3 className={`text-lg sm:text-xl font-bold ${isDark ? "text-white" : "text-slate-900 font-extrabold"}`}>
                  {selectedScan.subject}
                </h3>
              </div>
              <button
                onClick={() => setSelectedScan(null)}
                aria-label="Close Forensic Inspector"
                className={`p-2 rounded-xl cursor-pointer transition-colors border ${
                  isDark
                    ? "bg-slate-900 border-slate-700 text-slate-400 hover:text-white hover:border-slate-500"
                    : "bg-slate-100 border-slate-300 text-slate-600 hover:text-slate-900 hover:border-slate-400"
                }`}
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Quick Metrics Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
              <div className={`p-3.5 rounded-xl border ${isDark ? "bg-slate-900/80 border-slate-800" : "bg-slate-50 border-slate-200"}`}>
                <span className={`block text-[11px] ${isDark ? "text-slate-400" : "text-slate-500"}`}>Sender</span>
                <span className={`truncate block font-semibold text-sm ${isDark ? "text-slate-200" : "text-slate-800"}`}>
                  {selectedScan.sender}
                </span>
              </div>
              <div className={`p-3.5 rounded-xl border ${isDark ? "bg-slate-900/80 border-slate-800" : "bg-slate-50 border-slate-200"}`}>
                <span className={`block text-[11px] ${isDark ? "text-slate-400" : "text-slate-500"}`}>Threat Level</span>
                <span
                  className={`inline-block mt-0.5 font-bold px-2 py-0.5 rounded border text-xs ${
                    getThreatLevelConfig(selectedScan.threat_level).badgeBg
                  }`}
                >
                  {selectedScan.threat_level}
                </span>
              </div>
              <div className={`p-3.5 rounded-xl border ${isDark ? "bg-slate-900/80 border-slate-800" : "bg-slate-50 border-slate-200"}`}>
                <span className={`block text-[11px] ${isDark ? "text-slate-400" : "text-slate-500"}`}>Risk Score</span>
                <span className={`font-bold text-lg ${isDark ? "text-cyan-300" : "text-sky-700"}`}>
                  {selectedScan.risk_score} / 100
                </span>
              </div>
            </div>

            {/* ML & Heuristics Breakdown */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {/* ML Scores */}
              <div
                className={`p-4 rounded-xl border space-y-2.5 ${
                  isDark ? "bg-slate-900/60 border-slate-800" : "bg-slate-50 border-slate-200"
                }`}
              >
                <span className={`text-xs font-mono uppercase font-bold tracking-wider ${isDark ? "text-purple-400" : "text-purple-700"}`}>
                  Machine Learning Analysis
                </span>
                <div className="space-y-2 text-xs font-mono">
                  <div className="flex items-center justify-between">
                    <span className={isDark ? "text-slate-300" : "text-slate-700"}>Spam Probability:</span>
                    <span className="font-bold">{(selectedScan.spam_probability * 100).toFixed(1)}%</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className={isDark ? "text-slate-300" : "text-slate-700"}>Phishing Probability:</span>
                    <span className="font-bold">{(selectedScan.phishing_probability * 100).toFixed(1)}%</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className={isDark ? "text-slate-300" : "text-slate-700"}>URL Risk Score:</span>
                    <span className="font-bold">{(selectedScan.url_risk_score * 100).toFixed(1)}%</span>
                  </div>
                </div>
              </div>

              {/* Header Authentication */}
              <div
                className={`p-4 rounded-xl border space-y-2.5 ${
                  isDark ? "bg-slate-900/60 border-slate-800" : "bg-slate-50 border-slate-200"
                }`}
              >
                <span className={`text-xs font-mono uppercase font-bold tracking-wider ${isDark ? "text-cyan-400" : "text-sky-700"}`}>
                  Header Authentication
                </span>
                <div className="space-y-2 text-xs font-mono">
                  <div className="flex items-center justify-between">
                    <span className={isDark ? "text-slate-300" : "text-slate-700"}>Transport Headers:</span>
                    <span className="font-bold">{selectedScan.has_headers ? "Provided" : "Not Provided"}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className={isDark ? "text-slate-300" : "text-slate-700"}>SPF Status:</span>
                    <span className="font-bold">{selectedScan.header_details?.spf_status || "not_evaluated"}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className={isDark ? "text-slate-300" : "text-slate-700"}>DKIM / DMARC:</span>
                    <span className="font-bold">{selectedScan.header_details?.dmarc_status || "not_evaluated"}</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Detected & Defanged URLs */}
            <div className="space-y-2.5">
              <span className={`text-xs font-mono uppercase tracking-wider block font-bold ${isDark ? "text-slate-300" : "text-slate-700"}`}>
                Detected & Defanged URLs ({selectedScan.detected_urls.length})
              </span>
              {selectedScan.detected_urls.length === 0 ? (
                <p className="text-xs text-slate-500 italic p-3 rounded-lg border border-dashed border-slate-800">
                  No embedded URLs detected in this email.
                </p>
              ) : (
                <div className="space-y-2 max-h-48 overflow-y-auto">
                  {selectedScan.detected_urls.map((u, idx) => (
                    <div
                      key={idx}
                      className={`p-3 rounded-lg border text-xs font-mono flex items-center justify-between flex-wrap gap-2 ${
                        isDark ? "bg-slate-900 border-slate-800" : "bg-slate-50 border-slate-200"
                      }`}
                    >
                      <code className={`font-semibold ${isDark ? "text-cyan-300" : "text-sky-700"}`}>
                        {u.defanged_url}
                      </code>
                      <div className="flex items-center gap-3 text-[11px]">
                        <span className={isDark ? "text-slate-400" : "text-slate-600"}>
                          Entropy: <strong>{u.entropy}</strong>
                        </span>
                        <span
                          className={`px-2 py-0.5 rounded font-bold ${
                            u.is_suspicious ? "bg-rose-950 text-rose-300 border border-rose-800" : "bg-emerald-950 text-emerald-300 border border-emerald-800"
                          }`}
                        >
                          {u.is_suspicious ? "SUSPICIOUS" : "LOW RISK"}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Recommendations */}
            {selectedScan.recommendations && selectedScan.recommendations.length > 0 && (
              <div
                className={`p-4 rounded-xl border space-y-2 ${
                  isDark ? "bg-slate-900/60 border-slate-800" : "bg-slate-50 border-slate-200"
                }`}
              >
                <span className={`text-xs font-mono uppercase font-bold tracking-wider ${isDark ? "text-emerald-400" : "text-emerald-700"}`}>
                  Defensive Action Plan
                </span>
                <ul className="space-y-1 text-xs">
                  {selectedScan.recommendations.map((rec, rIdx) => (
                    <li key={rIdx} className="flex items-start gap-2">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 mt-1.5 shrink-0" />
                      <span className={isDark ? "text-slate-300" : "text-slate-700 font-medium"}>{rec}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Bottom Modal Actions */}
            <div className={`pt-4 border-t flex items-center justify-between flex-wrap gap-3 ${isDark ? "border-slate-800" : "border-slate-200"}`}>
              <button
                onClick={() => handleExportScanJson(selectedScan)}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono flex items-center gap-1.5 border cursor-pointer ${
                  isDark
                    ? "bg-slate-900 hover:bg-slate-800 text-slate-300 border-slate-700"
                    : "bg-slate-100 hover:bg-slate-200 text-slate-800 border-slate-300"
                }`}
              >
                <Download className="w-3.5 h-3.5" />
                <span>Export JSON</span>
              </button>

              <button
                onClick={() => setSelectedScan(null)}
                className={`px-4 py-2 rounded-lg text-xs font-mono font-bold cursor-pointer border transition-colors ${
                  isDark
                    ? "bg-slate-800 hover:bg-slate-700 text-slate-200 border-slate-700"
                    : "bg-slate-100 hover:bg-slate-200 text-slate-900 border-slate-300 font-bold"
                }`}
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
