import React, { useEffect, useState } from "react";
import { Binary, Database, ShieldCheck } from "lucide-react";
import { api } from "../api/client";
import { useTheme } from "../context/ThemeContext";
import type { ModelBenchmarksResponse } from "../types";
import { formatIST } from "../utils/dateFormatter";

export const ModelHubPage: React.FC = () => {
  const { isDark } = useTheme();
  const [data, setData] = useState<ModelBenchmarksResponse | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getModelBenchmarks()
      .then(setData)
      .catch((err) => console.error("Error loading model benchmarks:", err))
      .finally(() => setLoading(false));
  }, []);

  if (loading || !data) {
    return (
      <div className={`flex flex-col items-center justify-center min-h-[300px] space-y-3 ${isDark ? "text-slate-400" : "text-slate-600"}`}>
        <div className="w-8 h-8 border-2 border-cyan-500/20 border-t-cyan-500 rounded-full animate-spin"></div>
        <span className="text-xs font-mono">Loading Machine Learning Benchmarks...</span>
      </div>
    );
  }

  const renderConfusionMatrix = (cm?: { true_negatives: number; false_positives: number; false_negatives: number; true_positives: number }) => {
    if (!cm) return null;
    return (
      <div className="space-y-2">
        <span className={`text-[11px] font-mono block uppercase tracking-wider ${isDark ? "text-[#CBD5E1] font-semibold" : "text-slate-600 font-semibold"}`}>
          Evaluation Confusion Matrix (Test Split)
        </span>
        <div className="grid grid-cols-2 gap-2 text-center text-xs font-mono">
          <div
            className={`p-3 rounded-lg border ${
              isDark
                ? "bg-[#174B3C] border-[#226752]"
                : "bg-emerald-50 border-emerald-200 text-emerald-800"
            }`}
          >
            <span className={`font-bold block text-sm ${isDark ? "text-[#86EFAC]" : "text-emerald-950"}`}>{cm.true_negatives}</span>
            <span className={`text-[10px] ${isDark ? "text-[#CBD5E1]" : "text-slate-600"}`}>True Negatives (Clean)</span>
          </div>
          <div
            className={`p-3 rounded-lg border ${
              isDark
                ? "bg-[#59401F] border-[#7E5B2D]"
                : "bg-amber-50 border-amber-200 text-amber-800"
            }`}
          >
            <span className={`font-bold block text-sm ${isDark ? "text-[#FCD34D]" : "text-amber-950"}`}>{cm.false_positives}</span>
            <span className={`text-[10px] ${isDark ? "text-[#CBD5E1]" : "text-slate-600"}`}>False Positives (Type I)</span>
          </div>
          <div
            className={`p-3 rounded-lg border ${
              isDark
                ? "bg-[#542B3A] border-[#773D52]"
                : "bg-rose-50 border-rose-200 text-rose-800"
            }`}
          >
            <span className={`font-bold block text-sm ${isDark ? "text-[#FDA4AF]" : "text-rose-950"}`}>{cm.false_negatives}</span>
            <span className={`text-[10px] ${isDark ? "text-[#CBD5E1]" : "text-slate-600"}`}>False Negatives (Type II)</span>
          </div>
          <div
            className={`p-3 rounded-lg border ${
              isDark
                ? "bg-[#193F60] border-[#255A88]"
                : "bg-sky-50 border-sky-200 text-sky-800"
            }`}
          >
            <span className={`font-bold block text-sm ${isDark ? "text-[#7DD3FC]" : "text-sky-950"}`}>{cm.true_positives}</span>
            <span className={`text-[10px] ${isDark ? "text-[#CBD5E1]" : "text-slate-600"}`}>True Positives (Caught)</span>
          </div>
        </div>
      </div>
    );
  };

  return (
    <div className="space-y-8">
      {/* Title */}
      <div>
        <h1
          className={`text-2xl font-bold flex items-center gap-2 ${
            isDark ? "text-white" : "text-slate-900 font-extrabold"
          }`}
        >
          <Binary className={`w-7 h-7 ${isDark ? "text-cyan-400" : "text-sky-600"}`} />
          Machine Learning Model Evaluation Lab
        </h1>
        <p className={`text-sm ${isDark ? "text-slate-400" : "text-slate-600"}`}>
          Independent evaluation metrics, cross-model comparison, and confusion matrices.
        </p>
      </div>

      {/* Dataset Attribution Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Primary Spam Dataset Card (Blue Theme) */}
        <div
          className={`dataset-card-blue p-5 rounded-xl border space-y-2.5 overflow-hidden ${
            isDark
              ? "bg-[#101D35] border-[#263F68]"
              : "bg-[#EFF6FF] border-[#BFDBFE] shadow-xs"
          }`}
        >
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <Database className={`w-4 h-4 shrink-0 ${isDark ? "text-[#60A5FA]" : "text-[#1D4ED8]"}`} />
              <span
                className={`text-xs font-mono font-bold uppercase tracking-wider ${
                  isDark ? "text-[#60A5FA]" : "text-[#1D4ED8]"
                }`}
              >
                Primary Spam Dataset
              </span>
            </div>
            <span
              className={`text-[10px] px-2 py-0.5 rounded font-mono font-medium border ${
                isDark
                  ? "bg-blue-950/80 text-blue-300 border-blue-800/60"
                  : "bg-blue-100 text-blue-800 border-blue-200"
              }`}
            >
              bvk/ENRON-spam
            </span>
          </div>
          <p className={`text-xs leading-relaxed ${isDark ? "text-slate-300" : "text-slate-700 font-medium"}`}>
            Enron corporate email corpus with verified spam and ham classifications. Stratified split (70% Train, 15% Val, 15% Test).
          </p>
        </div>

        {/* Secondary Phishing Dataset Card (Purple Theme) */}
        <div
          className={`dataset-card-purple p-5 rounded-xl border space-y-2.5 overflow-hidden ${
            isDark
              ? "bg-[#251638] border-[#493064]"
              : "bg-[#F5F0FF] border-[#DDD6FE] shadow-xs"
          }`}
        >
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <ShieldCheck className={`w-4 h-4 shrink-0 ${isDark ? "text-[#C084FC]" : "text-[#7C3AED]"}`} />
              <span
                className={`text-xs font-mono font-bold uppercase tracking-wider ${
                  isDark ? "text-[#C084FC]" : "text-[#7C3AED]"
                }`}
              >
                Secondary Phishing Dataset
              </span>
            </div>
            <span
              className={`text-[10px] px-2 py-0.5 rounded font-mono font-medium border ${
                isDark
                  ? "bg-purple-950/80 text-purple-300 border-purple-800/60"
                  : "bg-purple-100 text-purple-800 border-purple-200"
              }`}
            >
              zefang-liu/phishing-email-dataset
            </span>
          </div>
          <p className={`text-xs leading-relaxed ${isDark ? "text-slate-300" : "text-slate-700 font-medium"}`}>
            Specialized phishing corpus containing credential harvesting and spoofing attacks. Kept strictly separate from the spam dataset.
          </p>
        </div>
      </div>

      {/* Model Benchmark Cards */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {Object.entries(data.models).map(([key, model], idx) => (
          <div
            key={idx}
            className={`model-card-glow p-6 rounded-xl border space-y-5 shadow-xl flex flex-col justify-between overflow-hidden ${
              isDark ? "bg-[#172B43] border-[#334E68]" : "bg-white border-slate-200 shadow-sm"
            }`}
          >
            <div className="space-y-3">
              <div>
                <span
                  className={`text-[10px] px-2 py-0.5 rounded font-mono font-bold uppercase tracking-wider border ${
                    isDark
                      ? "bg-[#1E3550] text-[#CBD5E1] border-[#334E68]"
                      : "bg-slate-100 text-slate-700 border-slate-200"
                  }`}
                >
                  {key.includes("spam") ? "Spam Classification" : "Phishing Classification"}
                </span>
                <h3 className={`text-lg font-bold mt-1.5 ${isDark ? "text-[#F1F5F9]" : "text-slate-900"}`}>
                  {model.model_name || key.replace(/_/g, " ").toUpperCase()}
                </h3>
              </div>

              {/* Metrics Grid */}
              <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                <div
                  className={`p-2.5 rounded border ${
                    isDark ? "bg-[#233D59] border-[#334E68]" : "bg-slate-50 border-slate-200"
                  }`}
                >
                  <span className={`block text-[10px] ${isDark ? "text-[#CBD5E1]" : "text-slate-600"}`}>Accuracy</span>
                  <span className={`font-bold text-base ${isDark ? "text-[#38BDF8]" : "text-sky-700"}`}>
                    {(model.accuracy * 100).toFixed(2)}%
                  </span>
                </div>
                <div
                  className={`p-2.5 rounded border ${
                    isDark ? "bg-[#233D59] border-[#334E68]" : "bg-slate-50 border-slate-200"
                  }`}
                >
                  <span className={`block text-[10px] ${isDark ? "text-[#CBD5E1]" : "text-slate-600"}`}>F1 Score</span>
                  <span className={`font-bold text-base ${isDark ? "text-[#C084FC]" : "text-purple-700"}`}>
                    {(model.f1_score * 100).toFixed(2)}%
                  </span>
                </div>
                <div
                  className={`p-2.5 rounded border ${
                    isDark ? "bg-[#233D59] border-[#334E68]" : "bg-slate-50 border-slate-200"
                  }`}
                >
                  <span className={`block text-[10px] ${isDark ? "text-[#CBD5E1]" : "text-slate-600"}`}>Precision</span>
                  <span className={`font-bold text-base ${isDark ? "text-[#4ADE80]" : "text-emerald-700"}`}>
                    {(model.precision * 100).toFixed(2)}%
                  </span>
                </div>
                <div
                  className={`p-2.5 rounded border ${
                    isDark ? "bg-[#233D59] border-[#334E68]" : "bg-slate-50 border-slate-200"
                  }`}
                >
                  <span className={`block text-[10px] ${isDark ? "text-[#CBD5E1]" : "text-slate-600"}`}>Recall</span>
                  <span className={`font-bold text-base ${isDark ? "text-[#60A5FA]" : "text-indigo-700"}`}>
                    {(model.recall * 100).toFixed(2)}%
                  </span>
                </div>
              </div>

              {/* Confusion Matrix */}
              {renderConfusionMatrix(model.confusion_matrix)}
            </div>

            <div className={`pt-3 border-t text-[11px] font-mono flex items-center justify-between flex-wrap gap-2 ${isDark ? "border-[#334E68] text-[#CBD5E1]" : "border-slate-200 text-slate-500"}`}>
              <span>Persisted artifact: .joblib</span>
              {model.evaluated_at && (
                <span className={isDark ? "text-[#60A5FA]" : "text-sky-700"}>Evaluated: {formatIST(model.evaluated_at)}</span>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
