import React from "react";
import type { VerificationReport } from "../types";
import { EvidenceCategoryCard } from "./EvidenceCategoryCard";

interface Props {
  report: VerificationReport;
  onExportMarkdown: () => void;
  onExportJson: () => void;
  onNewVerification: () => void;
}

export const AnalysisResultView: React.FC<Props> = ({
  report,
  onExportMarkdown,
  onExportJson,
  onNewVerification,
}) => {
  const riskColors =
    report.risk_level === "HIGH RISK"
      ? "bg-red-50 dark:bg-red-950/40 border-red-300 dark:border-red-800 text-red-950 dark:text-red-100"
      : report.risk_level === "MEDIUM RISK"
      ? "bg-amber-50 dark:bg-amber-950/40 border-amber-300 dark:border-amber-800 text-amber-950 dark:text-amber-100"
      : "bg-emerald-50 dark:bg-emerald-950/40 border-emerald-300 dark:border-emerald-800 text-emerald-950 dark:text-emerald-100";

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <button
          type="button"
          onClick={onNewVerification}
          className="px-4 py-2 rounded-xl text-xs font-bold bg-white dark:bg-[#111F36] border border-slate-200 dark:border-slate-700"
        >
          ← New Verification
        </button>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={onExportMarkdown}
            className="px-3.5 py-2 rounded-xl text-xs font-semibold bg-white dark:bg-[#111F36] border border-slate-200 dark:border-slate-700"
          >
            ⬇ Export Markdown
          </button>
          <button
            type="button"
            onClick={onExportJson}
            className="px-3.5 py-2 rounded-xl text-xs font-semibold bg-white dark:bg-[#111F36] border border-slate-200 dark:border-slate-700"
          >
            ⬇ Export JSON
          </button>
        </div>
      </div>

      <div className={`rounded-2xl p-6 border-2 ${riskColors} space-y-4`}>
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="space-y-2 flex-1 min-w-[260px]">
            <div className="flex flex-wrap items-center gap-2">
              <span className="px-3 py-1 rounded-lg text-xs font-extrabold uppercase bg-slate-900 text-white">
                {report.risk_level}
              </span>
              {report.is_demo && (
                <span className="px-2.5 py-1 rounded-lg text-xs font-bold bg-indigo-600 text-white">
                  SYNTHETIC DEMO SCENARIO
                </span>
              )}
              <span className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-white/80 dark:bg-slate-900/80 text-slate-800 dark:text-slate-200">
                Coverage: {report.evidence_coverage_percent}%
              </span>
            </div>
            <h1 className="text-xl font-extrabold">{report.risk_headline}</h1>
            <p className="text-xs opacity-90">{report.risk_index_disclaimer}</p>
          </div>
          <div className="bg-white/95 dark:bg-slate-900/95 px-6 py-4 rounded-2xl border border-slate-200 dark:border-slate-800 text-center min-w-[160px]">
            <div className="text-[10px] font-bold uppercase text-slate-500">Heuristic Risk Index</div>
            <div className="text-4xl font-extrabold text-slate-900 dark:text-white mt-1">
              {report.risk_index}
              <span className="text-sm text-slate-400">/100</span>
            </div>
            <div className="text-[11px] text-slate-500 mt-1">{report.verification_confidence}</div>
          </div>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2 text-xs">
          <div className="p-3 rounded-xl bg-white/80 dark:bg-slate-900/70">
            <div className="text-slate-500">Suspicious Indicators</div>
            <div className="text-lg font-extrabold text-red-600">{report.suspicious_indicator_count}</div>
          </div>
          <div className="p-3 rounded-xl bg-white/80 dark:bg-slate-900/70">
            <div className="text-slate-500">Confirmed Checks</div>
            <div className="text-lg font-extrabold text-emerald-600">{report.confirmed_check_count}</div>
          </div>
          <div className="p-3 rounded-xl bg-white/80 dark:bg-slate-900/70">
            <div className="text-slate-500">Unverified Checks</div>
            <div className="text-lg font-extrabold text-amber-600">{report.unverified_check_count}</div>
          </div>
          <div className="p-3 rounded-xl bg-white/80 dark:bg-slate-900/70">
            <div className="text-slate-500">Checks Unavailable</div>
            <div className="text-lg font-extrabold text-slate-600">{report.unavailable_check_count}</div>
          </div>
        </div>
      </div>

      <div className="space-y-3">
        <h2 className="text-lg font-extrabold text-slate-900 dark:text-white">
          Seven-Category Evidence-Based Verification Report
        </h2>
        {report.categories.map((cat) => (
          <EvidenceCategoryCard key={cat.category_id} category={cat} />
        ))}
      </div>

      <div className="rounded-2xl bg-white dark:bg-[#111F36] border border-slate-200 dark:border-slate-700 p-6 space-y-3">
        <h2 className="text-base font-bold text-slate-900 dark:text-white">Recommended Next Actions</h2>
        <ul className="space-y-2 text-xs text-slate-700 dark:text-slate-200">
          {report.recommended_actions.map((act, i) => (
            <li key={i} className="p-3 rounded-xl bg-[#F4F7FB] dark:bg-slate-900/70 border border-slate-200 dark:border-slate-800">
              {i + 1}. {act}
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
};
