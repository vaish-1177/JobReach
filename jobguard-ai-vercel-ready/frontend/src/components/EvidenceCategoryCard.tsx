import React, { useState } from "react";
import type { EvidenceCategoryReport, EvidenceStatus } from "../types";

const STATUS_BADGE: Record<EvidenceStatus, string> = {
  "Confirmed by Source": "bg-emerald-100 text-emerald-800 border-emerald-300 dark:bg-emerald-950/60 dark:text-emerald-200 dark:border-emerald-800",
  "Inconsistent": "bg-orange-100 text-orange-800 border-orange-300 dark:bg-orange-950/60 dark:text-orange-200 dark:border-orange-800",
  "Suspicious Signal": "bg-red-100 text-red-800 border-red-300 dark:bg-red-950/60 dark:text-red-200 dark:border-red-800",
  "Unverified": "bg-amber-100 text-amber-800 border-amber-300 dark:bg-amber-950/60 dark:text-amber-200 dark:border-amber-800",
  "Check Unavailable": "bg-slate-100 text-slate-700 border-slate-300 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700",
};

interface Props {
  category: EvidenceCategoryReport;
}

export const EvidenceCategoryCard: React.FC<Props> = ({ category }) => {
  const [expanded, setExpanded] = useState(
    category.overall_status === "Suspicious Signal" || category.overall_status === "Inconsistent"
  );

  return (
    <div className="rounded-2xl bg-white dark:bg-[#111F36] border border-slate-200 dark:border-slate-700 shadow-sm overflow-hidden">
      <button
        type="button"
        onClick={() => setExpanded((e) => !e)}
        className="w-full p-5 flex items-center justify-between gap-4 text-left hover:bg-slate-50 dark:hover:bg-slate-800/40 transition"
      >
        <div className="space-y-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs font-extrabold uppercase tracking-wider text-[#167D82] dark:text-teal-300">
              Category {category.category_number}
            </span>
            <span className={`px-2.5 py-0.5 rounded-full text-[11px] font-bold border ${STATUS_BADGE[category.overall_status]}`}>
              {category.overall_status}
            </span>
          </div>
          <h3 className="text-base font-bold text-slate-900 dark:text-white">{category.category_name}</h3>
          <p className="text-xs text-slate-600 dark:text-slate-300">{category.summary}</p>
        </div>
        <span className="text-xs font-semibold text-slate-500 shrink-0">
          {expanded ? "Hide Details ▲" : `Inspect (${category.records.length}) ▼`}
        </span>
      </button>

      {expanded && (
        <div className="px-5 pb-5 pt-2 border-t border-slate-200 dark:border-slate-800 space-y-3">
          {category.records.map((rec, idx) => (
            <div
              key={`${category.category_id}-${idx}`}
              className="p-4 rounded-xl bg-[#F4F7FB] dark:bg-slate-900/70 border border-slate-200 dark:border-slate-800 space-y-2 text-xs"
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-bold text-slate-900 dark:text-white">{rec.check_name}</span>
                <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold border ${STATUS_BADGE[rec.status]}`}>
                  {rec.status}
                </span>
              </div>
              <div className="text-slate-600 dark:text-slate-300">
                <strong>Source Examined:</strong> {rec.source_examined} ({rec.source_type.replace(/_/g, " ")})
              </div>
              <div className="text-slate-800 dark:text-slate-100">
                <strong>Observed Result:</strong> {rec.observed_result}
              </div>
              {rec.supporting_quotation && (
                <blockquote className="p-2.5 rounded-lg bg-white dark:bg-slate-950 border-l-4 border-[#167D82] font-mono text-[11px] text-slate-700 dark:text-slate-200 break-all">
                  "{rec.supporting_quotation}"
                </blockquote>
              )}
              <p className="text-slate-600 dark:text-slate-300">{rec.explanation}</p>
              <div className="text-[11px] text-amber-800 dark:text-amber-300 bg-amber-50/70 dark:bg-amber-950/30 px-2.5 py-1.5 rounded-lg">
                <strong>Residual Uncertainty:</strong> {rec.residual_uncertainty}
              </div>
              <div className="text-[10px] text-slate-400 font-mono">Checked at: {rec.timestamp}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
