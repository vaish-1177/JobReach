import React from "react";
import type { ExtractedJobData } from "../types";

const FIELD_ORDER: Array<{ key: keyof ExtractedJobData; label: string }> = [
  { key: "employer", label: "1. Employer / Company" },
  { key: "role", label: "2. Job Title / Role" },
  { key: "salary", label: "3. Salary / Compensation" },
  { key: "recruiter_email", label: "4. Recruiter Email" },
  { key: "phone", label: "5. Phone Number" },
  { key: "location", label: "6. Job Location" },
  { key: "job_url", label: "7. Job / Application URL" },
  { key: "requisition_id", label: "8. Requisition / Job ID" },
  { key: "payment_requests", label: "9. Payment Requests" },
  { key: "deadlines", label: "10. Deadlines" },
];

interface Props {
  extracted: ExtractedJobData;
  edits: Record<string, string>;
  onEditChange: (field: string, value: string) => void;
  onConfirmVerify: () => void;
  onBack: () => void;
  isVerifying: boolean;
}

export const ExtractionReview: React.FC<Props> = ({
  extracted,
  edits,
  onEditChange,
  onConfirmVerify,
  onBack,
  isVerifying,
}) => {
  return (
    <div className="rounded-2xl bg-white dark:bg-[#111F36] border border-slate-200 dark:border-slate-700 p-6 space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <span className="text-xs font-extrabold uppercase tracking-wider text-[#167D82] dark:text-teal-300">
            Pre-Analysis Extraction Review
          </span>
          <h2 className="text-xl font-extrabold text-slate-900 dark:text-white mt-1">
            Review & Correct the 10 Extracted Fields
          </h2>
          <p className="text-xs text-slate-600 dark:text-slate-300 mt-1">
            Missing fields remain explicitly marked as missing and are never invented. Edit any field before running full 7-category verification.
          </p>
        </div>
        <button
          type="button"
          onClick={onBack}
          className="px-3.5 py-2 rounded-xl text-xs font-semibold bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-200"
        >
          ← Edit Source Input
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {FIELD_ORDER.map(({ key, label }) => {
          const field = extracted[key] as {
            value: string | null;
            status: "extracted" | "missing";
            confidence: number;
            supporting_snippet: string | null;
          };
          const currentVal = edits[key] !== undefined ? edits[key] : field.value || "";
          const isMissing = !currentVal.trim();
          return (
            <div
              key={key}
              className="p-4 rounded-xl bg-[#F4F7FB] dark:bg-slate-900/70 border border-slate-200 dark:border-slate-800 space-y-2"
            >
              <div className="flex items-center justify-between gap-2">
                <label className="text-xs font-bold text-slate-800 dark:text-slate-100">{label}</label>
                {isMissing ? (
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-amber-100 text-amber-800 dark:bg-amber-950/70 dark:text-amber-300">
                    Missing
                  </span>
                ) : (
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-100 text-emerald-800 dark:bg-emerald-950/70 dark:text-emerald-300">
                    {Math.round((field.confidence || 1) * 100)}% conf.
                  </span>
                )}
              </div>
              <input
                type="text"
                value={currentVal}
                onChange={(e) => onEditChange(key, e.target.value)}
                placeholder="Explicitly missing — leave blank or enter value"
                className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2 text-xs text-slate-900 dark:text-white font-mono"
              />
              {field.supporting_snippet && (
                <div className="text-[11px] text-slate-500 dark:text-slate-400 font-mono truncate" title={field.supporting_snippet}>
                  Snippet: "{field.supporting_snippet}"
                </div>
              )}
            </div>
          );
        })}
      </div>

      <div className="flex justify-end gap-3 pt-2">
        <button
          type="button"
          disabled={isVerifying}
          onClick={onConfirmVerify}
          className="px-6 py-3 rounded-xl font-bold text-sm bg-[#167D82] hover:bg-[#12686D] text-white shadow-sm transition disabled:opacity-50"
        >
          {isVerifying ? "Running 7-Category Verification..." : "Confirm Fields & Run Verification →"}
        </button>
      </div>
    </div>
  );
};
