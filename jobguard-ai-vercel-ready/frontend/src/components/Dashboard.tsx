import React from "react";
import type { VerificationReport } from "../types";

interface Props {
  history: VerificationReport[];
  onStartVerify: () => void;
  onOpenReport: (reportId: string) => void;
}

export const Dashboard: React.FC<Props> = ({ history, onStartVerify, onOpenReport }) => {
  const high = history.filter((r) => r.risk_level === "HIGH RISK").length;
  const med = history.filter((r) => r.risk_level === "MEDIUM RISK").length;
  const low = history.filter((r) => r.risk_level === "LOW RISK").length;

  return (
    <div className="space-y-6">
      <div className="rounded-2xl bg-[#091426] text-white p-6 flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="text-xs font-bold uppercase tracking-wider text-teal-300">JobGuard AI Dashboard</div>
          <h1 className="text-2xl font-extrabold mt-1">Before You Trust the Offer, Verify the Evidence.</h1>
          <p className="text-xs text-slate-300 mt-1">
            All analytics below reflect only your real local verification records — never fabricated activity.
          </p>
        </div>
        <button
          type="button"
          onClick={onStartVerify}
          className="px-5 py-2.5 rounded-xl font-bold text-sm bg-[#167D82] hover:bg-[#1A9399] text-white"
        >
          + Start New Verification
        </button>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 rounded-2xl bg-white dark:bg-[#111F36] border border-slate-200 dark:border-slate-700">
          <div className="text-xs text-slate-500">Total Verifications</div>
          <div className="text-2xl font-extrabold mt-1">{history.length}</div>
        </div>
        <div className="p-4 rounded-2xl bg-red-50/70 dark:bg-red-950/30 border border-red-200 dark:border-red-900">
          <div className="text-xs text-red-700 dark:text-red-300">High-Risk Opportunities</div>
          <div className="text-2xl font-extrabold text-red-600 mt-1">{high}</div>
        </div>
        <div className="p-4 rounded-2xl bg-amber-50/70 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-900">
          <div className="text-xs text-amber-800 dark:text-amber-300">Medium-Risk / Unverified</div>
          <div className="text-2xl font-extrabold text-amber-600 mt-1">{med}</div>
        </div>
        <div className="p-4 rounded-2xl bg-emerald-50/70 dark:bg-emerald-950/30 border border-emerald-200 dark:border-emerald-900">
          <div className="text-xs text-emerald-800 dark:text-emerald-300">Low-Risk Opportunities</div>
          <div className="text-2xl font-extrabold text-emerald-600 mt-1">{low}</div>
        </div>
      </div>

      <div className="rounded-2xl bg-white dark:bg-[#111F36] border border-slate-200 dark:border-slate-700 p-6 space-y-3">
        <h2 className="text-base font-bold">Recently Analyzed Jobs</h2>
        {history.length === 0 ? (
          <p className="text-xs text-slate-500">No verifications recorded yet. Submit a job ad or run a labeled demo scenario.</p>
        ) : (
          <div className="space-y-2">
            {history.slice(0, 6).map((item) => (
              <div
                key={item.report_id}
                className="p-3.5 rounded-xl bg-[#F4F7FB] dark:bg-slate-900/70 border border-slate-200 dark:border-slate-800 flex items-center justify-between gap-3"
              >
                <div className="min-w-0">
                  <div className="text-xs font-bold">
                    {item.extracted_data.employer.value || "Unidentified Employer"} —{" "}
                    {item.extracted_data.role.value || "Role Unspecified"}
                  </div>
                  <div className="text-[11px] text-slate-500">
                    {item.risk_level} ({item.risk_index}/100) • Coverage {item.evidence_coverage_percent}%
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => onOpenReport(item.report_id)}
                  className="px-3 py-1.5 rounded-lg text-xs font-bold bg-[#167D82] text-white shrink-0"
                >
                  Open Report
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
