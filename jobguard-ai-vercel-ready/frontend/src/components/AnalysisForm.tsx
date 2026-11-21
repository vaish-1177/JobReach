import React from "react";
import { DEMO_SCENARIOS } from "../data/samples";

interface Props {
  text: string;
  secondaryText: string;
  jobUrl: string;
  onTextChange: (val: string) => void;
  onSecondaryTextChange: (val: string) => void;
  onJobUrlChange: (val: string) => void;
  onExtract: () => void;
  onLoadDemo: (id: string) => void;
  isLoading: boolean;
}

export const AnalysisForm: React.FC<Props> = ({
  text,
  secondaryText,
  jobUrl,
  onTextChange,
  onSecondaryTextChange,
  onJobUrlChange,
  onExtract,
  onLoadDemo,
  isLoading,
}) => {
  return (
    <div className="space-y-6">
      <div className="rounded-2xl bg-white dark:bg-[#111F36] border border-slate-200 dark:border-slate-700 p-6 space-y-4">
        <h2 className="text-base font-bold text-slate-900 dark:text-white">
          Submit Job Advertisement, Recruiter Message, or Offer Letter
        </h2>
        <textarea
          rows={6}
          value={text}
          onChange={(e) => onTextChange(e.target.value)}
          placeholder="Paste job ad, WhatsApp/Telegram message, LinkedIn description, email, or offer letter text (English, Hindi, or Hinglish)..."
          className="w-full rounded-xl border border-slate-300 dark:border-slate-700 bg-[#F4F7FB] dark:bg-slate-900 p-4 text-sm text-slate-900 dark:text-white"
        />

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-xs font-bold mb-1 text-slate-700 dark:text-slate-300">
              Job or Career Portal URL (Optional — Zero-Visit Structural Check)
            </label>
            <input
              type="text"
              value={jobUrl}
              onChange={(e) => onJobUrlChange(e.target.value)}
              placeholder="https://company.careers-example.xyz/apply"
              className="w-full rounded-xl border border-slate-300 dark:border-slate-700 bg-[#F4F7FB] dark:bg-slate-900 px-3.5 py-2.5 text-xs font-mono"
            />
          </div>
          <div>
            <label className="block text-xs font-bold mb-1 text-slate-700 dark:text-slate-300">
              Secondary Document for Consistency Check (Optional Offer Letter / Chat)
            </label>
            <input
              type="text"
              value={secondaryText}
              onChange={(e) => onSecondaryTextChange(e.target.value)}
              placeholder="Paste offer letter or second recruiter message to detect contradictions..."
              className="w-full rounded-xl border border-slate-300 dark:border-slate-700 bg-[#F4F7FB] dark:bg-slate-900 px-3.5 py-2.5 text-xs"
            />
          </div>
        </div>

        <div className="flex justify-end">
          <button
            type="button"
            disabled={isLoading}
            onClick={onExtract}
            className="px-6 py-3 rounded-xl font-bold text-sm bg-[#167D82] hover:bg-[#12686D] text-white shadow-sm transition disabled:opacity-50"
          >
            {isLoading ? "Extracting Structured Fields..." : "Extract & Review 10 Fields →"}
          </button>
        </div>
      </div>

      <div className="rounded-2xl bg-white dark:bg-[#111F36] border border-slate-200 dark:border-slate-700 p-6 space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-bold text-slate-900 dark:text-white">
            Synthetic Demonstration Scenarios (Clearly Labeled — Not Live Employer Verifications)
          </h3>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {DEMO_SCENARIOS.map((sc) => (
            <button
              key={sc.id}
              type="button"
              onClick={() => onLoadDemo(sc.id)}
              className="p-3.5 rounded-xl text-left bg-[#F4F7FB] dark:bg-slate-900/70 border border-slate-200 dark:border-slate-800 hover:border-[#167D82] transition"
            >
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-bold text-[#167D82] dark:text-teal-300">{sc.categoryHint}</span>
                <span className="text-[10px] uppercase px-2 py-0.5 rounded bg-slate-200 dark:bg-slate-800 font-semibold">
                  DEMO • {sc.lang}
                </span>
              </div>
              <div className="text-xs font-semibold text-slate-800 dark:text-slate-100 mt-1">{sc.label}</div>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
};
