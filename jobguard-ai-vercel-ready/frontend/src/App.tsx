import React, { useState } from "react";
import { AnalysisForm } from "./components/AnalysisForm";
import { AnalysisResultView } from "./components/AnalysisResultView";
import { Dashboard } from "./components/Dashboard";
import { ExtractionReview } from "./components/ExtractionReview";
import { DEMO_SCENARIOS } from "./data/samples";
import {
  exportReportToMarkdown,
  extractStructuredJobData,
  runLocalVerification,
} from "./engine/localEngine.mjs";
import type { ExtractedJobData, VerificationReport } from "./types";

export const App: React.FC = () => {
  const [view, setView] = useState<"dashboard" | "verify" | "review" | "report">("dashboard");
  const [text, setText] = useState("");
  const [secondaryText, setSecondaryText] = useState("");
  const [jobUrl, setJobUrl] = useState("");
  const [isDemo, setIsDemo] = useState(false);
  const [extracted, setExtracted] = useState<ExtractedJobData | null>(null);
  const [edits, setEdits] = useState<Record<string, string>>({});
  const [currentReport, setCurrentReport] = useState<VerificationReport | null>(null);
  const [history, setHistory] = useState<VerificationReport[]>([]);
  const [loading, setLoading] = useState(false);

  const handleExtract = async () => {
    setLoading(true);
    try {
      const resp = await fetch("/api/extract", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text, job_url: jobUrl || null }),
      });
      const data = resp.ok ? await resp.json() : extractStructuredJobData(text, jobUrl);
      setExtracted(data);
      setEdits({});
      setView("review");
    } catch {
      setExtracted(extractStructuredJobData(text, jobUrl) as ExtractedJobData);
      setEdits({});
      setView("review");
    } finally {
      setLoading(false);
    }
  };

  const handleVerify = async () => {
    setLoading(true);
    try {
      const resp = await fetch("/api/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          text,
          secondary_text: secondaryText || null,
          job_url: jobUrl || null,
          edited_fields: edits,
          is_demo: isDemo,
        }),
      });
      const rep: VerificationReport = resp.ok
        ? await resp.json()
        : (runLocalVerification({ text, secondaryText, jobUrl, editedFields: edits, isDemo }) as VerificationReport);
      setCurrentReport(rep);
      setHistory((prev) => [rep, ...prev]);
      setView("report");
    } catch {
      const rep = runLocalVerification({ text, secondaryText, jobUrl, editedFields: edits, isDemo }) as VerificationReport;
      setCurrentReport(rep);
      setHistory((prev) => [rep, ...prev]);
      setView("report");
    } finally {
      setLoading(false);
    }
  };

  const handleLoadDemo = (id: string) => {
    const sc = DEMO_SCENARIOS.find((s) => s.id === id);
    if (!sc) return;
    setText(sc.text);
    setSecondaryText(sc.secondaryText || "");
    setJobUrl(sc.jobUrl || "");
    setIsDemo(true);
  };

  const downloadFile = (content: string, filename: string, mime: string) => {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="min-h-screen bg-[#F4F7FB] dark:bg-[#081120] text-slate-900 dark:text-slate-100 p-6">
      <div className="max-w-6xl mx-auto space-y-6">
        {view === "dashboard" && (
          <Dashboard
            history={history}
            onStartVerify={() => setView("verify")}
            onOpenReport={(id) => {
              const found = history.find((h) => h.report_id === id);
              if (found) {
                setCurrentReport(found);
                setView("report");
              }
            }}
          />
        )}
        {view === "verify" && (
          <AnalysisForm
            text={text}
            secondaryText={secondaryText}
            jobUrl={jobUrl}
            onTextChange={(v) => { setText(v); setIsDemo(false); }}
            onSecondaryTextChange={setSecondaryText}
            onJobUrlChange={setJobUrl}
            onExtract={handleExtract}
            onLoadDemo={handleLoadDemo}
            isLoading={loading}
          />
        )}
        {view === "review" && extracted && (
          <ExtractionReview
            extracted={extracted}
            edits={edits}
            onEditChange={(k, v) => setEdits((prev) => ({ ...prev, [k]: v }))}
            onConfirmVerify={handleVerify}
            onBack={() => setView("verify")}
            isVerifying={loading}
          />
        )}
        {view === "report" && currentReport && (
          <AnalysisResultView
            report={currentReport}
            onExportMarkdown={() =>
              downloadFile(exportReportToMarkdown(currentReport), `${currentReport.report_id}.md`, "text/markdown")
            }
            onExportJson={() =>
              downloadFile(JSON.stringify(currentReport, null, 2), `${currentReport.report_id}.json`, "application/json")
            }
            onNewVerification={() => setView("verify")}
          />
        )}
      </div>
    </div>
  );
};

export default App;
