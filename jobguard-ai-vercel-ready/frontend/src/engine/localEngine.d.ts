import type { ExtractedJobData, VerificationReport } from "../types";

export function extractStructuredJobData(
  text: string,
  jobUrl?: string | null
): ExtractedJobData;

export function runLocalVerification(input: {
  text?: string;
  secondary_text?: string;
  job_url?: string;
  edited_fields?: Record<string, string>;
  is_demo?: boolean;
}): VerificationReport;

export function exportReportToMarkdown(report: VerificationReport): string;

export function redactSensitiveInfo(text: string): {
  redactedText: string;
  counts: Record<string, number>;
};

export function inspectUrlStructurally(url: string): Record<string, unknown>;
