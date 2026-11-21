export type EvidenceStatus =
  | "Confirmed by Source"
  | "Inconsistent"
  | "Suspicious Signal"
  | "Unverified"
  | "Check Unavailable";

export type RiskLevel = "LOW RISK" | "MEDIUM RISK" | "HIGH RISK";
export type Severity = "low" | "medium" | "high" | "critical";

export interface ExtractedField {
  field_name: string;
  value: string | null;
  status: "extracted" | "missing";
  confidence: number;
  supporting_snippet: string | null;
}

export interface ExtractedJobData {
  employer: ExtractedField;
  role: ExtractedField;
  salary: ExtractedField;
  recruiter_email: ExtractedField;
  phone: ExtractedField;
  location: ExtractedField;
  job_url: ExtractedField;
  requisition_id: ExtractedField;
  payment_requests: ExtractedField;
  deadlines: ExtractedField;
  additional_emails: string[];
  additional_phones: string[];
  additional_urls: string[];
  employment_type?: string | null;
  work_mode?: string | null;
  qualifications?: string | null;
  experience_required?: string | null;
  detected_language: string;
}

export interface DetectionIndicator {
  id: string;
  category: string;
  matched_text: string;
  severity: Severity;
  explanation: string;
  explanation_hi: string;
  detection_method: string;
  reason_it_matters: string;
  suggested_action: string;
}

export interface URLSignal {
  signal: string;
  severity: Severity;
  explanation: string;
}

export interface URLInspectionResult {
  submitted_url: string;
  normalized_url: string;
  hostname: string;
  registrable_domain: string;
  subdomains: string[];
  scheme: string;
  is_https: boolean;
  is_ip_address: boolean;
  is_shortened: boolean;
  has_punycode_or_idn: boolean;
  subdomain_count: number;
  impersonated_brand: string | null;
  official_domains: string[];
  risk_level: RiskLevel;
  risk_index: number;
  summary: string;
  signals: URLSignal[];
  reputation_status: string;
  reputation_provider: string;
  recommended_actions: string[];
  limitations: string[];
}

export interface EvidenceRecord {
  check_name: string;
  source_examined: string;
  source_type: string;
  observed_result: string;
  supporting_quotation?: string | null;
  status: EvidenceStatus;
  timestamp: string;
  explanation: string;
  residual_uncertainty: string;
}

export interface EvidenceCategoryReport {
  category_number: number;
  category_id: string;
  category_name: string;
  overall_status: EvidenceStatus;
  summary: string;
  records: EvidenceRecord[];
}

export interface VerificationReport {
  report_id: string;
  timestamp: string;
  is_demo: boolean;
  detected_language: string;
  interface_language: string;
  risk_index: number;
  risk_level: RiskLevel;
  risk_headline: string;
  risk_index_disclaimer: string;
  evidence_coverage_percent: number;
  verification_confidence: string;
  suspicious_indicator_count: number;
  confirmed_check_count: number;
  unverified_check_count: number;
  unavailable_check_count: number;
  inconsistent_check_count: number;
  extracted_data: ExtractedJobData;
  indicators: DetectionIndicator[];
  url_inspections: URLInspectionResult[];
  categories: EvidenceCategoryReport[];
  recommended_actions: string[];
  recommended_actions_hi: string[];
  what_was_verified: string[];
  what_could_not_be_verified: string[];
  ml_assessment: {
    available: boolean;
    model_type: string;
    predicted_label: string;
    scam_probability_estimate: number;
    top_contributing_terms: string[];
    dataset_disclosure: string;
    evaluation_metrics: Record<string, unknown>;
  };
  ai_explanation: {
    provider: string;
    used_external_llm: boolean;
    summary: string;
    plain_language_advice: string[];
    uncertainty_note: string;
  };
  redacted_input_preview: string;
  redaction_counts: Record<string, number>;
  limitations: string[];
}
