"""Pydantic schemas for JobGuard AI verification requests, extraction, and 7-category evidence reports."""
from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class EvidenceStatus(str, Enum):
    CONFIRMED_BY_SOURCE = "Confirmed by Source"
    INCONSISTENT = "Inconsistent"
    SUSPICIOUS_SIGNAL = "Suspicious Signal"
    UNVERIFIED = "Unverified"
    CHECK_UNAVAILABLE = "Check Unavailable"


class RiskLevel(str, Enum):
    LOW = "LOW RISK"
    MEDIUM = "MEDIUM RISK"
    HIGH = "HIGH RISK"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ExtractedField(BaseModel):
    field_name: str
    value: Optional[str] = None
    status: str = Field(default="missing", description="'extracted' or 'missing'")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    supporting_snippet: Optional[str] = None


class ExtractedJobData(BaseModel):
    employer: ExtractedField
    role: ExtractedField
    salary: ExtractedField
    recruiter_email: ExtractedField
    phone: ExtractedField
    location: ExtractedField
    job_url: ExtractedField
    requisition_id: ExtractedField
    payment_requests: ExtractedField
    deadlines: ExtractedField
    additional_emails: List[str] = Field(default_factory=list)
    additional_phones: List[str] = Field(default_factory=list)
    additional_urls: List[str] = Field(default_factory=list)
    employment_type: Optional[str] = None
    work_mode: Optional[str] = None
    qualifications: Optional[str] = None
    experience_required: Optional[str] = None
    detected_language: str = "en"


class DetectionIndicator(BaseModel):
    id: str
    category: str
    matched_text: str
    severity: Severity
    explanation: str
    explanation_hi: str = ""
    detection_method: str = "deterministic_rule_engine"
    reason_it_matters: str
    suggested_action: str


class URLSignal(BaseModel):
    signal: str
    severity: Severity
    explanation: str


class URLInspectionResult(BaseModel):
    submitted_url: str
    normalized_url: str
    hostname: str
    registrable_domain: str
    subdomains: List[str] = Field(default_factory=list)
    scheme: str
    is_https: bool
    is_ip_address: bool
    is_shortened: bool
    has_punycode_or_idn: bool
    subdomain_count: int
    impersonated_brand: Optional[str] = None
    official_domains: List[str] = Field(default_factory=list)
    risk_level: RiskLevel
    risk_index: int = Field(ge=0, le=100)
    summary: str
    signals: List[URLSignal] = Field(default_factory=list)
    reputation_status: str = "Check Unavailable"
    reputation_provider: str = "none (local zero-visit structural inspection)"
    recommended_actions: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)


class EvidenceRecord(BaseModel):
    check_name: str
    source_examined: str
    source_type: str = Field(
        description="'external_verification', 'local_heuristic', 'curated_registry', or 'user_supplied'"
    )
    observed_result: str
    supporting_quotation: Optional[str] = None
    status: EvidenceStatus
    timestamp: str
    explanation: str
    residual_uncertainty: str


class EvidenceCategoryReport(BaseModel):
    category_number: int
    category_id: str
    category_name: str
    overall_status: EvidenceStatus
    summary: str
    records: List[EvidenceRecord] = Field(default_factory=list)


class MLAssessment(BaseModel):
    available: bool
    model_type: str
    predicted_label: str
    scam_probability_estimate: float = Field(ge=0.0, le=1.0)
    top_contributing_terms: List[str] = Field(default_factory=list)
    dataset_disclosure: str
    evaluation_metrics: Dict[str, Any] = Field(default_factory=dict)


class AIExplanation(BaseModel):
    provider: str
    used_external_llm: bool
    summary: str
    plain_language_advice: List[str] = Field(default_factory=list)
    uncertainty_note: str


class ExtractRequest(BaseModel):
    text: str = Field(default="", max_length=25000)
    job_url: Optional[str] = Field(default=None, max_length=2048)
    secondary_text: Optional[str] = Field(
        default=None,
        max_length=25000,
        description="Optional second document (e.g., offer letter or recruiter chat) for consistency comparison",
    )
    language_hint: str = Field(default="auto")


class VerifyRequest(BaseModel):
    text: str = Field(default="", max_length=25000)
    secondary_text: Optional[str] = Field(default=None, max_length=25000)
    job_url: Optional[str] = Field(default=None, max_length=2048)
    language_hint: str = Field(default="auto")
    interface_language: str = Field(default="en")
    edited_fields: Optional[Dict[str, Optional[str]]] = None
    run_external_checks: bool = Field(default=False)
    is_demo: bool = Field(default=False)
    redact_sensitive: bool = Field(default=True)


class URLInspectRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048)
    run_external_checks: bool = Field(default=False)


class DocumentExtractionResponse(BaseModel):
    filename: str
    file_type: str
    extracted_text: str
    redacted_text: str
    redaction_counts: Dict[str, int] = Field(default_factory=dict)
    warnings: List[str] = Field(default_factory=list)
    extracted_fields: ExtractedJobData


class VerificationReport(BaseModel):
    report_id: str
    timestamp: str
    is_demo: bool = False
    detected_language: str
    interface_language: str = "en"
    risk_index: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    risk_headline: str
    risk_index_disclaimer: str
    evidence_coverage_percent: int = Field(ge=0, le=100)
    verification_confidence: str
    suspicious_indicator_count: int
    confirmed_check_count: int
    unverified_check_count: int
    unavailable_check_count: int
    inconsistent_check_count: int
    extracted_data: ExtractedJobData
    indicators: List[DetectionIndicator] = Field(default_factory=list)
    url_inspections: List[URLInspectionResult] = Field(default_factory=list)
    categories: List[EvidenceCategoryReport] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)
    recommended_actions_hi: List[str] = Field(default_factory=list)
    what_was_verified: List[str] = Field(default_factory=list)
    what_could_not_be_verified: List[str] = Field(default_factory=list)
    ml_assessment: MLAssessment
    ai_explanation: AIExplanation
    redacted_input_preview: str
    redaction_counts: Dict[str, int] = Field(default_factory=dict)
    limitations: List[str] = Field(default_factory=list)
