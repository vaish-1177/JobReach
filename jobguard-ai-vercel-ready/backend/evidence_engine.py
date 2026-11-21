"""Core 7-Category Evidence-Based Verification Report Engine & Explainable Risk Scorer."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import List, Optional

from .ai_explainer import generate_grounded_explanation
from .analyzer import RULES, compare_document_consistency, detect_legitimacy_signals, run_rule_analysis
from .extractor import apply_user_field_edits, extract_structured_job_data
from .ml_classifier import run_ml_classification
from .providers import (
    check_cloudflare_mx,
    check_gleif_employer,
    check_greenhouse_vacancy,
    check_lever_vacancy,
    check_url_reputation,
)
from .schemas import (
    DetectionIndicator,
    EvidenceCategoryReport,
    EvidenceRecord,
    EvidenceStatus,
    RiskLevel,
    Severity,
    URLInspectionResult,
    VerificationReport,
    VerifyRequest,
)
from .security import redact_sensitive_info, sanitize_plain_text
from .url_inspector import extract_urls_from_text, inspect_url_structurally
from .verification import analyze_recruiter_and_domain_alignment, lookup_employer_in_registry


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _worst_status(records: List[EvidenceRecord]) -> EvidenceStatus:
    """Determine category overall status from its individual evidence records."""
    statuses = [r.status for r in records]
    if EvidenceStatus.SUSPICIOUS_SIGNAL in statuses:
        return EvidenceStatus.SUSPICIOUS_SIGNAL
    if EvidenceStatus.INCONSISTENT in statuses:
        return EvidenceStatus.INCONSISTENT
    if EvidenceStatus.CONFIRMED_BY_SOURCE in statuses:
        return EvidenceStatus.CONFIRMED_BY_SOURCE
    if EvidenceStatus.UNVERIFIED in statuses:
        return EvidenceStatus.UNVERIFIED
    return EvidenceStatus.CHECK_UNAVAILABLE


async def build_verification_report(req: VerifyRequest) -> VerificationReport:
    """Execute all verification layers (A–H) and assemble the 7-category evidence report."""
    ts = _now_iso()
    raw_text = sanitize_plain_text(req.text)
    secondary_text = sanitize_plain_text(req.secondary_text or "")
    job_url = (req.job_url or "").strip() or None

    # Extract structured fields & apply user edits from Pre-Analysis Review
    extracted = extract_structured_job_data(raw_text, job_url=job_url, language_hint=req.language_hint)
    extracted = apply_user_field_edits(extracted, req.edited_fields)

    # Privacy redaction for stored/returned preview
    if req.redact_sensitive:
        redacted_preview, redaction_counts = redact_sensitive_info(raw_text)
    else:
        redacted_preview, redaction_counts = raw_text, {}

    # Layer A, B, G: Deterministic multilingual recruitment fraud rules
    indicators, has_disclaimer = run_rule_analysis(raw_text, extracted)

    # Layer F: Zero-visit URL & domain security inspection
    all_urls = extract_urls_from_text(raw_text)
    if extracted.job_url.value and extracted.job_url.value not in all_urls:
        all_urls.insert(0, extracted.job_url.value)
    url_inspections: List[URLInspectionResult] = [inspect_url_structurally(u) for u in all_urls[:8]]

    # Add URL-derived indicators
    for u_res in url_inspections:
        if u_res.risk_level in (RiskLevel.HIGH, RiskLevel.MEDIUM):
            sig_desc = "; ".join(s.explanation for s in u_res.signals[:2]) or u_res.summary
            indicators.append(
                DetectionIndicator(
                    id=f"url_signal_{len(indicators) + 1}",
                    category="Fake Career Portal / Suspicious URL"
                    if u_res.impersonated_brand
                    else "Suspicious Recruitment Link",
                    matched_text=u_res.submitted_url,
                    severity=Severity.CRITICAL if u_res.impersonated_brand else (
                        Severity.HIGH if u_res.risk_level == RiskLevel.HIGH else Severity.MEDIUM
                    ),
                    explanation=sig_desc,
                    explanation_hi=f"संदिग्ध लिंक '{u_res.registrable_domain}': बिना आधिकारिक पुष्टि के इस लिंक को न खोलें।",
                    detection_method="zero_visit_url_inspector",
                    reason_it_matters="Fraudulent career portals mimic real companies to steal resumes, identity documents, or registration fees.",
                    suggested_action=u_res.recommended_actions[0] if u_res.recommended_actions else "Do not open this link.",
                )
            )

    # Layer C: Employer Identity Registry Lookup
    employer_name = extracted.employer.value if extracted.employer.status == "extracted" else None
    registry_entry = lookup_employer_in_registry(employer_name)

    # Layer E: Recruiter & Email-Domain Alignment
    recruiter_info = analyze_recruiter_and_domain_alignment(extracted, registry_entry)
    if recruiter_info["is_lookalike_email_domain"]:
        indicators.append(
            DetectionIndicator(
                id=f"lookalike_email_{len(indicators) + 1}",
                category="Lookalike Recruiter Email Domain",
                matched_text=str(recruiter_info["email"]),
                severity=Severity.HIGH,
                explanation=str(recruiter_info["alignment_explanation"]),
                explanation_hi="रिक्रूटर का ईमेल डोमेन कंपनी के आधिकारिक डोमेन से मेल नहीं खाता।",
                detection_method="email_domain_alignment",
                reason_it_matters="Scammers register lookalike domains (e.g., @company-hr-careers.com) to impersonate corporate HR.",
                suggested_action="Verify the recruiter's email address against the company's official corporate domain.",
            )
        )
    elif recruiter_info["domain_mismatch"] and recruiter_info["is_personal_email"] and registry_entry:
        indicators.append(
            DetectionIndicator(
                id=f"personal_email_corp_{len(indicators) + 1}",
                category="Personal Email Claiming Major Corporate Employer",
                matched_text=str(recruiter_info["email"]),
                severity=Severity.MEDIUM,
                explanation=str(recruiter_info["alignment_explanation"]),
                explanation_hi="बड़ी कंपनी के नाम पर व्यक्तिगत जीमेल/याहू ईमेल का उपयोग किया गया है।",
                detection_method="email_domain_alignment",
                reason_it_matters="While personal email alone does not prove fraud, large enterprises almost always send official offers from corporate domains.",
                suggested_action="Ask the recruiter to email you from their verified corporate domain before proceeding.",
            )
        )

    # Layer H: Cross-Document & Internal Consistency Check
    conflicts = compare_document_consistency(raw_text, extracted, secondary_text)
    for c in conflicts:
        indicators.append(
            DetectionIndicator(
                id=f"consistency_conflict_{len(indicators) + 1}",
                category="Document & Communication Inconsistency",
                matched_text=f"{c['primary_value']} vs {c['secondary_value']}",
                severity=Severity.HIGH,
                explanation=c["explanation"],
                explanation_hi="दस्तावेजों या संदेशों में कंपनी, पद या वेतन की जानकारी में विरोधाभास पाया गया है।",
                detection_method="cross_document_consistency",
                reason_it_matters="Conflicting company names, roles, or salaries across offer letters and job posts are strong signs of a fabricated template.",
                suggested_action="Clarify the discrepancy directly through the employer's official HR contact.",
            )
        )

    # =========================================================================
    # ASSEMBLE THE 7-CATEGORY EVIDENCE-BASED VERIFICATION REPORT
    # =========================================================================
    categories: List[EvidenceCategoryReport] = []

    # --- Category 1: Employer Identity ---
    cat1_records: List[EvidenceRecord] = []
    if employer_name and registry_entry:
        cat1_records.append(
            EvidenceRecord(
                check_name="Curated Employer Reference Registry",
                source_examined="JobGuard AI Local Employer Reference Registry",
                source_type="curated_registry",
                observed_result=(
                    f"Matched '{registry_entry.canonical_name}' — Official website: {registry_entry.official_website}, "
                    f"Domains: {', '.join(registry_entry.official_domains)}, Career Portal: {registry_entry.career_portal}."
                ),
                supporting_quotation=extracted.employer.supporting_snippet,
                status=EvidenceStatus.CONFIRMED_BY_SOURCE,
                timestamp=ts,
                explanation=registry_entry.registry_note,
                residual_uncertainty="Being a real company in the registry does not prove this specific message came from them; check domain alignment and URL safety.",
            )
        )
    elif employer_name:
        cat1_records.append(
            EvidenceRecord(
                check_name="Curated Employer Reference Registry",
                source_examined="JobGuard AI Local Employer Reference Registry",
                source_type="curated_registry",
                observed_result=f"Employer '{employer_name}' is not listed in the local reference registry.",
                supporting_quotation=extracted.employer.supporting_snippet,
                status=EvidenceStatus.UNVERIFIED,
                timestamp=ts,
                explanation="An unknown or unlisted company is NOT automatically fraudulent—many legitimate startups and SMEs are not in the local registry.",
                residual_uncertainty="Independently check MCA/CIN corporate registration, LinkedIn company page, and official website.",
            )
        )
    else:
        cat1_records.append(
            EvidenceRecord(
                check_name="Employer Name Extraction",
                source_examined="User-submitted text",
                source_type="user_supplied",
                observed_result="No employer or company name was identified in the submitted material.",
                status=EvidenceStatus.UNVERIFIED,
                timestamp=ts,
                explanation="Legitimate job postings typically identify the hiring organization or authorized recruiting agency.",
                residual_uncertainty="Request the full registered legal name and website of the employer.",
            )
        )

    gleif_record = await check_gleif_employer(employer_name if req.run_external_checks else None)
    cat1_records.append(gleif_record)
    cat1_status = _worst_status(cat1_records)
    categories.append(
        EvidenceCategoryReport(
            category_number=1,
            category_id="employer_identity",
            category_name="Employer Identity",
            overall_status=cat1_status,
            summary=cat1_records[0].observed_result,
            records=cat1_records,
        )
    )

    # --- Category 2: Vacancy and Requisition Verification ---
    cat2_records: List[EvidenceRecord] = []
    if extracted.requisition_id.status == "extracted":
        cat2_records.append(
            EvidenceRecord(
                check_name="Requisition / Job ID Presence",
                source_examined="User-submitted text",
                source_type="user_supplied",
                observed_result=f"Extracted Requisition/Job ID: {extracted.requisition_id.value}.",
                supporting_quotation=extracted.requisition_id.supporting_snippet,
                status=EvidenceStatus.UNVERIFIED,
                timestamp=ts,
                explanation="A requisition ID was supplied, but it has not yet been matched against a live ATS database.",
                residual_uncertainty="Search this requisition ID directly on the employer's official career portal.",
            )
        )
    else:
        cat2_records.append(
            EvidenceRecord(
                check_name="Requisition / Job ID Presence",
                source_examined="User-submitted text",
                source_type="user_supplied",
                observed_result="No requisition ID or vacancy code was found in the submission.",
                status=EvidenceStatus.UNVERIFIED,
                timestamp=ts,
                explanation="Many small-company postings omit requisition IDs, while larger enterprises usually assign one.",
                residual_uncertainty="Ask for the public job posting link or requisition ID.",
            )
        )

    gh_token = registry_entry.ats_slug if (registry_entry and registry_entry.ats_provider == "greenhouse" and req.run_external_checks) else None
    gh_rec = await check_greenhouse_vacancy(gh_token, extracted.role.value, extracted.requisition_id.value)
    lever_rec = await check_lever_vacancy(None, extracted.role.value)
    cat2_records.extend([gh_rec, lever_rec])
    cat2_status = _worst_status(cat2_records)
    categories.append(
        EvidenceCategoryReport(
            category_number=2,
            category_id="vacancy_verification",
            category_name="Vacancy and Requisition Verification",
            overall_status=cat2_status,
            summary=(
                "Live ATS vacancy match confirmed."
                if cat2_status == EvidenceStatus.CONFIRMED_BY_SOURCE
                else "Vacancy could not be independently confirmed via public ATS boards."
            ),
            records=cat2_records,
        )
    )

    # --- Category 3: Recruiter Contact Verification ---
    cat3_records: List[EvidenceRecord] = []
    messaging_only = any(i.category == "WhatsApp / Telegram-Only Recruitment Funnel" for i in indicators)
    if messaging_only:
        ind = next(i for i in indicators if i.category == "WhatsApp / Telegram-Only Recruitment Funnel")
        cat3_records.append(
            EvidenceRecord(
                check_name="Recruitment Communication Channel",
                source_examined="User-submitted text",
                source_type="local_heuristic",
                observed_result="Recruiter directs candidates exclusively to WhatsApp or Telegram.",
                supporting_quotation=ind.matched_text,
                status=EvidenceStatus.SUSPICIOUS_SIGNAL,
                timestamp=ts,
                explanation=ind.explanation,
                residual_uncertainty="Verify whether the recruiter also communicates via an official corporate email.",
            )
        )
    if extracted.phone.status == "extracted":
        cat3_records.append(
            EvidenceRecord(
                check_name="Contact Phone Extraction",
                source_examined="User-submitted text",
                source_type="user_supplied",
                observed_result=f"Phone number detected: {extracted.phone.value}.",
                supporting_quotation=extracted.phone.supporting_snippet,
                status=EvidenceStatus.UNVERIFIED,
                timestamp=ts,
                explanation="Personal or mobile phone numbers cannot be independently verified as belonging to a company without corporate directory lookup.",
                residual_uncertainty="Do not rely solely on caller ID or WhatsApp display pictures.",
            )
        )
    if not cat3_records:
        cat3_records.append(
            EvidenceRecord(
                check_name="Recruiter Contact Details",
                source_examined="User-submitted text",
                source_type="user_supplied",
                observed_result="No phone number or messaging handle was provided.",
                status=EvidenceStatus.UNVERIFIED,
                timestamp=ts,
                explanation="Recruiter identity should be confirmed via official corporate channels.",
                residual_uncertainty="Check recruiter profile on LinkedIn and verify corporate email.",
            )
        )
    cat3_status = _worst_status(cat3_records)
    categories.append(
        EvidenceCategoryReport(
            category_number=3,
            category_id="recruiter_contact",
            category_name="Recruiter Contact Verification",
            overall_status=cat3_status,
            summary=cat3_records[0].observed_result,
            records=cat3_records,
        )
    )

    # --- Category 4: Email and Domain Alignment ---
    cat4_records: List[EvidenceRecord] = [
        EvidenceRecord(
            check_name="Recruiter Email vs. Employer Domain Alignment",
            source_examined="Extracted email & Employer Reference Registry",
            source_type="curated_registry" if registry_entry else "local_heuristic",
            observed_result=(
                f"Email: {recruiter_info['email']} (domain: {recruiter_info['email_domain']})"
                if recruiter_info["email"]
                else "No recruiter email address present."
            ),
            supporting_quotation=extracted.recruiter_email.supporting_snippet,
            status=recruiter_info["alignment_status"],  # type: ignore[arg-type]
            timestamp=ts,
            explanation=str(recruiter_info["alignment_explanation"]),
            residual_uncertainty="Pasted text cannot verify SPF/DKIM/DMARC email headers; check the full email header in your mail client.",
        )
    ]
    mx_rec = await check_cloudflare_mx(
        str(recruiter_info["email_domain"]) if (req.run_external_checks and recruiter_info["email_domain"]) else None
    )
    cat4_records.append(mx_rec)
    cat4_status = _worst_status(cat4_records)
    categories.append(
        EvidenceCategoryReport(
            category_number=4,
            category_id="email_domain_alignment",
            category_name="Email and Domain Alignment",
            overall_status=cat4_status,
            summary=str(recruiter_info["alignment_explanation"]),
            records=cat4_records,
        )
    )

    # --- Category 5: Link and Domain Safety ---
    cat5_records: List[EvidenceRecord] = []
    if url_inspections:
        for u_res in url_inspections:
            u_status = (
                EvidenceStatus.SUSPICIOUS_SIGNAL
                if u_res.risk_level in (RiskLevel.HIGH, RiskLevel.MEDIUM)
                else (
                    EvidenceStatus.CONFIRMED_BY_SOURCE
                    if (registry_entry and u_res.registrable_domain in registry_entry.official_domains)
                    else EvidenceStatus.UNVERIFIED
                )
            )
            cat5_records.append(
                EvidenceRecord(
                    check_name=f"Zero-Visit URL Structural Inspection ({u_res.registrable_domain or u_res.hostname})",
                    source_examined=u_res.submitted_url,
                    source_type="local_heuristic",
                    observed_result=u_res.summary,
                    supporting_quotation=u_res.submitted_url,
                    status=u_status,
                    timestamp=ts,
                    explanation="; ".join(s.explanation for s in u_res.signals) if u_res.signals else "No structural phishing anomalies found.",
                    residual_uncertainty="URL was never visited automatically; structural inspection cannot detect compromised pages on legitimate hosts.",
                )
            )
        rep_rec = await check_url_reputation(url_inspections[0].normalized_url if req.run_external_checks else None)
        cat5_records.append(rep_rec)
    else:
        cat5_records.append(
            EvidenceRecord(
                check_name="URL Extraction & Structural Inspection",
                source_examined="User-submitted text",
                source_type="local_heuristic",
                observed_result="No job or application URLs were found in the submitted text.",
                status=EvidenceStatus.UNVERIFIED,
                timestamp=ts,
                explanation="Without an official application link, the career portal domain cannot be verified.",
                residual_uncertainty="Ask for the official career portal URL and inspect it before clicking.",
            )
        )
    cat5_status = _worst_status(cat5_records)
    categories.append(
        EvidenceCategoryReport(
            category_number=5,
            category_id="link_domain_safety",
            category_name="Link and Domain Safety",
            overall_status=cat5_status,
            summary=cat5_records[0].observed_result,
            records=cat5_records,
        )
    )

    # --- Category 6: Payment and Sensitive Information Requests ---
    cat6_records: List[EvidenceRecord] = []
    payment_or_cred_cats = {
        "Advance Fee / Registration Scam",
        "Security / Equipment Deposit Scam",
        "Direct UPI / QR / Payment Transfer Request",
        "Paid Training / Fake Internship Scam",
        "Prepaid Task & Recharge Scam",
        "Crypto / Investment / Deposit-Return Job Scam",
        "OTP / UPI PIN / Credential Theft",
        "Upfront KYC / Identity & Bank Document Harvest",
        "Remote-Access Software Scam",
    }
    pay_inds = [i for i in indicators if i.category in payment_or_cred_cats]
    if pay_inds:
        for ind in pay_inds:
            cat6_records.append(
                EvidenceRecord(
                    check_name=ind.category,
                    source_examined="User-submitted text",
                    source_type="local_heuristic",
                    observed_result=f"Detected {ind.category} ({ind.severity.value} severity).",
                    supporting_quotation=ind.matched_text,
                    status=EvidenceStatus.SUSPICIOUS_SIGNAL,
                    timestamp=ts,
                    explanation=ind.explanation,
                    residual_uncertainty="Verify directly with official HR; legitimate hiring does not require upfront candidate payments or OTP/UPI PIN.",
                )
            )
    else:
        cat6_records.append(
            EvidenceRecord(
                check_name="Upfront Payment, Deposit & Credential Request Check",
                source_examined="User-submitted text",
                source_type="local_heuristic",
                observed_result=(
                    "Contains an explicit anti-fraud safety disclaimer stating no fees are charged."
                    if has_disclaimer
                    else "No upfront fee, security deposit, OTP/UPI PIN, or remote-access software demands detected in the submitted text."
                ),
                status=EvidenceStatus.CONFIRMED_BY_SOURCE if has_disclaimer else EvidenceStatus.UNVERIFIED,
                timestamp=ts,
                explanation=(
                    "Anti-fraud disclaimers are recognized as protective notices rather than scam triggers."
                    if has_disclaimer
                    else "Absence of payment demands in the initial message does not guarantee a fee will not be requested later in the process."
                ),
                residual_uncertainty="Stay alert if payment, deposit, or sensitive credentials are requested in later messages or calls.",
            )
        )
    cat6_status = _worst_status(cat6_records)
    categories.append(
        EvidenceCategoryReport(
            category_number=6,
            category_id="payment_sensitive_info",
            category_name="Payment and Sensitive Information Requests",
            overall_status=cat6_status,
            summary=cat6_records[0].observed_result,
            records=cat6_records,
        )
    )

    # --- Category 7: Document and Message Consistency ---
    cat7_records: List[EvidenceRecord] = []
    if conflicts:
        for c in conflicts:
            cat7_records.append(
                EvidenceRecord(
                    check_name=f"Consistency Check: {c['field']}",
                    source_examined="Primary vs. Secondary Submitted Materials",
                    source_type="local_heuristic",
                    observed_result=c["explanation"],
                    supporting_quotation=f"{c['primary_value']} <-> {c['secondary_value']}",
                    status=EvidenceStatus.INCONSISTENT,
                    timestamp=ts,
                    explanation=c["explanation"],
                    residual_uncertainty="Resolve all discrepancies directly with verified corporate HR before signing or sharing documents.",
                )
            )
    elif secondary_text:
        cat7_records.append(
            EvidenceRecord(
                check_name="Cross-Document Field Comparison",
                source_examined="Primary & Secondary Submitted Materials",
                source_type="local_heuristic",
                observed_result="No contradictions detected across overlapping extracted fields in the two submitted materials.",
                status=EvidenceStatus.CONFIRMED_BY_SOURCE,
                timestamp=ts,
                explanation="Extracted employer, role, salary, location, and email fields did not conflict across the submitted texts.",
                residual_uncertainty="Manual review of fine-print offer terms is still recommended.",
            )
        )
    else:
        missing_core = [
            name
            for name in ("employer", "role", "salary", "location", "recruiter_email")
            if getattr(extracted, name).status == "missing"
        ]
        cat7_records.append(
            EvidenceRecord(
                check_name="Single-Document Completeness & Consistency",
                source_examined="User-submitted text",
                source_type="local_heuristic",
                observed_result=(
                    f"Single document submitted; {len(missing_core)} core field(s) missing ({', '.join(missing_core)})."
                    if missing_core
                    else "All core job-posting fields are present; no secondary document supplied for cross-comparison."
                ),
                status=EvidenceStatus.UNVERIFIED,
                timestamp=ts,
                explanation=(
                    "Incomplete job details reduce verifiability. Submit an offer letter or recruiter email alongside the job description to run cross-document comparison."
                ),
                residual_uncertainty="Cross-document consistency could not be evaluated without a second source.",
            )
        )
    cat7_status = _worst_status(cat7_records)
    categories.append(
        EvidenceCategoryReport(
            category_number=7,
            category_id="document_consistency",
            category_name="Document and Message Consistency",
            overall_status=cat7_status,
            summary=cat7_records[0].observed_result,
            records=cat7_records,
        )
    )

    # =========================================================================
    # EXPLAINABLE CALIBRATED HEURISTIC RISK INDEX & COVERAGE CALCULATION (v2)
    # =========================================================================
    rule_weight_by_cat = {r.category: r.weight for r in RULES}
    sev_default_weight = {
        Severity.CRITICAL: 44,
        Severity.HIGH: 28,
        Severity.MEDIUM: 16,
        Severity.LOW: 10,
    }
    crit_cnt = sum(1 for i in indicators if i.severity == Severity.CRITICAL)
    high_cnt = sum(1 for i in indicators if i.severity == Severity.HIGH)
    med_cnt = sum(1 for i in indicators if i.severity == Severity.MEDIUM)
    low_cnt = sum(1 for i in indicators if i.severity == Severity.LOW)
    max_url_risk = max((u.risk_index for u in url_inspections), default=0)

    # 1. Weighted indicator sum + compound multi-signal synergy
    indicator_points = sum(
        rule_weight_by_cat.get(i.category, sev_default_weight[i.severity])
        for i in indicators
    )
    distinct_cats = len({i.category for i in indicators})
    synergy_bonus = 18 if distinct_cats >= 4 else (12 if distinct_cats == 3 else (6 if distinct_cats == 2 else 0))

    # Smooth diminishing saturation above 70 so high-risk scores spread meaningfully (62..98)
    combined_signal_pts = indicator_points + synergy_bonus
    if combined_signal_pts > 70:
        combined_signal_pts = 70 + int(round((combined_signal_pts - 70) * 0.42))

    # Base neutral score starts at 12 (never a hardcoded 26 cliff)
    raw_score = 12 + combined_signal_pts

    if max_url_risk >= 60 and crit_cnt == 0:
        raw_score = max(raw_score, max_url_risk)
    elif max_url_risk >= 25 and not any(i.detection_method == "zero_visit_url_inspector" for i in indicators):
        raw_score += int(max_url_risk * 0.30)

    # 2. Secondary ML layer (Unigram+Bigram TF-IDF + Logistic Regression)
    ml_res = run_ml_classification(raw_text)
    ml_prob = ml_res.scam_probability_estimate
    if ml_prob >= 0.72:
        raw_score += int(round((ml_prob - 0.50) * 32))
    elif ml_prob >= 0.58:
        raw_score += int(round((ml_prob - 0.50) * 20))
    elif ml_prob <= 0.32 and crit_cnt == 0 and high_cnt == 0 and max_url_risk < 40:
        raw_score -= int(round((0.45 - ml_prob) * 22))

    # 3. Positive legitimacy & trust-signal calibration (only when no critical/high fraud exists)
    trust_deduction = 0
    if crit_cnt == 0 and high_cnt == 0 and max_url_risk < 40 and not conflicts:
        if recruiter_info["alignment_status"] == EvidenceStatus.CONFIRMED_BY_SOURCE:
            trust_deduction += 10
        elif recruiter_info["email_domain"] and not recruiter_info["is_personal_email"] and not recruiter_info["domain_mismatch"]:
            trust_deduction += 5
        if any(
            registry_entry and u.registrable_domain in registry_entry.official_domains
            for u in url_inspections
        ):
            trust_deduction += 8
        if has_disclaimer:
            trust_deduction += 10
        legit_sigs = detect_legitimacy_signals(raw_text)
        trust_deduction += min(16, sum(int(s["bonus"]) for s in legit_sigs))
        raw_score -= min(28, trust_deduction)
        if has_disclaimer and med_cnt == 0:
            raw_score = min(raw_score, 12)

    # 4. Proportional missing-info uncertainty (replaces the old hardcoded 26 trap)
    missing_core_count = sum(
        1
        for f in ("employer", "role", "recruiter_email", "job_url")
        if getattr(extracted, f).status == "missing"
    )
    if crit_cnt == 0 and high_cnt == 0 and med_cnt == 0 and trust_deduction < 8 and missing_core_count >= 2:
        raw_score += min(9, (missing_core_count - 1) * 3)

    # Ensure critical indicators always reflect HIGH RISK floor (>=64)
    if crit_cnt >= 1:
        raw_score = max(raw_score, 70 + min(20, (crit_cnt - 1) * 10 + high_cnt * 6 + med_cnt * 4))
    elif high_cnt >= 2:
        raw_score = max(raw_score, 62)

    risk_index = max(4, min(98, int(round(raw_score))))

    if risk_index >= 60 or crit_cnt >= 1 or high_cnt >= 2:
        risk_level = RiskLevel.HIGH
        risk_headline = "HIGH RISK — Multiple serious fraud indicators or strong contradictory evidence."
    elif risk_index >= 28 or high_cnt >= 1 or med_cnt >= 1 or conflicts:
        risk_level = RiskLevel.MEDIUM
        risk_headline = "MEDIUM RISK — Concerning indicators or important unverified information."
    else:
        risk_level = RiskLevel.LOW
        risk_headline = "LOW RISK — No strong suspicious indicators identified (verify unconfirmed details)."

    # Evidence coverage & status counts across all records
    all_records = [r for cat in categories for r in cat.records]
    confirmed_count = sum(1 for r in all_records if r.status == EvidenceStatus.CONFIRMED_BY_SOURCE)
    unverified_count = sum(1 for r in all_records if r.status == EvidenceStatus.UNVERIFIED)
    unavailable_count = sum(1 for r in all_records if r.status == EvidenceStatus.CHECK_UNAVAILABLE)
    inconsistent_count = sum(1 for r in all_records if r.status == EvidenceStatus.INCONSISTENT)
    suspicious_count = sum(1 for r in all_records if r.status == EvidenceStatus.SUSPICIOUS_SIGNAL)

    evaluated_checks = confirmed_count + inconsistent_count + suspicious_count
    evidence_coverage = int(round((evaluated_checks / max(1, len(all_records))) * 100))

    if evidence_coverage >= 65 and unavailable_count <= 2:
        verification_confidence = "Moderate-to-High (Multiple Checks Evaluated)"
    elif evidence_coverage >= 35:
        verification_confidence = "Partial (Local Checks Complete; External Checks Limited)"
    else:
        verification_confidence = "Limited (Several Details Missing or Unverified)"

    what_verified = [
        f"{c.category_name}: {r.check_name} — {r.observed_result}"
        for c in categories
        for r in c.records
        if r.status == EvidenceStatus.CONFIRMED_BY_SOURCE
    ]
    what_not_verified = [
        f"{c.category_name}: {r.check_name} ({r.status.value}) — {r.residual_uncertainty}"
        for c in categories
        for r in c.records
        if r.status in (EvidenceStatus.UNVERIFIED, EvidenceStatus.CHECK_UNAVAILABLE)
    ]

    ai_explanation = generate_grounded_explanation(
        risk_level=risk_level,
        risk_index=risk_index,
        indicators=indicators,
        categories=categories,
        what_could_not_be_verified=what_not_verified,
        interface_language=req.interface_language,
    )

    rec_actions_en = (
        [
            "Do not pay any registration fee, security deposit, training fee, or task recharge.",
            "Do not open unverified career links or install AnyDesk / TeamViewer.",
            "Never share OTPs, UPI PINs, ATM PINs, CVV, or banking passwords with any recruiter.",
            "If you already transferred money in India, dial 1930 immediately and report on cybercrime.gov.in.",
        ]
        if risk_level == RiskLevel.HIGH
        else (
            [
                "Independently look up the company's official website and career portal to verify the vacancy.",
                "Ask the recruiter to communicate from a verified corporate email address.",
                "Never pay upfront fees or share Aadhaar/PAN/banking details before verifying the employer.",
            ]
            if risk_level == RiskLevel.MEDIUM
            else [
                "Even with low detected risk, confirm the role directly on the company's official career page.",
                "Treat any later demand for fees, deposits, or OTPs as an immediate red flag.",
            ]
        )
    )

    rec_actions_hi = [
        "किसी भी रजिस्ट्रेशन फीस, सिक्योरिटी डिपॉजिट या प्रीपेड टास्क के लिए पैसे न दें।",
        "असत्यापित करियर लिंक न खोलें और न ही AnyDesk या TeamViewer इंस्टॉल करें।",
        "अपना ओटीपी, यूपीआई पिन या बैंक पासवर्ड किसी भी रिक्रूटर के साथ साझा न करें।",
        "वित्तीय धोखाधड़ी होने पर तुरंत 1930 पर कॉल करें और cybercrime.gov.in पर शिकायत दर्ज करें।",
    ]

    return VerificationReport(
        report_id=f"jg-{uuid.uuid4().hex[:10]}",
        timestamp=ts,
        is_demo=req.is_demo,
        detected_language=extracted.detected_language,
        interface_language=req.interface_language,
        risk_index=risk_index,
        risk_level=risk_level,
        risk_headline=risk_headline,
        risk_index_disclaimer=(
            "This 0–100 Risk Index is an explainable heuristic assessment derived from deterministic rules, "
            "domain/URL structure, and evidence consistency—NOT a mathematically calibrated probability of fraud. "
            "Absence of detected indicators does not prove an opportunity is legitimate."
        ),
        evidence_coverage_percent=evidence_coverage,
        verification_confidence=verification_confidence,
        suspicious_indicator_count=len(indicators),
        confirmed_check_count=confirmed_count,
        unverified_check_count=unverified_count,
        unavailable_check_count=unavailable_count,
        inconsistent_check_count=inconsistent_count,
        extracted_data=extracted,
        indicators=indicators,
        url_inspections=url_inspections,
        categories=categories,
        recommended_actions=rec_actions_en,
        recommended_actions_hi=rec_actions_hi,
        what_was_verified=what_verified,
        what_could_not_be_verified=what_not_verified,
        ml_assessment=ml_res,
        ai_explanation=ai_explanation,
        redacted_input_preview=redacted_preview[:1500],
        redaction_counts=redaction_counts,
        limitations=[
            "Local verification never opens or fetches arbitrary user-submitted URLs.",
            "External ATS (Greenhouse/Lever), corporate (GLEIF/OpenCorporates), DNS MX, and reputation checks are optional and honestly marked 'Check Unavailable' when disabled or unreachable.",
            "An unknown company not present in the curated reference registry is marked 'Unverified', never automatically classified as fraudulent.",
            "Pasted email text cannot cryptographically validate SPF/DKIM/DMARC mail headers.",
        ],
    )
