"""Layers C & E: Curated Employer Identity Reference Registry & Recruiter / Email-Domain Alignment."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .schemas import EvidenceStatus, ExtractedJobData
from .url_inspector import extract_registrable_domain


@dataclass(frozen=True)
class EmployerRegistryEntry:
    canonical_name: str
    aliases: Tuple[str, ...]
    official_website: str
    official_domains: Tuple[str, ...]
    career_portal: str
    registry_note: str
    ats_provider: Optional[str] = None
    ats_slug: Optional[str] = None


# Curated, explainable employer reference registry (local reference — not live MCA/corporate registry)
EMPLOYER_REGISTRY: List[EmployerRegistryEntry] = [
    EmployerRegistryEntry(
        canonical_name="Infosys Limited",
        aliases=("infosys", "infosys limited", "infosys ltd"),
        official_website="https://www.infosys.com",
        official_domains=("infosys.com",),
        career_portal="https://www.infosys.com/careers/",
        registry_note="Publicly listed Indian IT services corporation; official hiring communications use @infosys.com.",
    ),
    EmployerRegistryEntry(
        canonical_name="Tata Consultancy Services (TCS)",
        aliases=("tcs", "tata consultancy services", "tata consultancy services ltd"),
        official_website="https://www.tcs.com",
        official_domains=("tcs.com",),
        career_portal="https://www.tcs.com/careers",
        registry_note="Publicly listed IT services company; official recruitment portal is TCS NextStep / tcs.com.",
    ),
    EmployerRegistryEntry(
        canonical_name="Wipro Limited",
        aliases=("wipro", "wipro limited", "wipro ltd"),
        official_website="https://www.wipro.com",
        official_domains=("wipro.com",),
        career_portal="https://careers.wipro.com",
        registry_note="Official hiring communications use @wipro.com; Wipro publishes an anti-recruitment-fraud notice stating it never charges fees.",
    ),
    EmployerRegistryEntry(
        canonical_name="HCLTech",
        aliases=("hcl", "hcltech", "hcl technologies", "hcl technologies limited"),
        official_website="https://www.hcltech.com",
        official_domains=("hcltech.com", "hcl.com"),
        career_portal="https://www.hcltech.com/careers",
        registry_note="Official corporate domain is hcltech.com.",
    ),
    EmployerRegistryEntry(
        canonical_name="Accenture",
        aliases=("accenture", "accenture india", "accenture solutions"),
        official_website="https://www.accenture.com",
        official_domains=("accenture.com",),
        career_portal="https://www.accenture.com/in-en/careers",
        registry_note="Official hiring communications originate from @accenture.com.",
    ),
    EmployerRegistryEntry(
        canonical_name="Cognizant Technology Solutions",
        aliases=("cognizant", "cts", "cognizant technology solutions"),
        official_website="https://www.cognizant.com",
        official_domains=("cognizant.com",),
        career_portal="https://careers.cognizant.com",
        registry_note="Official hiring communications originate from @cognizant.com.",
    ),
    EmployerRegistryEntry(
        canonical_name="Capgemini",
        aliases=("capgemini", "capgemini india"),
        official_website="https://www.capgemini.com",
        official_domains=("capgemini.com",),
        career_portal="https://www.capgemini.com/careers/",
        registry_note="Official corporate domain is capgemini.com.",
    ),
    EmployerRegistryEntry(
        canonical_name="Google LLC",
        aliases=("google", "google india", "google llc"),
        official_website="https://www.google.com",
        official_domains=("google.com",),
        career_portal="https://www.google.com/about/careers/applications/",
        registry_note="Official recruiter emails end in @google.com (or authorized staffing partners with transparent disclosure).",
    ),
    EmployerRegistryEntry(
        canonical_name="Microsoft Corporation",
        aliases=("microsoft", "microsoft india", "microsoft corporation"),
        official_website="https://www.microsoft.com",
        official_domains=("microsoft.com",),
        career_portal="https://careers.microsoft.com",
        registry_note="Official corporate recruitment domain is microsoft.com.",
    ),
    EmployerRegistryEntry(
        canonical_name="Amazon",
        aliases=("amazon", "amazon india", "amazon development centre", "aws"),
        official_website="https://www.amazon.jobs",
        official_domains=("amazon.com", "amazon.jobs", "amazon.in"),
        career_portal="https://www.amazon.jobs",
        registry_note="Official job portal is amazon.jobs; corporate emails use @amazon.com.",
    ),
    EmployerRegistryEntry(
        canonical_name="Flipkart",
        aliases=("flipkart", "flipkart internet"),
        official_website="https://www.flipkartcareers.com",
        official_domains=("flipkart.com", "flipkartcareers.com"),
        career_portal="https://www.flipkartcareers.com",
        registry_note="Official career portal is flipkartcareers.com.",
    ),
    EmployerRegistryEntry(
        canonical_name="Zoho Corporation",
        aliases=("zoho", "zoho corp", "zoho corporation"),
        official_website="https://www.zoho.com",
        official_domains=("zohocorp.com", "zoho.com"),
        career_portal="https://www.zoho.com/careers/",
        registry_note="Official corporate domains are zohocorp.com and zoho.com.",
    ),
    EmployerRegistryEntry(
        canonical_name="Deloitte",
        aliases=("deloitte", "deloitte india", "deloitte usi"),
        official_website="https://www2.deloitte.com",
        official_domains=("deloitte.com",),
        career_portal="https://jobsindia.deloitte.com",
        registry_note="Official corporate domain is deloitte.com.",
    ),
    EmployerRegistryEntry(
        canonical_name="Razorpay",
        aliases=("razorpay", "razorpay software"),
        official_website="https://razorpay.com",
        official_domains=("razorpay.com",),
        career_portal="https://razorpay.com/jobs/",
        registry_note="Official corporate domain is razorpay.com.",
        ats_provider="greenhouse",
        ats_slug="razorpaysoftwareprivatelimited",
    ),
]

PERSONAL_EMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "yahoo.co.in", "outlook.com", "hotmail.com",
    "live.com", "rediffmail.com", "protonmail.com", "proton.me", "icloud.com", "aol.com",
}


def lookup_employer_in_registry(employer_name: Optional[str]) -> Optional[EmployerRegistryEntry]:
    """Match an extracted employer name against the curated local reference registry."""
    if not employer_name:
        return None
    norm = re.sub(r"[^a-z0-9\s]", "", employer_name.lower()).strip()
    norm = re.sub(r"\s+", " ", norm)
    for entry in EMPLOYER_REGISTRY:
        for alias in entry.aliases:
            if norm == alias or alias in norm or norm in alias and len(norm) >= 3:
                return entry
    return None


def analyze_recruiter_and_domain_alignment(
    extracted: ExtractedJobData,
    registry_entry: Optional[EmployerRegistryEntry],
) -> Dict[str, object]:
    """Layer E: Evaluate recruiter email, personal email usage, and domain alignment."""
    email = extracted.recruiter_email.value if extracted.recruiter_email.status == "extracted" else None
    job_url = extracted.job_url.value if extracted.job_url.status == "extracted" else None

    email_domain: Optional[str] = None
    is_personal_email = False
    if email and "@" in email:
        email_domain = email.rsplit("@", 1)[-1].lower().strip()
        is_personal_email = email_domain in PERSONAL_EMAIL_PROVIDERS

    url_reg_domain: Optional[str] = None
    if job_url:
        from urllib.parse import urlparse

        ws = job_url if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", job_url) else f"http://{job_url}"
        url_reg_domain, _ = extract_registrable_domain(urlparse(ws).hostname or "")

    alignment_status = EvidenceStatus.UNVERIFIED
    alignment_explanation = "No recruiter email address was provided to verify domain alignment."
    is_lookalike_email_domain = False
    domain_mismatch = False

    if email_domain:
        if registry_entry:
            if email_domain in registry_entry.official_domains:
                alignment_status = EvidenceStatus.CONFIRMED_BY_SOURCE
                alignment_explanation = (
                    f"Recruiter email domain '@{email_domain}' matches {registry_entry.canonical_name}'s "
                    f"known official domain ({', '.join(registry_entry.official_domains)}). "
                    "Note: Email headers/DKIM are not verified from pasted text alone."
                )
            elif is_personal_email:
                alignment_status = EvidenceStatus.SUSPICIOUS_SIGNAL
                domain_mismatch = True
                alignment_explanation = (
                    f"Claimed employer '{registry_entry.canonical_name}' uses corporate domains "
                    f"({', '.join(registry_entry.official_domains)}), but the recruiter uses a personal email "
                    f"('@'{email_domain}). Personal email alone is not conclusive proof of fraud, but is unusual for large corporate hiring."
                )
            else:
                alignment_status = EvidenceStatus.INCONSISTENT
                domain_mismatch = True
                # Check if email domain impersonates the employer name
                brand_key = registry_entry.aliases[0]
                if brand_key in email_domain:
                    is_lookalike_email_domain = True
                alignment_explanation = (
                    f"Recruiter email domain '@{email_domain}' does not match {registry_entry.canonical_name}'s "
                    f"official domain(s) ({', '.join(registry_entry.official_domains)})."
                )
        else:
            if is_personal_email:
                alignment_status = EvidenceStatus.UNVERIFIED
                alignment_explanation = (
                    f"Recruiter uses a free personal email provider ('@{email_domain}'). "
                    "Small businesses sometimes use personal email, so this alone is not conclusive proof of fraud, "
                    "but corporate affiliation cannot be verified from the email domain."
                )
            elif url_reg_domain and email_domain != url_reg_domain and not email_domain.endswith("." + url_reg_domain):
                alignment_status = EvidenceStatus.INCONSISTENT
                domain_mismatch = True
                alignment_explanation = (
                    f"Recruiter email domain '@{email_domain}' differs from the job URL domain '{url_reg_domain}'."
                )
            else:
                alignment_status = EvidenceStatus.UNVERIFIED
                alignment_explanation = (
                    f"Recruiter uses custom domain '@{email_domain}', which is not in the curated registry "
                    "and has not been independently verified via live corporate records."
                )

    return {
        "email": email,
        "email_domain": email_domain,
        "is_personal_email": is_personal_email,
        "is_lookalike_email_domain": is_lookalike_email_domain,
        "domain_mismatch": domain_mismatch,
        "url_reg_domain": url_reg_domain,
        "alignment_status": alignment_status,
        "alignment_explanation": alignment_explanation,
    }
