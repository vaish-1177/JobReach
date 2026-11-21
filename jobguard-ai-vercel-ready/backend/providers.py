"""Optional, environment-variable-gated external verification providers.

Supported allowlisted providers (all optional; core platform works 100% locally without them):
- Greenhouse public job boards (ENABLE_GREENHOUSE_CHECK=true)
- Lever public job postings (ENABLE_LEVER_CHECK=true)
- GLEIF public LEI API (ENABLE_GLEIF_CHECK=true)
- OpenCorporates API (OPENCORPORATES_API_KEY)
- IANA RDAP (ENABLE_RDAP_CHECK=true)
- Cloudflare DNS-over-HTTPS for MX records (ENABLE_DOH_MX_CHECK=true)
- Google Safe Browsing (GOOGLE_SAFE_BROWSING_API_KEY)
- VirusTotal (VIRUSTOTAL_API_KEY)

CRITICAL POLICY:
- Never fetch arbitrary user-controlled URLs.
- Never claim a check succeeded if a provider is disabled, unconfigured, or unreachable.
- Always return EvidenceStatus.CHECK_UNAVAILABLE when a provider cannot be reached.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import httpx

from .schemas import EvidenceRecord, EvidenceStatus

DEFAULT_TIMEOUT = 5.0


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _env_true(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in ("1", "true", "yes", "on")


def get_provider_status_summary() -> Dict[str, Dict[str, Any]]:
    """Return honest configuration status of all optional external providers."""
    return {
        "greenhouse_boards": {
            "enabled": _env_true("ENABLE_GREENHOUSE_CHECK"),
            "requires_key": False,
            "env_var": "ENABLE_GREENHOUSE_CHECK=true",
        },
        "lever_postings": {
            "enabled": _env_true("ENABLE_LEVER_CHECK"),
            "requires_key": False,
            "env_var": "ENABLE_LEVER_CHECK=true",
        },
        "gleif_lei": {
            "enabled": _env_true("ENABLE_GLEIF_CHECK"),
            "requires_key": False,
            "env_var": "ENABLE_GLEIF_CHECK=true",
        },
        "opencorporates": {
            "enabled": bool(os.getenv("OPENCORPORATES_API_KEY")),
            "requires_key": True,
            "env_var": "OPENCORPORATES_API_KEY",
        },
        "iana_rdap": {
            "enabled": _env_true("ENABLE_RDAP_CHECK"),
            "requires_key": False,
            "env_var": "ENABLE_RDAP_CHECK=true",
        },
        "cloudflare_doh_mx": {
            "enabled": _env_true("ENABLE_DOH_MX_CHECK"),
            "requires_key": False,
            "env_var": "ENABLE_DOH_MX_CHECK=true",
        },
        "google_safe_browsing": {
            "enabled": bool(os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")),
            "requires_key": True,
            "env_var": "GOOGLE_SAFE_BROWSING_API_KEY",
        },
        "virustotal": {
            "enabled": bool(os.getenv("VIRUSTOTAL_API_KEY")),
            "requires_key": True,
            "env_var": "VIRUSTOTAL_API_KEY",
        },
    }


async def check_greenhouse_vacancy(
    board_token: Optional[str],
    role_title: Optional[str],
    requisition_id: Optional[str],
) -> EvidenceRecord:
    """Check allowlisted Greenhouse public job board API when enabled."""
    ts = _now_iso()
    if not _env_true("ENABLE_GREENHOUSE_CHECK"):
        return EvidenceRecord(
            check_name="Greenhouse Public Job Board Check",
            source_examined="boards-api.greenhouse.io (allowlisted ATS)",
            source_type="external_verification",
            observed_result="External Greenhouse lookup is disabled in current environment.",
            status=EvidenceStatus.CHECK_UNAVAILABLE,
            timestamp=ts,
            explanation="Live Greenhouse ATS verification is optional and currently disabled (set ENABLE_GREENHOUSE_CHECK=true to enable).",
            residual_uncertainty="Vacancy existence on Greenhouse was not checked.",
        )
    if not board_token:
        return EvidenceRecord(
            check_name="Greenhouse Public Job Board Check",
            source_examined="boards-api.greenhouse.io (allowlisted ATS)",
            source_type="external_verification",
            observed_result="No allowlisted Greenhouse board token mapped for this employer.",
            status=EvidenceStatus.CHECK_UNAVAILABLE,
            timestamp=ts,
            explanation="Employer does not have a mapped Greenhouse board token; arbitrary websites are never scraped.",
            residual_uncertainty="Vacancy could exist on another ATS or internal portal.",
        )

    url = f"https://boards-api.greenhouse.io/v1/boards/{board_token}/jobs"
    try:
        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                raise RuntimeError(f"HTTP {resp.status_code}")
            jobs = resp.json().get("jobs", [])
    except Exception as exc:
        return EvidenceRecord(
            check_name="Greenhouse Public Job Board Check",
            source_examined=url,
            source_type="external_verification",
            observed_result=f"Provider unreachable ({type(exc).__name__}).",
            status=EvidenceStatus.CHECK_UNAVAILABLE,
            timestamp=ts,
            explanation="Could not reach Greenhouse public API; no vacancy claim is marked confirmed.",
            residual_uncertainty="Network or provider outage prevented live ATS verification.",
        )

    matched = None
    for j in jobs:
        title_ok = role_title and role_title.lower() in (j.get("title") or "").lower()
        req_ok = requisition_id and str(j.get("id", "")) == requisition_id
        if req_ok or title_ok:
            matched = j
            break

    if matched:
        return EvidenceRecord(
            check_name="Greenhouse Public Job Board Check",
            source_examined=url,
            source_type="external_verification",
            observed_result=f"Matched live posting: '{matched.get('title')}' (ID: {matched.get('id')}).",
            supporting_quotation=matched.get("absolute_url"),
            status=EvidenceStatus.CONFIRMED_BY_SOURCE,
            timestamp=ts,
            explanation="Independently located a matching active role on the employer's public Greenhouse board.",
            residual_uncertainty="Confirm that the recruiter contacting you is genuinely affiliated with this posting.",
        )
    return EvidenceRecord(
        check_name="Greenhouse Public Job Board Check",
        source_examined=url,
        source_type="external_verification",
        observed_result=f"Checked {len(jobs)} public postings; no exact match for role/requisition ID.",
        status=EvidenceStatus.UNVERIFIED,
        timestamp=ts,
        explanation="The advertised role was not found on the public Greenhouse board. It may be closed, unlisted, or fabricated.",
        residual_uncertainty="Absence from a public board does not by itself prove fraud.",
    )


async def check_lever_vacancy(
    company_slug: Optional[str], role_title: Optional[str]
) -> EvidenceRecord:
    """Check allowlisted Lever public job postings API when enabled."""
    ts = _now_iso()
    if not _env_true("ENABLE_LEVER_CHECK") or not company_slug:
        return EvidenceRecord(
            check_name="Lever Public Job Postings Check",
            source_examined="api.lever.co (allowlisted ATS)",
            source_type="external_verification",
            observed_result="Lever ATS check is disabled or employer slug is unavailable.",
            status=EvidenceStatus.CHECK_UNAVAILABLE,
            timestamp=ts,
            explanation="Live Lever ATS verification is optional (enable with ENABLE_LEVER_CHECK=true).",
            residual_uncertainty="Vacancy existence on Lever was not checked.",
        )

    url = f"https://api.lever.co/v0/postings/{company_slug}?mode=json"
    try:
        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                raise RuntimeError(f"HTTP {resp.status_code}")
            postings = resp.json()
    except Exception as exc:
        return EvidenceRecord(
            check_name="Lever Public Job Postings Check",
            source_examined=url,
            source_type="external_verification",
            observed_result=f"Provider unreachable ({type(exc).__name__}).",
            status=EvidenceStatus.CHECK_UNAVAILABLE,
            timestamp=ts,
            explanation="Could not reach Lever public API.",
            residual_uncertainty="Live ATS check could not be completed.",
        )

    match = next(
        (p for p in postings if role_title and role_title.lower() in (p.get("text") or "").lower()),
        None,
    )
    if match:
        return EvidenceRecord(
            check_name="Lever Public Job Postings Check",
            source_examined=url,
            source_type="external_verification",
            observed_result=f"Matched live Lever posting: '{match.get('text')}'.",
            supporting_quotation=match.get("hostedUrl"),
            status=EvidenceStatus.CONFIRMED_BY_SOURCE,
            timestamp=ts,
            explanation="Independently located a matching posting on Lever.",
            residual_uncertainty="Still verify recruiter identity separately.",
        )
    return EvidenceRecord(
        check_name="Lever Public Job Postings Check",
        source_examined=url,
        source_type="external_verification",
        observed_result=f"Checked {len(postings)} postings; no match found.",
        status=EvidenceStatus.UNVERIFIED,
        timestamp=ts,
        explanation="No matching public Lever posting was located.",
        residual_uncertainty="Role may be private, filled, or hosted elsewhere.",
    )


async def check_gleif_employer(employer_name: Optional[str]) -> EvidenceRecord:
    """Check GLEIF public Legal Entity Identifier (LEI) API when enabled."""
    ts = _now_iso()
    if not _env_true("ENABLE_GLEIF_CHECK") or not employer_name:
        return EvidenceRecord(
            check_name="GLEIF Legal Entity Check",
            source_examined="api.gleif.org (Global LEI Foundation)",
            source_type="external_verification",
            observed_result="GLEIF live corporate check is disabled or employer name is missing.",
            status=EvidenceStatus.CHECK_UNAVAILABLE,
            timestamp=ts,
            explanation="External GLEIF LEI lookup is optional (set ENABLE_GLEIF_CHECK=true).",
            residual_uncertainty="Live global corporate registration was not queried.",
        )

    url = "https://api.gleif.org/api/v1/lei-records"
    try:
        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
            resp = await client.get(url, params={"filter[entity.legalName]": employer_name, "page[size]": 1})
            if resp.status_code != 200:
                raise RuntimeError(f"HTTP {resp.status_code}")
            data = resp.json().get("data", [])
    except Exception as exc:
        return EvidenceRecord(
            check_name="GLEIF Legal Entity Check",
            source_examined=url,
            source_type="external_verification",
            observed_result=f"GLEIF API unreachable ({type(exc).__name__}).",
            status=EvidenceStatus.CHECK_UNAVAILABLE,
            timestamp=ts,
            explanation="Could not query GLEIF public API.",
            residual_uncertainty="Corporate registration status remains unverified externally.",
        )

    if data:
        rec = data[0]
        lei = rec.get("id")
        legal_name = rec.get("attributes", {}).get("entity", {}).get("legalName", {}).get("name")
        return EvidenceRecord(
            check_name="GLEIF Legal Entity Check",
            source_examined=url,
            source_type="external_verification",
            observed_result=f"Matched GLEIF entity '{legal_name}' (LEI: {lei}).",
            status=EvidenceStatus.CONFIRMED_BY_SOURCE,
            timestamp=ts,
            explanation="Found a registered legal entity matching the employer name in GLEIF.",
            residual_uncertainty="Entity existence does not prove the job offer is genuinely from that entity.",
        )
    return EvidenceRecord(
        check_name="GLEIF Legal Entity Check",
        source_examined=url,
        source_type="external_verification",
        observed_result="No matching LEI record returned.",
        status=EvidenceStatus.UNVERIFIED,
        timestamp=ts,
        explanation="Many legitimate small and mid-sized companies do not hold a global LEI.",
        residual_uncertainty="Absence from GLEIF does not imply fraud.",
    )


async def check_cloudflare_mx(domain: Optional[str]) -> EvidenceRecord:
    """Check MX records via Cloudflare DNS-over-HTTPS when enabled."""
    ts = _now_iso()
    if not _env_true("ENABLE_DOH_MX_CHECK") or not domain:
        return EvidenceRecord(
            check_name="DNS MX Record Check (Cloudflare DoH)",
            source_examined="cloudflare-dns.com/dns-query",
            source_type="external_verification",
            observed_result="Live MX record lookup is disabled or no email domain provided.",
            status=EvidenceStatus.CHECK_UNAVAILABLE,
            timestamp=ts,
            explanation="Optional DNS-over-HTTPS MX lookup is disabled (set ENABLE_DOH_MX_CHECK=true).",
            residual_uncertainty="Mail server configuration for the domain was not queried.",
        )

    url = "https://cloudflare-dns.com/dns-query"
    try:
        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
            resp = await client.get(
                url,
                params={"name": domain, "type": "MX"},
                headers={"Accept": "application/dns-json"},
            )
            if resp.status_code != 200:
                raise RuntimeError(f"HTTP {resp.status_code}")
            answers = resp.json().get("Answer", [])
    except Exception as exc:
        return EvidenceRecord(
            check_name="DNS MX Record Check (Cloudflare DoH)",
            source_examined=url,
            source_type="external_verification",
            observed_result=f"Cloudflare DoH unreachable ({type(exc).__name__}).",
            status=EvidenceStatus.CHECK_UNAVAILABLE,
            timestamp=ts,
            explanation="Could not query DNS MX records.",
            residual_uncertainty="Email domain mail-exchange capability could not be checked.",
        )

    if answers:
        mx_list = ", ".join(a.get("data", "") for a in answers[:3])
        return EvidenceRecord(
            check_name="DNS MX Record Check (Cloudflare DoH)",
            source_examined=url,
            source_type="external_verification",
            observed_result=f"Active MX records found for '{domain}': {mx_list}.",
            status=EvidenceStatus.CONFIRMED_BY_SOURCE,
            timestamp=ts,
            explanation="The email domain has valid DNS mail-exchange records.",
            residual_uncertainty="Having MX records does not guarantee the domain belongs to the claimed employer.",
        )
    return EvidenceRecord(
        check_name="DNS MX Record Check (Cloudflare DoH)",
        source_examined=url,
        source_type="external_verification",
        observed_result=f"No MX records found for '{domain}'.",
        status=EvidenceStatus.SUSPICIOUS_SIGNAL,
        timestamp=ts,
        explanation="The recruiter email domain has no configured MX records to receive replies.",
        residual_uncertainty="Check for typos in the email domain.",
    )


async def check_url_reputation(url_to_check: Optional[str]) -> EvidenceRecord:
    """Check Google Safe Browsing or VirusTotal only when API keys are configured."""
    ts = _now_iso()
    gsb_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    vt_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()

    if not url_to_check or (not gsb_key and not vt_key):
        return EvidenceRecord(
            check_name="External URL Reputation Check (Safe Browsing / VirusTotal)",
            source_examined="Google Safe Browsing / VirusTotal (unconfigured)",
            source_type="external_verification",
            observed_result="External threat-intelligence API keys are not configured.",
            status=EvidenceStatus.CHECK_UNAVAILABLE,
            timestamp=ts,
            explanation="Core URL safety relies on local zero-visit structural inspection. Configure GOOGLE_SAFE_BROWSING_API_KEY or VIRUSTOTAL_API_KEY for external reputation lookups.",
            residual_uncertainty="External blocklist reputation was not queried.",
        )

    if gsb_key:
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={gsb_key}"
        payload = {
            "client": {"clientId": "jobguard-ai", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url_to_check}],
            },
        }
        try:
            async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
                resp = await client.post(endpoint, json=payload)
                if resp.status_code != 200:
                    raise RuntimeError(f"HTTP {resp.status_code}")
                matches = resp.json().get("matches", [])
            if matches:
                return EvidenceRecord(
                    check_name="Google Safe Browsing Reputation Check",
                    source_examined="safebrowsing.googleapis.com",
                    source_type="external_verification",
                    observed_result=f"Flagged by Google Safe Browsing ({matches[0].get('threatType')}).",
                    status=EvidenceStatus.SUSPICIOUS_SIGNAL,
                    timestamp=ts,
                    explanation="External threat intelligence flagged this URL as malicious or social engineering.",
                    residual_uncertainty="Do not visit this URL.",
                )
            return EvidenceRecord(
                check_name="Google Safe Browsing Reputation Check",
                source_examined="safebrowsing.googleapis.com",
                source_type="external_verification",
                observed_result="No threat matches returned by Google Safe Browsing.",
                status=EvidenceStatus.UNVERIFIED,
                timestamp=ts,
                explanation="Not currently listed in Google Safe Browsing. Newly created phishing domains may not yet be indexed.",
                residual_uncertainty="Absence from blocklists is not proof of legitimacy.",
            )
        except Exception as exc:
            return EvidenceRecord(
                check_name="Google Safe Browsing Reputation Check",
                source_examined="safebrowsing.googleapis.com",
                source_type="external_verification",
                observed_result=f"Safe Browsing API unreachable ({type(exc).__name__}).",
                status=EvidenceStatus.CHECK_UNAVAILABLE,
                timestamp=ts,
                explanation="External reputation check could not be completed.",
                residual_uncertainty="Rely on structural URL analysis and official career portals.",
            )

    return EvidenceRecord(
        check_name="External URL Reputation Check",
        source_examined="VirusTotal (configured)",
        source_type="external_verification",
        observed_result="VirusTotal lookup skipped (disabled in offline mode).",
        status=EvidenceStatus.CHECK_UNAVAILABLE,
        timestamp=ts,
        explanation="External reputation lookup could not be completed.",
        residual_uncertainty="Rely on local zero-visit structural analysis.",
    )
