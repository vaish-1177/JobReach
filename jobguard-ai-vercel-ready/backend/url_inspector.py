"""Layer F: Zero-visit structural URL and domain security inspection engine.

Never automatically opens or fetches user-submitted URLs.
Specifically detects fake company career portals and lookalike recruitment domains.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .schemas import RiskLevel, Severity, URLInspectionResult, URLSignal

MULTI_PART_TLDS = {
    "co.in", "gov.in", "nic.in", "ac.in", "org.in", "net.in", "res.in", "edu.in",
    "co.uk", "org.uk", "com.au", "co.jp", "com.sg", "com.br", "co.nz",
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "loan", "work", "gq", "tk", "ml", "cf", "ga",
    "buzz", "icu", "vip", "monster", "shop", "live", "online", "site", "club", "win",
}

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "rb.gy", "cutt.ly",
    "shorturl.at", "tiny.cc", "ow.ly", "rebrand.ly", "lnkd.in", "wa.me",
}

# Protected major employers & recruitment platforms for brand impersonation checks
PROTECTED_EMPLOYER_BRANDS: Dict[str, List[str]] = {
    "infosys": ["infosys.com"],
    "tcs": ["tcs.com"],
    "wipro": ["wipro.com"],
    "hcltech": ["hcltech.com"],
    "hcl": ["hcltech.com", "hcl.com"],
    "accenture": ["accenture.com"],
    "cognizant": ["cognizant.com"],
    "capgemini": ["capgemini.com"],
    "techmahindra": ["techmahindra.com"],
    "google": ["google.com", "careers.google.com", "abc.xyz"],
    "microsoft": ["microsoft.com", "careers.microsoft.com"],
    "amazon": ["amazon.jobs", "amazon.com", "amazon.in"],
    "meta": ["metacareers.com", "meta.com"],
    "flipkart": ["flipkartcareers.com", "flipkart.com"],
    "zoho": ["zohocorp.com", "zoho.com"],
    "deloitte": ["deloitte.com"],
    "pwc": ["pwc.com", "pwc.in"],
    "kpmg": ["kpmg.com"],
    "ey": ["ey.com"],
    "ibm": ["ibm.com"],
    "oracle": ["oracle.com"],
    "razorpay": ["razorpay.com"],
    "swiggy": ["swiggy.com"],
    "zomato": ["zomato.com"],
    "paytm": ["paytm.com"],
    "reliance": ["ril.com", "jio.com"],
    "jio": ["jio.com", "ril.com"],
    "tata": ["tata.com", "tcs.com", "tatamotors.com"],
    "linkedin": ["linkedin.com"],
    "naukri": ["naukri.com"],
    "internshala": ["internshala.com"],
    "indeed": ["indeed.com", "indeed.co.in"],
    "greenhouse": ["greenhouse.io"],
    "lever": ["lever.co"],
}

RECRUITMENT_PHISHING_TERMS = [
    "career", "careers", "jobs", "hire", "hiring", "recruit", "recruitment",
    "verify", "verification", "offer", "onboarding", "register", "registration",
    "apply", "portal", "hr", "interview", "login", "signin", "kyc", "fee", "deposit",
]

URL_EXTRACT_REGEX = re.compile(
    r"(?:https?://|www\.)[^\s<>\"'\)\]]+"
    r"|\b(?:[a-zA-Z0-9-]+\.)+(?:in|com|org|net|io|co|xyz|top|click|icu|vip|online|site|live|shop|info|jobs|co\.in|gov\.in|ly|at|gy|cc|me)(?:/[^\s<>\"'\)\]]*)?",
    re.IGNORECASE,
)


def extract_urls_from_text(text: str, limit: int = 10) -> List[str]:
    """Extract unique URLs from text without visiting them."""
    if not text:
        return []
    found: List[str] = []
    seen = set()
    for match in URL_EXTRACT_REGEX.finditer(text):
        raw = match.group(0).rstrip(".,;:!?'\"])}")
        # Skip email domains accidentally matched (preceded by @)
        if match.start() > 0 and text[match.start() - 1] == "@":
            continue
        key = raw.lower()
        if raw and key not in seen:
            seen.add(key)
            found.append(raw)
        if len(found) >= limit:
            break
    return found


def extract_registrable_domain(hostname: str) -> Tuple[str, List[str]]:
    """Return (registrable_domain, list_of_subdomains)."""
    host = (hostname or "").lower().strip(".")
    if not host:
        return "", []
    try:
        ipaddress.ip_address(host)
        return host, []
    except ValueError:
        pass
    parts = host.split(".")
    if len(parts) < 2:
        return host, []
    last_two = ".".join(parts[-2:])
    if last_two in MULTI_PART_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:]), parts[:-3]
    return last_two, parts[:-2]


def _is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def inspect_url_structurally(raw_url: str) -> URLInspectionResult:
    """Zero-visit structural inspection of a recruitment or job URL."""
    submitted = (raw_url or "").strip()
    lower_sub = submitted.lower()

    if lower_sub.startswith(("javascript:", "data:", "vbscript:", "file:")):
        scheme = lower_sub.split(":", 1)[0]
        return URLInspectionResult(
            submitted_url=submitted,
            normalized_url=submitted,
            hostname="",
            registrable_domain="",
            subdomains=[],
            scheme=scheme,
            is_https=False,
            is_ip_address=False,
            is_shortened=False,
            has_punycode_or_idn=False,
            subdomain_count=0,
            risk_level=RiskLevel.HIGH,
            risk_index=95,
            summary="Executable or non-web URI scheme detected. Never open or paste this link into a browser.",
            signals=[
                URLSignal(
                    signal="dangerous_uri_scheme",
                    severity=Severity.CRITICAL,
                    explanation=f"Uses an unsafe '{scheme}:' URI scheme that can execute scripts or access local files.",
                )
            ],
            recommended_actions=[
                "Do not click or paste this address into your browser.",
                "Report the message as a phishing attempt.",
            ],
            limitations=["Evaluated structurally without visiting the URL."],
        )

    with_scheme = submitted if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", submitted) else f"http://{submitted}"
    parsed = urlparse(with_scheme)
    raw_host = (parsed.hostname or "").lower().strip(".")

    if not raw_host or ("." not in raw_host and not _is_ip_address(raw_host)):
        return URLInspectionResult(
            submitted_url=submitted,
            normalized_url=with_scheme,
            hostname=raw_host,
            registrable_domain=raw_host,
            subdomains=[],
            scheme=parsed.scheme or "invalid",
            is_https=parsed.scheme == "https",
            is_ip_address=False,
            is_shortened=False,
            has_punycode_or_idn=False,
            subdomain_count=0,
            risk_level=RiskLevel.HIGH,
            risk_index=80,
            summary="Malformed or non-standard recruitment URL structure.",
            signals=[
                URLSignal(
                    signal="malformed_url",
                    severity=Severity.HIGH,
                    explanation="The submitted link does not resolve to a valid standard hostname.",
                )
            ],
            recommended_actions=["Do not open malformed links; verify the job on the employer's official career site."],
            limitations=["Evaluated structurally without visiting the URL."],
        )

    scheme = (parsed.scheme or "http").lower()
    is_https = scheme == "https"
    is_ip = _is_ip_address(raw_host)
    has_idn = ("xn--" in raw_host) or any(ord(ch) > 127 for ch in raw_host)
    reg_domain, subdomains = extract_registrable_domain(raw_host)
    sub_count = len(subdomains)
    is_shortened = reg_domain in KNOWN_SHORTENERS

    signals: List[URLSignal] = []
    points = 0

    if parsed.username or parsed.password or "@" in (parsed.netloc or ""):
        points += 42
        signals.append(
            URLSignal(
                signal="embedded_credentials_in_url",
                severity=Severity.HIGH,
                explanation="Contains '@' in the URL authority section, a technique used to disguise the real destination domain.",
            )
        )

    if is_ip:
        points += 45
        signals.append(
            URLSignal(
                signal="raw_ip_address",
                severity=Severity.HIGH,
                explanation="Uses a raw numeric IP address instead of a registered corporate domain.",
            )
        )

    if has_idn:
        points += 38
        signals.append(
            URLSignal(
                signal="punycode_or_idn_homograph",
                severity=Severity.HIGH,
                explanation="Contains Punycode ('xn--') or non-ASCII internationalized characters that can impersonate trusted letters.",
            )
        )

    if not is_https:
        points += 14
        signals.append(
            URLSignal(
                signal="unencrypted_http",
                severity=Severity.MEDIUM,
                explanation="Uses unencrypted HTTP instead of HTTPS. Note that HTTPS alone also does not prove a career site is legitimate.",
            )
        )

    if len(raw_host) > 40:
        points += 20
        signals.append(
            URLSignal(
                signal="excessively_long_hostname",
                severity=Severity.MEDIUM,
                explanation=f"Hostname is unusually long ({len(raw_host)} chars), often used to push the true domain off mobile screens.",
            )
        )

    if sub_count >= 3:
        points += 22
        signals.append(
            URLSignal(
                signal="excessive_subdomains",
                severity=Severity.MEDIUM,
                explanation=f"Uses {sub_count} subdomain levels ({'.'.join(subdomains)}) before the actual registrable domain '{reg_domain}'.",
            )
        )

    dom_label = reg_domain.split(".")[0] if reg_domain else ""
    if dom_label.count("-") >= 2 or (dom_label.count("-") >= 1 and any(k in dom_label for k in ("career", "verify", "hire", "job", "hr", "offer"))):
        points += 22
        signals.append(
            URLSignal(
                signal="lookalike_hyphenated_domain",
                severity=Severity.MEDIUM,
                explanation=f"Registrable domain '{reg_domain}' combines hyphens with recruitment/verification words typical of lookalike portals.",
            )
        )

    tld = reg_domain.rsplit(".", 1)[-1] if "." in reg_domain else ""
    if tld in SUSPICIOUS_TLDS:
        points += 26
        signals.append(
            URLSignal(
                signal="suspicious_tld",
                severity=Severity.MEDIUM,
                explanation=f"Uses the '.{tld}' top-level domain frequently abused in disposable fake career portals.",
            )
        )

    if is_shortened:
        points += 24
        signals.append(
            URLSignal(
                signal="url_shortener",
                severity=Severity.MEDIUM,
                explanation=f"Uses URL shortener '{reg_domain}' which conceals the true destination domain.",
            )
        )

    # Check brand impersonation (e.g., infosys.careers-verification.xyz or tcs-hr-portal.top)
    impersonated_brand: Optional[str] = None
    official_domains: List[str] = []
    full_host_and_path = f"{raw_host}{parsed.path}".lower()
    # Normalize tokens to avoid false positives like 'ey' inside 'survey'
    host_tokens = set(re.split(r"[^a-z0-9]+", raw_host))
    path_tokens = set(re.split(r"[^a-z0-9]+", (parsed.path or "").lower()))
    all_tokens = host_tokens | path_tokens

    for brand, domains in PROTECTED_EMPLOYER_BRANDS.items():
        matched_brand = (brand in all_tokens) if len(brand) <= 3 else (brand in full_host_and_path)
        if matched_brand and reg_domain not in domains:
            impersonated_brand = brand.upper()
            official_domains = domains
            points += 52
            signals.append(
                URLSignal(
                    signal="employer_brand_impersonation",
                    severity=Severity.CRITICAL,
                    explanation=(
                        f"References '{brand.upper()}' in the URL, but the actual registrable domain is "
                        f"'{reg_domain}' rather than an official domain ({', '.join(domains)})."
                    ),
                )
            )
            break

    is_known_official = any(reg_domain in doms for doms in PROTECTED_EMPLOYER_BRANDS.values())

    # Suspicious login/verification/application path keywords on unverified domains
    path_and_sub = f"{' '.join(subdomains)} {parsed.path}".lower()
    matched_terms = [t for t in RECRUITMENT_PHISHING_TERMS if re.search(rf"\b{t}\b", path_and_sub)]
    if matched_terms and not is_known_official and (points > 0 or len(matched_terms) >= 2):
        points += min(24, 10 * len(matched_terms))
        signals.append(
            URLSignal(
                signal="suspicious_recruitment_path",
                severity=Severity.MEDIUM if len(matched_terms) == 1 else Severity.HIGH,
                explanation=(
                    f"Contains recruitment/verification terms ({', '.join(matched_terms[:4])}) "
                    f"on unverified domain '{reg_domain}'."
                ),
            )
        )

    if parsed.query and re.search(r"(redirect|url=|next=|return=|token=|otp=|session=|ref=http)", parsed.query, re.I):
        points += 18
        signals.append(
            URLSignal(
                signal="suspicious_redirect_parameters",
                severity=Severity.MEDIUM,
                explanation=f"Query string contains redirect or session parameters ('{parsed.query[:60]}').",
            )
        )

    risk_index = min(98, max(5, points))
    if risk_index >= 60 or impersonated_brand is not None:
        risk_level = RiskLevel.HIGH
        summary = (
            f"High-risk structural indicators detected on '{reg_domain}'. "
            + (
                f"This URL appears to impersonate {impersonated_brand} (official: {', '.join(official_domains)}). "
                if impersonated_brand
                else ""
            )
            + "Do not open or submit personal details on this link."
        )
    elif risk_index >= 25:
        risk_level = RiskLevel.MEDIUM
        summary = (
            f"Structural warning signs found on '{reg_domain}'. "
            "Verify the employer's official career portal independently before clicking."
        )
    else:
        risk_level = RiskLevel.LOW
        summary = (
            f"No strong structural phishing signals detected in '{reg_domain}'. "
            "Structural inspection alone cannot guarantee the site is legitimate."
        )

    rec_actions = (
        [
            f"Do not open or enter personal details on '{reg_domain}'.",
            (
                f"Visit {impersonated_brand}'s official careers page manually via {official_domains[0]}."
                if impersonated_brand and official_domains
                else "Navigate manually to the company's official website to verify the job opening."
            ),
            "Never pay registration fees or submit Aadhaar/PAN/banking credentials on unverified portals.",
        ]
        if risk_level == RiskLevel.HIGH
        else [
            "Confirm the domain matches the employer's verified corporate website before applying.",
            "Remember that an HTTPS padlock only encrypts transit—it does not verify company legitimacy.",
        ]
    )

    return URLInspectionResult(
        submitted_url=submitted,
        normalized_url=parsed.geturl(),
        hostname=raw_host,
        registrable_domain=reg_domain,
        subdomains=subdomains,
        scheme=scheme,
        is_https=is_https,
        is_ip_address=is_ip,
        is_shortened=is_shortened,
        has_punycode_or_idn=has_idn,
        subdomain_count=sub_count,
        impersonated_brand=impersonated_brand,
        official_domains=official_domains,
        risk_level=risk_level,
        risk_index=risk_index,
        summary=summary,
        signals=signals,
        reputation_status="Check Unavailable",
        reputation_provider="none (local zero-visit structural inspection)",
        recommended_actions=rec_actions,
        limitations=[
            "Zero-visit inspection: JobGuard AI never automatically opens or fetches arbitrary user-submitted URLs.",
            "HTTPS presence does not prove a recruitment portal is genuine.",
            "Newly registered phishing domains may not yet appear in external reputation feeds.",
        ],
    )
