"""Privacy, PII redaction, input sanitization, safe file validation, and rate limiting."""
from __future__ import annotations

import html
import re
import time
from collections import defaultdict, deque
from typing import Deque, Dict, Tuple


# Sensitive data redaction patterns (India & global financial/identity identifiers)
REDACTION_PATTERNS = [
    (
        "aadhaar",
        re.compile(r"(?<!\d)(?:[2-9]\d{3}[\s-]\d{4}[\s-]\d{4}|[2-9]\d{11})(?!\d)"),
        "[REDACTED_AADHAAR]",
    ),
    (
        "pan",
        re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"),
        "[REDACTED_PAN]",
    ),
    (
        "ifsc",
        re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"),
        "[REDACTED_IFSC]",
    ),
    (
        "card_number",
        re.compile(r"(?<!\d)(?:\d{4}[\s-]){3}\d{4}(?!\d)"),
        "[REDACTED_CARD]",
    ),
    (
        "bank_account",
        re.compile(
            r"(?i)((?:a/c|acct|account)\s*(?:no\.?|number|#)?\s*[:=-]?\s*)\d{9,18}\b"
        ),
        r"\1[REDACTED_BANK_ACCOUNT]",
    ),
    (
        "otp_pin_cvv",
        re.compile(
            r"(?i)((?:otp|upi\s*pin|atm\s*pin|mpin|cvv|cvc|pin\s*(?:code|is|:))\s*(?:is|code|:|=|-)?\s*)\d{3,8}\b"
        ),
        r"\1[REDACTED_SECRET_CODE]",
    ),
    (
        "password",
        re.compile(r"(?i)((?:password|passcode|pwd)\s*(?:is|:|=)\s*)\S{3,40}"),
        r"\1[REDACTED_PASSWORD]",
    ),
]


def redact_sensitive_info(text: str) -> Tuple[str, Dict[str, int]]:
    """Automatically redact Aadhaar, PAN, IFSC, bank/card numbers, OTP/PIN/CVV, and passwords."""
    if not text:
        return "", {}
    redacted = text
    counts: Dict[str, int] = {}
    for label, pattern, replacement in REDACTION_PATTERNS:
        redacted, n = pattern.subn(replacement, redacted)
        if n > 0:
            counts[label] = n
    return redacted, counts


def sanitize_plain_text(value: str, max_len: int = 25000) -> str:
    """Strip null bytes and normalize control characters without corrupting Devanagari or punctuation."""
    if not value:
        return ""
    cleaned = value.replace("\x00", "").strip()
    cleaned = re.sub(r"[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]", "", cleaned)
    return cleaned[:max_len]


def escape_for_html(value: str) -> str:
    """Escape text for safe HTML rendering (XSS protection)."""
    return html.escape(value or "", quote=True)


ALLOWED_DOC_EXTENSIONS = {".pdf", ".docx", ".txt"}
MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB


def validate_upload_file(filename: str, size_bytes: int) -> Tuple[bool, str]:
    """Validate uploaded document extension and file size."""
    if not filename:
        return False, "Missing filename."
    lower = filename.lower()
    ext = "." + lower.rsplit(".", 1)[-1] if "." in lower else ""
    if ext not in ALLOWED_DOC_EXTENSIONS:
        return (
            False,
            f"Unsupported file format '{ext or 'unknown'}'. Supported formats: PDF, DOCX, TXT.",
        )
    if size_bytes <= 0:
        return False, "Uploaded file is empty."
    if size_bytes > MAX_UPLOAD_BYTES:
        return False, "File exceeds the 10 MB maximum upload size."
    return True, ext


class InMemoryRateLimiter:
    """Simple sliding-window in-memory rate limiter per client IP."""

    def __init__(self, max_requests: int = 60, window_seconds: int = 60) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._buckets: Dict[str, Deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> Tuple[bool, int]:
        now = time.time()
        bucket = self._buckets[key]
        cutoff = now - self.window_seconds
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) >= self.max_requests:
            retry_after = max(1, int(self.window_seconds - (now - bucket[0])))
            return False, retry_after
        bucket.append(now)
        return True, 0
