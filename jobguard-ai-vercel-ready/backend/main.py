"""JobGuard AI FastAPI Backend Application.

Provides structured REST API endpoints for:
- 10-field pre-analysis extraction (text & URL)
- PDF, DOCX, and TXT document extraction with PII redaction
- Full 7-category evidence-based verification
- Zero-visit URL & domain security inspection
- Provider & ML classifier transparency metadata
- Serving the production frontend SPA from public/index.html or frontend/dist/index.html
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Dict

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response

from .evidence_engine import build_verification_report
from .extractor import extract_structured_job_data, extract_text_from_document_bytes
from .ml_classifier import get_ml_metadata
from .providers import get_provider_status_summary
from .schemas import (
    DocumentExtractionResponse,
    ExtractedJobData,
    ExtractRequest,
    URLInspectionResult,
    URLInspectRequest,
    VerificationReport,
    VerifyRequest,
)
from .security import (
    InMemoryRateLimiter,
    redact_sensitive_info,
    sanitize_plain_text,
    validate_upload_file,
)
from .url_inspector import inspect_url_structurally

app = FastAPI(
    title="JobGuard AI — Evidence-Based Job & Recruitment Verification API",
    description="Before You Trust the Offer, Verify the Evidence.",
    version="1.0.0",
)

allowed_origins = os.getenv("CORS_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in allowed_origins if o.strip()],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

rate_limiter = InMemoryRateLimiter(max_requests=120, window_seconds=60)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
FRONTEND_CANDIDATES = (
    PROJECT_ROOT / "public" / "index.html",
    PROJECT_ROOT / "frontend" / "dist" / "index.html",
)


@app.middleware("http")
async def security_and_rate_limit_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "local"
    if request.url.path.startswith("/api/"):
        allowed, retry_after = rate_limiter.allow(client_ip)
        if not allowed:
            return JSONResponse(
                status_code=429,
                content={"detail": f"Rate limit exceeded. Retry after {retry_after}s."},
                headers={"Retry-After": str(retry_after)},
            )
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


@app.get("/api/health")
async def health_check() -> Dict[str, object]:
    return {
        "status": "ok",
        "service": "JobGuard AI",
        "tagline": "Before You Trust the Offer, Verify the Evidence.",
        "local_mode_ready": True,
        "providers": get_provider_status_summary(),
    }


@app.get("/api/providers/status")
async def providers_status() -> Dict[str, object]:
    return {
        "providers": get_provider_status_summary(),
        "note": "All external providers are optional. Core verification runs locally without API keys.",
    }


@app.get("/api/ml/info")
async def ml_info() -> Dict[str, object]:
    return get_ml_metadata()


@app.post("/api/extract", response_model=ExtractedJobData)
async def extract_fields_endpoint(payload: ExtractRequest) -> ExtractedJobData:
    clean_text = sanitize_plain_text(payload.text)
    if not clean_text and not (payload.job_url and payload.job_url.strip()):
        raise HTTPException(status_code=400, detail="Provide job text or a job URL to extract fields.")
    return extract_structured_job_data(
        clean_text, job_url=payload.job_url, language_hint=payload.language_hint
    )


@app.post("/api/extract/document", response_model=DocumentExtractionResponse)
async def extract_document_endpoint(file: UploadFile = File(...)) -> DocumentExtractionResponse:
    content = await file.read()
    valid, result = validate_upload_file(file.filename or "", len(content))
    if not valid:
        raise HTTPException(status_code=400, detail=result)

    try:
        raw_text, file_type, warnings = extract_text_from_document_bytes(
            file.filename or "upload.txt", content
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    clean_text = sanitize_plain_text(raw_text)
    redacted_text, redaction_counts = redact_sensitive_info(clean_text)
    extracted = extract_structured_job_data(clean_text)

    return DocumentExtractionResponse(
        filename=file.filename or "document",
        file_type=file_type,
        extracted_text=clean_text,
        redacted_text=redacted_text,
        redaction_counts=redaction_counts,
        warnings=warnings,
        extracted_fields=extracted,
    )


@app.post("/api/inspect-url", response_model=URLInspectionResult)
async def inspect_url_endpoint(payload: URLInspectRequest) -> URLInspectionResult:
    return inspect_url_structurally(payload.url)


@app.post("/api/verify", response_model=VerificationReport)
async def verify_job_endpoint(payload: VerifyRequest) -> VerificationReport:
    if not (payload.text and payload.text.strip()) and not (payload.job_url and payload.job_url.strip()):
        raise HTTPException(
            status_code=400,
            detail="Please provide job advertisement text, recruiter message, or a job URL to verify.",
        )
    return await build_verification_report(payload)


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return Response(status_code=204)


@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    for candidate in FRONTEND_CANDIDATES:
        if candidate.exists():
            return FileResponse(candidate)
    return HTMLResponse(
        "<h1>JobGuard AI Backend Running</h1><p>API docs available at <a href='/docs'>/docs</a>.</p>"
    )
