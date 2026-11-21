"""Optional AI Explanation Service — strictly grounded in verified report evidence.

Never invents findings, sources, company records, or successful verification checks.
Falls back cleanly to a deterministic plain-language explainer when no external LLM API key is configured.
"""
from __future__ import annotations

import os
from typing import List

from .schemas import (
    AIExplanation,
    DetectionIndicator,
    EvidenceCategoryReport,
    EvidenceStatus,
    RiskLevel,
)


def generate_grounded_explanation(
    risk_level: RiskLevel,
    risk_index: int,
    indicators: List[DetectionIndicator],
    categories: List[EvidenceCategoryReport],
    what_could_not_be_verified: List[str],
    interface_language: str = "en",
) -> AIExplanation:
    """Translate structured evidence into clear, plain-language advice without inventing facts."""
    # Optional external LLM key check (never exposed to frontend; core works offline without it)
    llm_configured = bool(os.getenv("OPENAI_API_KEY") or os.getenv("GEMINI_API_KEY"))

    suspicious_cats = [
        c.category_name
        for c in categories
        if c.overall_status in (EvidenceStatus.SUSPICIOUS_SIGNAL, EvidenceStatus.INCONSISTENT)
    ]
    confirmed_cats = [
        c.category_name
        for c in categories
        if c.overall_status == EvidenceStatus.CONFIRMED_BY_SOURCE
    ]

    is_hi = interface_language == "hi"

    if risk_level == RiskLevel.HIGH:
        summary = (
            f"उच्च जोखिम ({risk_index}/100): {len(indicators)} गंभीर चेतावनी संकेत पाए गए हैं "
            f"({', '.join(suspicious_cats[:3]) or 'भर्ती धोखाधड़ी पैटर्न'})। किसी भी प्रकार का शुल्क या ओटीपी/पिन साझा न करें।"
            if is_hi
            else (
                f"High Risk ({risk_index}/100 heuristic index): JobGuard AI identified {len(indicators)} "
                f"serious warning signal(s) affecting {', '.join(suspicious_cats[:3]) or 'recruitment safety'}. "
                "Do not pay any fee, click unverified career links, or share sensitive personal/banking codes."
            )
        )
    elif risk_level == RiskLevel.MEDIUM:
        summary = (
            f"मध्यम जोखिम ({risk_index}/100): कुछ संदिग्ध संकेत या असत्यापित जानकारी मिली है। "
            "कंपनी की आधिकारिक वेबसाइट से स्वतंत्र पुष्टि किए बिना आगे न बढ़ें।"
            if is_hi
            else (
                f"Medium Risk ({risk_index}/100 heuristic index): This opportunity contains concerning signals "
                "or important unverified details. Independently verify the employer and vacancy before sharing documents or attending."
            )
        )
    else:
        summary = (
            f"कम जोखिम ({risk_index}/100): कोई मजबूत धोखाधड़ी संकेत नहीं मिला, लेकिन स्वचालित जांच 100% वैधता की गारंटी नहीं देती।"
            if is_hi
            else (
                f"Low Risk ({risk_index}/100 heuristic index): No strong recruitment-fraud signals were detected in the submitted material. "
                + (
                    f"Confirmed checks: {', '.join(confirmed_cats)}. "
                    if confirmed_cats
                    else "However, key details remain unverified—absence of red flags is not proof of legitimacy."
                )
            )
        )

    advice: List[str] = []
    if indicators:
        for ind in indicators[:3]:
            advice.append(ind.suggested_action)
    if not advice:
        advice = [
            "Cross-check the job opening on the company's official career portal typed manually in your browser.",
            "Never pay registration, training, or security deposit fees at any stage of hiring.",
            "Confirm recruiter identity via an official corporate email address and LinkedIn presence.",
        ]

    uncertainty_note = (
        f"{len(what_could_not_be_verified)} verification area(s) could not be independently confirmed "
        "(including live ATS/corporate checks when optional external providers are disabled)."
        if what_could_not_be_verified
        else "All available checks were evaluated; always verify offer letters directly with the employer."
    )

    return AIExplanation(
        provider=(
            "deterministic_evidence_explainer (external LLM key present but offline-safe local grounding used)"
            if llm_configured
            else "deterministic_evidence_explainer (local, zero external API required)"
        ),
        used_external_llm=False,
        summary=summary,
        plain_language_advice=list(dict.fromkeys(advice)),
        uncertainty_note=uncertainty_note,
    )
