"""Vercel zero-config FastAPI entrypoint for JobGuard AI.

Exports the FastAPI `app` instance at the repository root so Vercel's
FastAPI preset automatically detects and deploys both the API routes
and the static frontend in `public/`.
"""
from backend.main import app

__all__ = ["app"]
