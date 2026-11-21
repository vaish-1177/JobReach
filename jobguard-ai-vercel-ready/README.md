# JobGuard AI — Evidence-Based Job & Recruitment Verification Platform

**Tagline:** *Before You Trust the Offer, Verify the Evidence.*

JobGuard AI is an evidence-first recruitment fraud verification platform designed to protect college students, fresh graduates, internship seekers, experienced job seekers, work-from-home applicants, and freelancers across WhatsApp, Telegram, email, LinkedIn, and job portals.

## Deploy to Vercel via GitHub (Zero Config)

This repository is pre-configured for one-click full-stack deployment on Vercel using the official FastAPI preset (`main.py` + root `requirements.txt` + `vercel.json` + CDN-served `public/index.html`):

1. **Push the project to GitHub** (ensure `main.py`, `requirements.txt`, `vercel.json`, `public/index.html`, and `backend/` are at the repository root — not nested inside an extra `jobguard-ai/` folder).
2. Open [Vercel New Project](https://vercel.com/new) and import your GitHub repository.
3. Keep **Root Directory** set to `.` (default), **Framework Preset** as **FastAPI** (auto-detected), and leave **Build Command** and **Output Directory** empty.
4. Click **Deploy**.
   - Your UI loads from `public/index.html` on Vercel's CDN (`https://<your-project>.vercel.app/`).
   - Your live FastAPI backend handles `/api/health`, `/api/extract`, `/api/extract/document`, `/api/inspect-url`, `/api/verify`, `/api/providers/status`, `/api/ml/info`, and `/docs`.
   - Zero environment variables are required for core verification; optional provider keys from `.env.example` can be added in **Project Settings → Environment Variables**.

## Architecture Overview

- **Vercel Entrypoint (`main.py`, `requirements.txt`, `vercel.json`, `public/index.html`)**: Exports `backend.main:app` for Vercel Functions and serves the calibrated v2.0 production frontend from `public/`.
- **Backend (`backend/`)**: Python 3.11+ + FastAPI + Pydantic v2
  - `analyzer.py`: Multilingual (English, Hindi, Hinglish) deterministic recruitment-fraud rule engine with negation and context awareness + cross-document consistency checker.
  - `extractor.py`: Pre-Analysis 10-field structured extractor (Employer, Role, Salary, Recruiter Email, Phone, Location, Job URL, Requisition ID, Payment Requests, Deadlines) with confidence scores, exact supporting snippets, and PDF/DOCX/TXT document extraction.
  - `url_inspector.py`: Zero-visit structural URL & domain security inspector (registrable domain, subdomains, Punycode/IDN, raw IP, suspicious TLDs, shorteners, embedded credentials, redirect parameters, and fake company career portal / brand impersonation detection).
  - `verification.py`: Curated, explainable employer reference registry and recruiter email/domain alignment checks (unknown companies are marked `Unverified`, never automatically fraudulent).
  - `evidence_engine.py`: Seven-Category Evidence-Based Verification Report assembler (`Confirmed by Source`, `Inconsistent`, `Suspicious Signal`, `Unverified`, `Check Unavailable`) and explainable heuristic risk index (0–100).
  - `providers.py`: Optional environment-variable-gated external verification providers (Greenhouse, Lever, GLEIF, OpenCorporates, IANA RDAP, Cloudflare DoH MX, Google Safe Browsing, VirusTotal).
  - `ml_classifier.py`: Pure-Python reproducible TF-IDF + L2 Logistic Regression secondary classifier with transparent held-out evaluation and explicit synthetic dataset disclosure.
  - `ai_explainer.py`: Strictly evidence-grounded plain-language explanation layer (never fabricates findings; works offline without API keys).
  - `security.py`: Automatic redaction of Aadhaar, PAN, IFSC, bank/card numbers, OTP/PIN/CVV, and passwords; XSS escaping; upload validation; and sliding-window rate limiting.
- **Frontend (`frontend/`)**:
  - Modular React + TypeScript + Vite + Tailwind CSS source in `frontend/src/` (with `localEngine.d.ts` and `frontend/vercel.json` if deploying `frontend/` standalone).
  - Pre-built production SPA bundle in `public/index.html` and `frontend/dist/index.html`.
- **Optional Database (`supabase/schema.sql`)**:
  - PostgreSQL + Supabase Auth + Row Level Security (RLS) for explicit opt-in report saving. Core local verification works without any account or database.

## Quick Start Locally (Zero API Keys Required)

### 1. Run Backend + Production Frontend (FastAPI)

```bash
pip install -r backend/requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000
```

Open **http://localhost:8000** in your browser. Interactive API docs are available at **http://localhost:8000/docs**.

### 2. Optional: Run Vite Frontend Dev Server

```bash
cd frontend
npm install
npm run dev
```

### 3. Run Automated Tests

```bash
# Backend & Vercel deployment readiness test suite
python3 -m unittest discover -s tests -v

# Frontend detection, redaction, and export test suite (Node.js 18+)
node --test tests/test_frontend.mjs
```

## Optional External Providers

Copy `.env.example` to `.env` (or add variables in Vercel **Project Settings → Environment Variables**) to enable optional external providers. All integrations are disabled by default and honestly report `Check Unavailable` when disabled or unreachable. Never expose `SUPABASE_SERVICE_ROLE_KEY` or private LLM API keys to the frontend.

## Limitations & Transparency

- The 0–100 Risk Index is an explainable heuristic score, not a mathematically calibrated probability of fraud.
- Absence of suspicious keywords does not prove a job opportunity is legitimate.
- JobGuard AI never automatically opens or fetches arbitrary user-submitted URLs.
- External ATS, corporate, DNS, and threat-intelligence checks require explicit opt-in and network access.
