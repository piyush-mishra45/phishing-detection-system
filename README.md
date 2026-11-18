# PhishGuard - AI-Based Phishing Email & Website Detection System

Full-stack cybersecurity app: **Flask + scikit-learn + SQLAlchemy/MySQL** backend and **React + Tailwind + Recharts** frontend.
It analyses emails (pasted text or `.eml`) and URLs, explains *why* something is risky, stores scan history and shows analytics.

> **Read this first - verification status.** The project was assembled in a sandbox with no internet access.
> What was actually executed there vs. what you must run yourself is listed in [Verification status](#verification-status).
> The bundled ML models are trained on **synthetic demo data** - retrain on real data before trusting any verdict.

## Features
* **Email scanner** - paste text or upload `.eml`; keyword groups, sender spoofing / look-alike / display-name checks, Reply-To & Return-Path mismatch, SPF/DKIM/DMARC from headers (missing => *unknown*, never "pass"), link analysis (never visited), attachment *names* only, TF-IDF ML.
* **Website scanner** - URL lexical analysis, SSL/TLS, DNS (A/AAAA/MX/NS/TXT), domain age (RDAP), redirect chain, static HTML analysis (credential forms, hidden iframes, suspicious JS *patterns*, external links, metadata), ML on URL features.
* **Risk engine** - `score = 0.5 x calibrated ML probability + 0.5 x heuristic score` (whole number 0-100; bands 0-30 Low, 31-60 Medium, 61-80 High, 81-100 Critical). *Model confidence* is reported separately. Unavailable checks are listed as **unknown** and never counted as safe.
* **Verdicts** - emails: PHISHING / SUSPICIOUS / LEGITIMATE; websites: PHISHING / SUSPICIOUS / SAFE / UNKNOWN. "SAFE" means "no strong indicators found", never a guarantee; HTTPS alone is never treated as proof of safety.
* **Accounts** - registration, login/logout (JWT, revocable), scrypt password hashing, roles (user/admin), admin dashboard.
* **Dashboard, analytics, history** - totals, 7-day and monthly charts, search/filter by date/type/threat level, per-scan reports, CSV export (formula-injection safe).

## Safety design (website scanning)
Never executes JavaScript - never submits forms - 8 s read timeout, 1 MB body cap, max 5 redirects, ports 80/443/8080/8443 only.
**SSRF protection:** every hostname is resolved and *all* addresses must be globally routable (blocks localhost, RFC1918, link-local/cloud metadata `169.254.x`, CGNAT, multicast, IPv4-mapped IPv6, NAT64/6to4, decimal/hex/octal IP tricks). The connection is **pinned** to the validated IP (anti DNS-rebinding) and **each redirect hop is re-validated**.
Privacy: only a 500-char excerpt with e-mail addresses/phone numbers redacted is stored for emails.

## Project structure
```
backend/   Flask API (app/routes, services, security, ml, models, database), training scripts, run.py
frontend/  React + Vite + Tailwind (pages, components, charts, hooks, services)
datasets/  synthetic demo CSVs + README on real datasets     models/  trained .pkl + metrics.json
database/  schema.sql (MySQL 8)    tests/  pytest suites    docs/  API.md, DEPLOYMENT.md    render.yaml
```

## Installation
Requirements: Python 3.11+, Node 18+, (production) MySQL 8.

```bash
# 1. Backend
python -m venv .venv && source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                                      # edit SECRET_KEY, DATABASE_URL, ADMIN_EMAIL
# MySQL (optional in dev - without DATABASE_URL a local SQLite file is used):
#   mysql -u root -p < database/schema.sql   (tables are also auto-created on first start)
cd backend && python run.py                                # http://127.0.0.1:5000/api/health

# 2. Train models (see datasets/README.md for real data; otherwise synthetic demo data is used with a loud warning)
cd backend && python train_email_model.py && python train_website_model.py   # restart the API afterwards

# 3. Frontend (new terminal)
cd frontend && npm install && npm run dev                  # http://localhost:5173 (proxies /api to :5000)
```
Register at `/register` using the email set as `ADMIN_EMAIL` to get an admin account.

## Testing
```bash
pip install -r requirements.txt && pytest                  # from the project root
cd frontend && npm test                                    # vitest
```
| Suite | Covers |
|---|---|
| `tests/test_security.py` | SSRF blocklist (13 private/obfuscated targets), malformed URLs, password policy, CSV injection, PII redaction |
| `tests/test_analysis.py` | URL features on malformed input, brand/typosquat detection, risk bands, unknown-never-safe, e-mail + `.eml` header parsing, HTML analysis, unreachable & private targets |
| `tests/test_fetch_local.py` | redirects, response-size cap, redirect loops (local test server) |
| `tests/test_ml.py` | model probabilities in range, sane ranking (needs trained models) |
| `tests/test_api.py` | auth, revoked tokens, hashing, scans, privacy minimisation, history filters/search/export, **IDOR protection**, RBAC, rate limiting, cascades |
| `frontend/src/__tests__` | risk bands, verdict badges, unknown rendering, gauge accessibility |

For manual end-to-end security testing also try: legitimate sites (`https://www.python.org`), known phishing samples from PhishTank *(do not visit them in a browser; paste into the scanner)*, malformed URLs, `http://169.254.169.254/`, redirect chains, and an unreachable domain (should be UNKNOWN, never SAFE).

## Verification status
| Area | Status in the build sandbox |
|---|---|
| URL features, risk engine, e-mail analyser, HTML analyser, SSRF guard, safe fetcher (redirects, size cap, loop, redirect-to-metadata block) | **Executed and passing** (39 unit checks + local-server fetch tests) |
| ML training scripts (e-mail: LR/NB/RF with grid search + calibration; website: RF/LR, XGBoost if installed) | **Executed** on synthetic demo data; models in `models/` come from that run |
| TLS inspection, DNS (dnspython), RDAP domain age, HTTPS fetch path | Written, **not exercised** (no internet) |
| Flask app, SQLAlchemy/MySQL layer, REST routes, `tests/test_api.py` | Syntax-checked only - **SQLAlchemy could not be installed offline.** Run `pytest` first on your machine and fix anything it reports |
| React frontend | All 22 files compile with esbuild; **not built or run** (npm packages unavailable). `npm install && npm run dev` is the first real test |
| XGBoost model, dashboard screenshots | **Not produced** (xgboost not installed; no browser/UI run). Take screenshots after `npm run dev` |

## Known limitations / honest notes
* Demo models are trained on template-generated data -> ~100% test scores that mean nothing. Real datasets (PhishTank/OpenPhish, Tranco, Kaggle/Nazario/Enron emails) are described in `datasets/README.md`, including dataset-bias pitfalls.
* The URL model sees only the URL string; live checks supply the rest. Brand list and keyword lists are small and English-centric.
* Rate limiting and token revocation are in-memory (single process). Use Redis for multi-worker deployments.
* JWT is stored in `localStorage` (XSS-exposed); use httpOnly cookies for higher assurance.
* Detection is probabilistic. A "SAFE"/"LEGITIMATE" verdict is not a guarantee.
* Added schema extras beyond the brief: `report_json` (full report), `confusion_matrix`/`dataset`/`is_demo_data` in `model_metrics`; `scan_features.scan_id` references `scan_history.id` (a foreign key cannot point at two tables).
