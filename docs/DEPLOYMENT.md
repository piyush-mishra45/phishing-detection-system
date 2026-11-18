# Deployment guide

## 1. Database (managed MySQL-compatible)
Create a MySQL 8 database (PlanetScale/Aiven/Railway/RDS/Cloud SQL). Run `database/schema.sql` or let the app create tables on first start.
Connection string: `mysql+pymysql://USER:PASSWORD@HOST:3306/phishguard` (add `?ssl_ca=...` if the provider requires TLS).

## 2. Backend (Render)
1. Push the repo to GitHub. 2. Render -> New -> Blueprint -> select the repo (`render.yaml`).
3. Set env vars: `DATABASE_URL`, `CORS_ORIGINS=https://<your-vercel-app>.vercel.app`, `ADMIN_EMAIL`. `SECRET_KEY` is generated; `FLASK_ENV=production` makes the app refuse to start without one. `TRUST_PROXY=1` is set so per-IP rate limits use the real client IP.
4. **Models:** commit `models/*.pkl` (trained on REAL data) or train in a build step with the datasets present: `cd backend && python train_email_model.py && python train_website_model.py`.
5. Check `https://<api>/api/health` -> `{"status":"ok","database":"ok","models":{...:true}}`.
Other hosts: `cd backend && gunicorn run:app --workers 1 --threads 4 --bind 0.0.0.0:$PORT`.
Outbound access to the internet (DNS, 80/443, rdap.org) is needed for website scans.

## 3. Frontend (Vercel)
Import the repo, set **Root Directory = `frontend`**, framework Vite, env var `VITE_API_URL=https://<api-host>`. `vercel.json` provides the SPA rewrite. Add the Vercel domain to the backend `CORS_ORIGINS`.

## 4. Production hardening checklist
* HTTPS only; strong `SECRET_KEY`; rotate on compromise (invalidates all tokens).
* Multi-worker/instance: replace the in-memory rate limiter and token-revocation set with Redis.
* Run the backend in a network segment without access to internal services/metadata (defence in depth beside the SSRF guard).
* Consider httpOnly-cookie sessions + CSRF protection instead of `localStorage` tokens.
* Never load `.pkl` files from untrusted sources (joblib = pickle). Pin scikit-learn to the training version.
* Retrain regularly; phishing changes fast. Monitor false positives.
