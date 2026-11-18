# API reference
Base URL `http://127.0.0.1:5000`. JSON in/out. Protected routes need `Authorization: Bearer <token>`.
Errors: `{ "error": "message", "field"?: "name" }` with 400 validation, 401 auth, 403 forbidden, 404, 409 conflict, 413 too large, 429 rate-limited (`Retry-After`), 500.

## Auth
| Method & path | Body | Notes |
|---|---|---|
| `POST /api/auth/register` | `{username,email,password}` | password >=10 chars with upper, lower, digit. Returns `{token,user}` (201). Email equal to `ADMIN_EMAIL` becomes admin |
| `POST /api/auth/login` | `{identifier,password}` (username or email) | `{token,user}`; generic 401 on failure |
| `POST /api/auth/logout` | - | revokes the token |
| `GET/PUT /api/auth/me` | `{username?,email?}` | profile |
| `POST /api/auth/change-password` | `{current_password,new_password}` | revokes token |
Auth endpoints: 10 requests/min/IP (configurable).

## Scans (10/min/user, configurable)
`POST /api/scan/email` - JSON `{email_content (required), sender_email?, subject?}` **or** multipart with `file` (.eml, <=2 MB) and optional `sender_email`, `subject`.
`POST /api/scan/website` - `{url}`.
Both return `201 {scan_id, scan_type, report}`. Key report fields: `prediction`, `risk_score` (0-100 int), `risk_level`, `ml_probability`, `model_confidence`, `heuristic_score`, `reasons[]`, `unknown_checks[]`, `signals[]`, `recommended_actions[]`;
email adds `phishing_probability`, `legitimate_probability`, `suspicious_keywords`, `links[]`, `malicious_links[]`, `headers`, `attachments`;
website adds `ssl`, `dns`, `domain_age`, `redirects`, `html`, `url_features`, `fetch`.
Unsafe targets (private/local addresses) are **not contacted**; the result is `UNKNOWN`.

## History & reports
`GET /api/history?q=&type=email|website&category=low|medium|high|critical&prediction=&date_from=YYYY-MM-DD&date_to=&page=&per_page=` -> `{items,total,page,per_page}`
`GET /api/history/{id}` -> scan metadata + `report` + `features[]` (own scans only; others return 404)
`DELETE /api/history/{id}`
`GET /api/reports/export` (same filters) -> CSV

## Dashboard / models / health
`GET /api/dashboard/stats` -> `totals, weekly[7], monthly, distribution, recent_scans` (`?scope=all` for admins)
`GET /api/model/metrics` -> latest metrics per model, with `is_demo_data` flag
`GET /api/health` -> `{status, database, models:{email,website}}` (public)

## Admin (role=admin)
`GET /api/admin/users`, `PATCH /api/admin/users/{id}/role {role}`, `DELETE /api/admin/users/{id}`, `GET /api/admin/stats`
