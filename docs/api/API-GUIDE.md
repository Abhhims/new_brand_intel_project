# API Documentation (DEL-04)

- **Interactive docs:** `http://<api-host>:8010/docs` (Swagger UI) and `/redoc`
- **Machine-readable spec:** [`openapi.json`](openapi.json) (regenerate: `cd backend && python -m uv run python -c "import json;from app.main import app;json.dump(app.openapi(),open('../docs/api/openapi.json','w'),indent=2)"`)
- **Base path:** `/api/v1` · JSON everywhere · times are ISO-8601 UTC

## Authentication

```bash
curl -s -X POST http://localhost:8010/api/v1/auth/login \
  -H 'content-type: application/json' -d '{"email":"analyst@beyondcloud.local","password":"..."}'
# → {"access_token":"eyJ...","token_type":"bearer","user":{...}}
curl -s http://localhost:8010/api/v1/alerts -H "Authorization: Bearer eyJ..."
```

Tokens expire after 12 hours (`JWT_EXPIRE_MINUTES`). `401` = missing/invalid token, `403` = admin role required.

## Endpoints

| Method & path | Role | Purpose | Req. |
|---|---|---|---|
| `POST /auth/login` | — | Get a token | FND-03 |
| `GET /auth/me` | any | Current user | FND-03 |
| `GET /users` · `POST /users` · `PATCH /users/{id}` | admin | Manage accounts (name, role, active, password) | FND-03 |
| `GET /brands` · `POST /brands` | any · admin | List / create brands (with allowlist in one call). A `demo_mode` field is rejected with `422` — the product has no demo mode (D-32) | FND-04, RDA-04 |
| `GET/PATCH/DELETE /brands/{id}` | any · admin | Read / update / delete a brand | FND-04 |
| `POST /brands/{id}/assets` (multipart `kind`, `file`) | admin | Upload official logo / favicon / app icon | FND-05 |
| `DELETE /brands/{id}/assets/{asset_id}` | admin | Remove an asset | FND-05 |
| `GET/POST /brands/{id}/allowlist` · `DELETE …/{allow_id}` | any · admin | Official domains, packages, publishers, handles, email domains | FND-06 |
| `POST /scans` `{brand_id, modules?}` | any | Queue scans now (all modules if `modules` omitted) | FND-07 |
| `GET /scans?brand_id=&limit=` | any | Scan history with status, statistics, per-component results and errors (see below) | FND-13, RDA-17 |
| `GET /alerts` | any | Alert queue — see filters below | DSH-07, 11–16 |
| `GET /alerts/{id}` | any | Alert with evidence (presigned links) and history | DSH-08 |
| `POST /alerts/{id}/status` `{status, note?}` | any | Workflow change; `409` with allowed targets if invalid | DSH-10, AC-10 |
| `GET /alerts/{id}/events` | any | Audit trail | DSH-10 |
| `GET /evidence/{id}` | any | One evidence item with a fresh link | FND-12 |
| `GET /stats/executive?date=&brand_id=` | any | Executive dashboard numbers, plus scan coverage (`last_completed_scan_at`, `components_unavailable`) | DSH-01…06, RDA-02 |
| `GET /stats/trends?days=&brand_id=` | any | Daily new alerts by risk level | DSH-17 |
| `GET /integrations` | any | Every integration, whether it is configured, how to configure it, its last result (never returns secrets) | RDA-03 |
| `GET /exports/alerts.csv` · `GET /exports/alerts.pdf` | any | Export with the same filters as `/alerts` | DSH-18, DSH-19 |
| `GET /health` | — | Liveness + database check | FND-13 |

### Alert filters (`/alerts`, `/exports/*`)

| Parameter | Example | Notes |
|---|---|---|
| `brand_id` | `brand_id=<uuid>&brand_id=<uuid>` | repeatable |
| `module` | `module=phishing&module=mx` | typosquat, mx, phishing, apk, rogue_app, social, documents, logo, email, email_posture, dmarc |
| `risk_level` | `risk_level=High&risk_level=Critical` | Low, Medium, High, Critical |
| `status` | `status=New&status=Under Review` | New, Under Review, Confirmed, False Positive, Closed |
| `date_from`, `date_to` | `2026-10-01` | inclusive, on `first_seen` (UTC days) |
| `q` | `q=zentr0va` | searches title, entity, brand name and output fields |
| `suspected_phishing` | `true` | |
| `sort` | `newest` (default), `oldest`, `risk`, `last_seen` | |
| `page`, `page_size` | `1`, `25` (max 200) | `/alerts` only; exports return up to 10,000 rows |

### Alert object (abridged)

```json
{
  "id": "…", "brand_name": "Zentrova Bank", "module": "phishing",
  "entity_key": "zentrova-login.com", "title": "Suspected phishing website: zentrova-login.com",
  "similarity": 100.0, "score": 100, "risk_level": "Critical", "status": "New", "suspected_phishing": true,
  "signals": {"score": 100, "raw_score": 100, "rules": {"brand_exact_in_domain": 40, "typo_similarity_gt_80": 25,
              "mx_present": 15, "https": 10, "login_payment_keywords": 20, "official_logo": 30}},
  "details": {"Domain": "zentrova-login.com", "Similarity Score": 100, "MX Enabled": true, "Website Live": true,
              "SSL Present": true, "Screenshot": true, "Risk Level": "Critical", "Email Risk": "High", "…": "…"},
  "evidence": [{"kind": "screenshot", "url": "https://…presigned…", "sha256": "…", "captured_at": "…"}],
  "events": [{"kind": "created", "to_status": "New", "note": "Detected by phishing module, risk Critical (100)"}]
}
```

`details` keys per module are the Expected Output columns of requirements §3 (listed in
`backend/app/modules/registry.py`, `OUTPUT_FIELDS`).

### Scan object (D-31)

```json
{
  "id": "…", "brand_name": "Kodachadri Chits", "module": "social", "trigger": "manual",
  "status": "partially_completed",
  "stats": {"runner": "social", "findings": 4, "created": 1, "updated": 3, "errors": 0},
  "components": [
    {"name": "Telegram API", "status": "not_configured", "fatal": false, "counts": {},
     "message": "TELEGRAM_API_ID / TELEGRAM_API_HASH / TELEGRAM_SESSION not set"},
    {"name": "Telegram public pages", "status": "ok", "fatal": false, "message": "", "counts": {"checked": 12, "found": 0}},
    {"name": "Web search - Brave Search API", "status": "ok", "fatal": false, "message": "", "counts": {"queries": 5}}
  ],
  "error": null
}
```

| `status` | Meaning |
|---|---|
| `queued`, `running` | waiting for a worker / in progress |
| `completed` | every part of the scan ran successfully |
| `partially_completed` | some sources were not configured or unavailable — results are real, coverage reduced |
| `completed_with_errors` | some lookups or captures failed part-way — results are real but incomplete |
| `failed` | the scan could not produce results; nothing was checked, so this is not a clean result |
| `cancelled` | interrupted (worker restart or stuck > 90 minutes) |

Component `status` is `ok`, `skipped`, `not_configured`, `unavailable` or `failed`; `fatal: true` means the run could
not produce results without that component (it makes the run `failed`). `error` holds the first 50 error lines.

### Integration object (`GET /integrations`)

```json
{"id": "telegram_api", "name": "Telegram search API (Telethon)", "category": "Discovery", "modules": ["Social"],
 "configured": false,
 "how_to_configure": "Set TELEGRAM_API_ID, TELEGRAM_API_HASH and TELEGRAM_SESSION (python -m scripts.telegram_login)",
 "last_status": "not_configured", "last_message": "TELEGRAM_API_ID / TELEGRAM_API_HASH / TELEGRAM_SESSION not set",
 "last_checked_at": "2026-10-09T01:35:00Z"}
```

`last_status` comes from the newest scan component for that integration (or, for the email tools, the newest
analysed email); `null` means it has never run — it is never assumed `ok`. Categories: Discovery, Analysis, Email
analysis, Threat intelligence, Email intake.

### Executive stats coverage fields

| Field | Meaning |
|---|---|
| `last_completed_scan_at` | Finish time of the newest run that ended `completed`, `partially_completed` or `completed_with_errors`; `null` = no scan has completed (the dashboard then says "No scans have run yet", never "No threats detected.") |
| `components_unavailable` | Number of components that were not `ok`/`skipped` in the latest finished run of each brand and runner |

## Errors

`{"detail": "message"}` with `400` bad input, `401`, `403`, `404`, `409` conflict (duplicate brand/allowlist entry,
invalid status transition), `413` file too large, `422` validation (details per field), `503` dependency
unavailable. Unexpected errors return `500` with a `request_id` to quote when reporting.

`openapi.json` is generated from the code — regenerate it after API changes (command at the top) so it shows the
SP1 scan states, `components`, `/integrations` and the brand schemas without `demo_mode`.
