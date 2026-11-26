# Database Schema & Migrations (DEL-03)

PostgreSQL 17. Schema is defined in `backend/app/db/models.py` (SQLAlchemy 2.0) and versioned with Alembic in
`backend/app/alembic/versions/`. The API container runs `alembic upgrade head` on every start; tests build their
database with the same migrations.

```bash
cd backend
python -m uv run alembic upgrade head                          # apply
python -m uv run alembic revision --autogenerate -m "message"  # after changing models.py
python -m uv run alembic downgrade -1                          # roll back one step
```

## Entity overview

```
users ──< alert_events >── alerts ──< evidence
                             │
brands ──< brand_assets      │ (brand_id)
   │   ──< brand_allowlist   │
   │   ──< scan_runs         │
   │   ──< domain_checks     │
   └── ──< app_listings      │
   └─────────────────────────┘
```

## Tables

| Table | What one row is | Key columns |
|---|---|---|
| `users` | An analyst or admin account (FND-03) | `email` (unique), `password_hash` (Argon2), `role` admin/analyst, `is_active` |
| `brands` | A monitored brand (FND-04) | `name` (unique), `keywords[]`, `product_terms[]`, `is_active` (no `demo_mode` since D-32) |
| `brand_assets` | An official logo / favicon / app icon (FND-05) | `kind`, `storage_key`, `sha256`, `phash`, `dhash`, `mmh3` (favicon hash) |
| `brand_allowlist` | An official value never to alert on (FND-06) | `kind` domain/package/publisher/social_handle/email_domain, `value`; unique (brand, kind, value) |
| `scan_runs` | One execution of one module for one brand (FND-07) | `module`, `trigger` schedule/manual, `status` (see `scan_status`), `stats` JSON, `components` JSON (D-31), `error` (first 50 error lines) |
| `alerts` | One suspicious entity (domain, app, account, document, page) | see below |
| `evidence` | One captured artefact for an alert (FND-12) | `kind` screenshot/favicon/html/metadata/file/ssl/whois/dns/image, `storage_key`, `sha256`, `size`, `meta` JSON, `captured_at` |
| `alert_events` | The audit trail of an alert (DSH-10) | `kind` created/status/rescored/reopened/stage/app_status, `from_status`, `to_status`, `note`, `user_id`, `at` |
| `domain_checks` | A point-in-time DNS/WHOIS/HTTP/TLS observation of a domain (MX-02) | `domain`, `fuzzer`, `a_records[]`, `mx_records[]`, `ns_records[]`, `whois`, `http_status`, `title`, `ssl`, `favicon_mmh3`, `checked_at` |
| `app_listings` | The last known state of a Google Play listing (ROG-05) | `store`, `package`, `publisher`, `installs`, `version`, `state` new/updated/unchanged/removed |

### `alerts`

| Column | Meaning |
|---|---|
| `brand_id`, `module` | Which brand and which module (for domains: the furthest stage reached — D-19) |
| `entity_key` | Stable identity: the domain, `play:<package>`, `<platform>:<handle>`, document URL, page URL. Unique per (brand, module, entity_key) — re-scans update instead of duplicating |
| `title` | Human-readable summary |
| `similarity` | 0–100 brand similarity |
| `score`, `risk_level` | Risk score 0–100 and Low/Medium/High/Critical (§6) |
| `status` | New / Under Review / Confirmed / False Positive / Closed |
| `suspected_phishing` | Domain rule D-04 |
| `signals` | Which scoring rules fired and their points (`rules`), `raw_score` before module clamp |
| `details` | The module's **Expected Output** fields from requirements §3, using the exact column names (e.g. `Domain`, `MX Enabled`, `Website Live`, `SSL Present`, `Screenshot`, `Risk Level`) plus supporting fields |
| `source_url` | Where the thing was found |
| `first_seen`, `last_seen`, `updated_at` | Timestamps (UTC) |

### `scan_runs.components` (D-31)

An ordered JSON list with one entry per part of the scan, written by the runner's `ScanReport`
(`backend/app/modules/base.py`):

```json
[{"name": "DNS resolution", "status": "failed", "fatal": false,
  "message": "3 domains could not be resolved (timeout/SERVFAIL) - not treated as unregistered; retried next scan",
  "counts": {"checked": 412, "registered": 9, "unresolved": 3}}]
```

`status` is `ok`, `skipped`, `not_configured`, `unavailable` or `failed` (a component keeps the worst status it
reached in the run). The run's `status` is derived from this list by `derive_run_status()`: a crash or a *fatal*
component that could not run → `failed`; any `failed` → `completed_with_errors`; any `not_configured` /
`unavailable` → `partially_completed`; otherwise `completed`. Migration `20261009_7b1d0c4e9a21_scan_components`
mapped old values `succeeded` → `completed`, `partial` → `completed_with_errors`, interrupted `failed` →
`cancelled`, and dropped `brands.demo_mode` (it refuses to run while a demo brand exists).

Indexes: `(brand_id, module, risk_level, status)` for the alert queue filters, `first_seen` for date filters
and dashboard counts, `entity_key` uniqueness constraint.

## Evidence files

Evidence bytes live in the S3 bucket (`S3_BUCKET`, default `evidence`), keyed
`alerts/<brand_id>/<alert_id>/<timestamp>-<n>-<kind>.<ext>`; brand assets under
`brands/<brand_id>/<kind>/...`. The database stores the key, SHA256 and size. The API returns time-limited
presigned links (1 hour). Identical evidence is stored once per alert (D-21).

## Enumerations

| Type | Values |
|---|---|
| `role` | admin, analyst |
| `module_name` | typosquat, mx, phishing, apk, rogue_app, social, documents, logo, email, email_posture, dmarc |
| `risk_level` | Low, Medium, High, Critical |
| `alert_status` | New, Under Review, Confirmed, False Positive, Closed |
| `asset_kind` | logo, favicon, app_icon |
| `allow_kind` | domain, package, publisher, social_handle, email_domain |
| `scan_status` | queued, running, completed, partially_completed, completed_with_errors, failed, cancelled (D-31) |
| `evidence_kind` | screenshot, favicon, html, metadata, file, ssl, whois, dns, image |
