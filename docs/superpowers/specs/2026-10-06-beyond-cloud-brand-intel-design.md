# Beyond Cloud Brand Intelligence Automation — Design Spec

- **Date:** 2026-10-06
- **Status:** Draft — awaiting owner review
- **Inputs:** `docs/requirements/00-source-requirements.md`, `docs/requirements/01-requirements-register.md`
- **Decisions:** `docs/decisions/DECISION-LOG.md` (D-xx references below)
- **Timeline:** 15 days (D-01)

## 1. What we are building

An internal web platform for Beyond Cloud analysts. Analysts register a brand with its official
assets. Scheduled workers search eight kinds of sources for abuse of that brand, score every
finding with one risk model, store evidence, and raise alerts. Analysts review alerts in a dashboard,
move them through a workflow, and export them.

Single organisation, many brands, not multi-tenant (OOS-05).

## 2. Architecture

```
            ┌───────────────┐     REST/JSON      ┌──────────────────────────┐
 Analyst ──▶│ Next.js web   │ ─────────────────▶ │ FastAPI  (api)           │
            │ (frontend/)   │ ◀───────────────── │ auth · brands · alerts   │
            └───────────────┘                    │ stats · exports · scans  │
                                                 └──────┬──────────┬────────┘
                                                        │          │ enqueue
                                             PostgreSQL ◀┘          ▼
                                                 ▲            ┌──────────┐
                                                 │            │  Redis   │◀── Celery beat (schedules)
                                                 │            └────┬─────┘
                                   ┌─────────────┴───────┐         │
                                   │ worker (queue:      │◀────────┤
                                   │ default) DNS, WHOIS,│         │
                                   │ CT, stores, search, │         │
                                   │ docs, scoring       │         │
                                   └─────────────────────┘         │
                                   ┌─────────────────────┐         │
                                   │ browser-worker      │◀────────┘
                                   │ (queue: browser)    │  Playwright: screenshots, favicon,
                                   │ isolated network    │  page images for logo matching
                                   └──────────┬──────────┘
                                              ▼
                                   MinIO (S3) bucket "evidence"
```

All services run from `deploy/docker-compose.yml` (D-16).

### 2.1 Repository layout

```
backend/
  pyproject.toml, uv.lock, wheels/          (moved from repo root)
  app/
    main.py                                 FastAPI app factory
    config.py                               pydantic-settings
    db/  models.py, session.py              SQLAlchemy 2.0 async
    alembic/                                migrations (DEL-03)
    api/  auth.py, brands.py, alerts.py, stats.py, exports.py, scans.py, users.py
    core/
      fetch.py        safe fetcher — the only way to reach the internet (skill: safe-fetcher)
      scoring.py      pure risk function (skill: risk-scoring)
      similarity.py   string similarity, homoglyph folding, IDN handling
      imaging.py      pHash/dHash, favicon mmh3 hash, image compare
      evidence.py     MinIO put/get, SHA256, presigned URLs
      alerts.py       create-or-update alert, dedupe, status transitions
      search.py       web-search provider interface (Brave / SerpAPI / simulated)
    modules/
      base.py         Module protocol + Source protocol
      typosquat/  mx/  phishing/  apk/  rogue_app/  social/  documents/  logo/
    workers/  celery_app.py, schedules.py, tasks.py
  tests/  unit/, modules/, api/
fixtures/          per-module fixture data + test website (served by the fixtures container)
frontend/          Next.js app
deploy/            docker-compose.yml, Dockerfiles, .env.example
docs/              requirements, decisions, specs, plans, reports, guides
scripts/           seed_demo.py, uat_report.py
```

## 3. Data model (PostgreSQL)

| Table | Key columns | Purpose / req |
|---|---|---|
| `users` | email, name, password_hash, role (admin/analyst), is_active | FND-03 |
| `brands` | name, keywords[], product_terms[], is_active | FND-04, OUT-01 |
| `brand_assets` | brand_id, kind (logo/favicon/app_icon), storage_key, phash, dhash, mmh3 | FND-05 |
| `brand_allowlist` | brand_id, kind (domain/package/publisher/social_handle/email_domain), value | FND-06 |
| `scan_runs` | brand_id, module, trigger (schedule/manual), started_at, finished_at, status, stats json, error | FND-07, FND-13 |
| `alerts` | brand_id, module, entity_key (unique per brand+module), title, similarity, score, risk_level, status, suspected_phishing, details jsonb, first_seen, last_seen | all modules, DSH-* |
| `evidence` | alert_id, kind (screenshot/favicon/html/metadata/file/ssl/whois), storage_key, sha256, captured_at, meta jsonb | FND-12 |
| `alert_events` | alert_id, user_id, from_status, to_status, note, at | DSH-10 audit trail |
| `domain_checks` | domain, a[], mx[], ns[], whois jsonb, http_status, title, ssl jsonb, favicon_mmh3, checked_at | MX-02, history |
| `app_listings` | store, package, title, publisher, installs, version, icon_phash, state (new/updated/removed), last_seen | ROG-05 |

`details` holds each module's exact Expected Output fields (§3 tables), so the dashboard and exports
show the columns the requirements name. Pydantic schemas per module validate it.

Dedupe: `(brand_id, module, entity_key)` is unique. Seeing an entity again updates `last_seen`,
re-scores, and adds evidence; it does not create a duplicate alert. A closed alert whose score
rises a level is re-opened to New with an event "re-opened: risk increased".

## 4. Detection modules

Every module implements one interface:

```python
class Module(Protocol):
    name: str                                   # "typosquat", "mx", ...
    def discover(self, brand) -> Iterable[Candidate]: ...   # uses one or more Sources
    def analyze(self, brand, c: Candidate) -> Finding | None: ...
```

A `Finding` carries signals (for scoring), output fields (for `details`) and evidence items.
`core/alerts.py` turns findings into alerts. Each external source has a **live** and a **simulated**
implementation; brands in demo mode use simulated sources (D-09).

### 4.1 Typosquat (TYP-01…13)
- Variant generation: `dnstwist` fuzzers (omission, replacement, transposition, homoglyph, insertion,
  addition, hyphenation, bitsquatting, subdomain) + our prefix/suffix list (`login-`, `secure-`,
  `-support`, `-verify`, `my`, `app`…) × TLD set `.com .in .net .org .co` + configurable ccTLDs.
- Discovery (D-11): resolve every variant daily (A/AAAA/MX/NS via `dnspython`); query crt.sh for
  certificates matching `%brand%`; optional `certstream` listener.
- Registered variants → WHOIS (`whoisit`, RDAP) for creation date and registrar.
- Similarity 0–100: IDN-decode, fold homoglyphs (`confusable-homoglyphs`), then max of
  `rapidfuzz` ratio / partial-ratio between the domain label and each brand keyword/official label.

### 4.2 MX (MX-01…04)
- Store MX records in `domain_checks`; `MX Enabled` Yes/No; Email Risk tier per D-02.

### 4.3 Active phishing (PHI-01…09)
- Safe fetcher: HTTP and HTTPS probe → live flag, status, final URL, title.
- TLS certificate: issuer, subject, SAN, validity (via `ssl` + `cryptography`).
- Browser worker: full-page screenshot, favicon bytes → mmh3 hash (Shodan-style) and pHash,
  compared with the brand favicon.
- Keywords: login, sign in, secure, account, verify, password, OTP, payment, card, bank… in title,
  visible text and form fields; password input presence.
- Suspected Phishing per D-04.

### 4.4 Fake APK (APK-01…09)
- Sources: web-search API over APK sites (D-12); simulated APK repository fixture.
- From listing: app name, package, version, developer, source URL, icon. If downloadable via safe
  fetcher (size cap 150 MB): SHA256, then `androguard` reads manifest and icon only (no decompile).
- Signals: package not in allowlist but similar (≥ 80) to an official package; name similarity;
  icon pHash vs official logo/app icon; developer not in allowlist → "official publisher mismatch".

### 4.5 Rogue app (ROG-01…06)
- `google-play-scraper` search per brand keyword/product term; `app_listings` tracks new/updated/removed.
- Flag when publisher ∉ allowlist and (name/description uses brand or product terms, or icon matches logo).

### 4.6 Social impersonation (SOC-01…12)
- Sources per D-10: Telegram (`telethon` public username/channel search), search-API discovery for
  X/Facebook/Instagram/LinkedIn, simulated source.
- Signals: username, display-name similarity; profile image pHash vs logo; bio contains brand;
  support/contact terms ("support", "help desk", "customer care", "official", "DM us"…);
  handle ∉ official handles allowlist.
- Evidence: profile metadata + screenshot of the public profile page when reachable without login.

### 4.7 Sensitive documents (DOC-01…08)
- Sources: search API with `filetype:pdf|docx|xlsx|pptx` + brand terms; public share-link patterns
  (Google Drive, OneDrive, Dropbox, Box, S3) + brand; simulated index.
- Fetch through safe fetcher into evidence; detect type with `python-magic`; extract text with
  `pypdf`/`pdfminer`, `python-docx`, `openpyxl`, `python-pptx`; never execute macros.
- Signals and Exposure Confidence per D-06.

### 4.8 Logo on websites (LOGO-01…06)
- Input: live domains from 4.1/4.3 plus analyst-added URLs.
- Browser worker collects page images (img, CSS backgrounds, SVG rendered to PNG); compute pHash +
  dHash; match score 0–100 from Hamming distance against each official logo (multiple scales).
- Match ≥ threshold (default 85) → screenshot + alert.

## 5. Risk scoring (RSK-01…10)

`core/scoring.py` — one pure function `score(signals, module) -> (score, level)`:
points per §6 + D-06 document rules, cap 100, levels 0–29/30–59/60–79/80+, then module clamp (D-03).
Every rule and every boundary (29/30, 59/60, 79/80, 80 vs 81 similarity, cap) has a unit test.

## 6. API (FND-08, DEL-04)

`/api/v1` — OpenAPI docs at `/docs` (exported to `docs/api/` as the API documentation deliverable).

- `POST /auth/login`, `GET /auth/me`
- `GET|POST /brands`, `GET|PATCH /brands/{id}`, `POST /brands/{id}/assets` (logo upload),
  `GET|POST|DELETE /brands/{id}/allowlist`
- `POST /scans` (brand, module(s)) · `GET /scans`
- `GET /alerts` (filters: brand, module, risk, status, date range, q) · `GET /alerts/{id}`
- `POST /alerts/{id}/status` (to, note) · `GET /alerts/{id}/events`
- `GET /evidence/{id}` (presigned URL)
- `GET /stats/executive?date=` · `GET /stats/trends`
- `GET /exports/alerts.csv` · `GET /exports/alerts.pdf` (same filters)
- `GET|POST|PATCH /users` (admin)

## 7. Frontend (DSH-01…21)

Next.js App Router + shadcn/ui + TanStack Query/Table + Recharts. Pages:

- `/login`
- `/` Executive dashboard — six KPI tiles (DSH-01…06), alerts-by-module and risk trend charts (DSH-17)
- `/alerts` Analyst queue — table with risk, score, module, brand, status; filters + search;
  CSV/PDF export buttons
- `/alerts/[id]` Alert detail — module output fields, evidence gallery (screenshots), status change
  with note, event history
- `/brands`, `/brands/[id]` — keywords, assets upload, allowlists, "Run scan now", recent scan runs
- `/scans` — scan history and errors
- `/settings/users` — admin only

Responsive down to tablet width (DSH-20).

## 8. Reliability, security, logging

- **Safe fetcher (D-18):** httpx with connect/read timeouts, tenacity retries with backoff, per-host
  token-bucket rate limit in Redis, DNS resolve → reject private/loopback/link-local/metadata IPs,
  re-check every redirect hop, response size caps, writes only to the evidence bucket. Test mode adds
  an explicit allowlist for the fixtures website.
- **Browser worker:** separate container and Docker network; Playwright request interception applies
  the same IP rules; no downloads executed.
- **Celery:** per-task retries with backoff, time limits, idempotent tasks keyed by (brand, module,
  entity); failed tasks recorded in `scan_runs.error`.
- **Logging:** structlog JSON logs with request/task IDs (FND-13).
- **Performance (FND-14):** DB indexes on alert filters, paginated APIs, concurrent DNS resolution,
  browser work isolated on its own queue.
- **Secrets** in `.env` only; `.env.example` committed.

## 9. Testing and traceability

- **Unit:** scoring, similarity, typo generation, hashing.
- **Module acceptance (skill: module-fixtures):** each module runs against `fixtures/` through its
  simulated source and asserts an alert with evidence and timestamp. Covers AC-01…08.
- **API tests:** auth, filters, status workflow (AC-10), exports.
- **End-to-end (skill: webapp-testing):** browser test logs in, sees alerts from all 8 modules (AC-09),
  changes a status (AC-10).
- **Traceability:** tests carry `@pytest.mark.req("AC-03", "PHI-04")`. `scripts/uat_report.py` joins
  test results with the register and writes `docs/reports/UAT-REPORT.md` (DEL-07).
- **Fixtures website:** a small container serving a fake "Zentrova" login page with the logo and
  favicon — the live suspicious site for AC-03 and AC-08 in demos.

## 10. 15-day schedule (D-01)

| Days | Stage | Delivers |
|---|---|---|
| 1–3 | Foundation | Docker stack, schema + migrations, auth, brands/assets/allowlists, Celery + beat, safe fetcher, scoring, API skeleton, dashboard shell connected to API |
| 4–6 | Domain intelligence | Typosquat, DNS/WHOIS/CT, MX, HTTP/TLS probe, screenshot + favicon, phishing flag — AC-01…03 |
| 7–9 | Mobile & social | Fake APK, Google Play rogue apps, social sources, evidence for listings/profiles — AC-04…06 |
| 10–11 | Content | Sensitive documents, logo matching — AC-07, AC-08 |
| 12–13 | Dashboard & workflow | Alert queue, detail, filters, charts, status workflow, CSV/PDF export — AC-09, AC-10 |
| 14 | Hardening & UAT | Logging, error paths, performance pass, full test run, UAT report, demo seed data |
| 15 | Delivery | Deployment guide, brand configuration guide, API docs, demo guide, rehearsal |

Daily progress reports go in `docs/reports/daily/` (D-17).

## 11. Documentation deliverables

| Deliverable | File |
|---|---|
| DEL-03 Schema & migrations | `backend/app/alembic/`, `docs/guides/DATA-MODEL.md` |
| DEL-04 API documentation | `docs/api/` (OpenAPI export + guide) |
| DEL-05 Deployment guide | `docs/guides/DEPLOYMENT.md` |
| DEL-06 Brand configuration guide | `docs/guides/BRAND-CONFIGURATION.md` |
| DEL-07 Test / UAT report | `docs/reports/UAT-REPORT.md` |
| DEL-08 Sample data | `scripts/seed_demo.py` + `fixtures/` |
| Demo support | `docs/demo/DEMO-GUIDE.md` (script, talking points, Q&A), `docs/decisions/DECISION-LOG.md` |

## 12. External inputs needed later (not blocking start)

| Needed by | Item |
|---|---|
| Day 7 | Web-search API key (Brave Search API preferred; SerpAPI alternative) |
| Day 8 | Telegram API ID/hash + a phone number for a monitoring account |
| Before live use | Confirmation Beyond Cloud is authorised to monitor each real brand |

Without these, the related modules run on simulated sources only and still pass acceptance.

## 13. Risks

| Risk | Mitigation |
|---|---|
| 15 days is tight for 8 modules | Shared core (fetcher, scoring, evidence, alerts) built first; modules are thin; simulated sources unblock tests |
| Third-party sites change HTML / block scraping | Sources are isolated adapters; failures are logged per scan run and don't stop other modules |
| False positives from fuzzy matching | Allowlists, tunable thresholds per brand, False Positive status measured in UAT |
| Windows dev machine lacks native libs | Backend runs in Docker; Windows used for editing and the frontend |
