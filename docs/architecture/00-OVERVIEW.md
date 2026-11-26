# 0 · Overview — how the whole platform fits together

## 1. In one paragraph

An analyst registers a **brand** (keywords, official domains, apps, publishers, social handles, logos). Every day
— or when someone presses **Run scan now** — the platform runs **seven scan runners** for that brand. Each runner
collects candidates from a **source** (DNS, certificate logs, Google Play, web search, Telegram, websites),
**analyses** each candidate, and produces **findings**. A finding is turned into an **alert** with a **risk score**
from one shared points table and **evidence** (screenshots, files, metadata) stored in object storage. Analysts
work the alerts in the **dashboard**: filter, review evidence, change status, export.

## 2. Services (what runs)

```
 Browser ──► web (Next.js, :3000) ──REST──► api (FastAPI, :8010)
                                              │  reads/writes
                                              ▼
                                     PostgreSQL  (brands, alerts, evidence records, history)
                                              ▲
             beat (scheduler) ──► Redis queue ┤
                                   │          │
                    ┌──────────────┴───┐  ┌───┴──────────────────┐
                    │ worker           │  │ browser-worker       │
                    │ queue "default"  │  │ queue "browser"      │
                    │ apk, rogue_app,  │  │ domains, logo,       │
                    │ documents        │  │ social (screenshots) │
                    └────────┬─────────┘  └──────────┬───────────┘
                             └──────── S3 store (RustFS) ◄── evidence files
```

| Service | Code entry point | Defined in |
|---|---|---|
| `api` | `backend/app/main.py` | `deploy/docker-compose.yml` |
| `worker`, `browser-worker`, `beat` | `backend/app/workers/celery_app.py` | `deploy/docker-compose.yml` |
| `web` | `frontend/src/app/layout.tsx` | `deploy/frontend.Dockerfile` |
| `postgres`, `redis`, `minio` (RustFS) | images | `deploy/docker-compose.yml` |
| `fixtures` | `backend/tests/fixtures/site/` (nginx) — test website only | `deploy/docker-compose.yml` |

All four backend services use **one image** (`deploy/backend.Dockerfile`) with different start commands.

## 3. Folders — where to look for what

```
backend/app/
  main.py            FastAPI app: routers, request logging, /health
  config.py          every setting (read from deploy/.env)
  db/models.py       database tables (SQLAlchemy)          db/session.py  connections
  alembic/versions/  database migrations
  api/               REST endpoints: auth, brands, alerts, scans, stats, exports, emails, integrations
  schemas/api.py     request/response shapes
  core/              shared engine (doc 01): fetch, browser, search, similarity, imaging, scoring,
                     alerts, evidence, assets, allowlist, security
  modules/           detection modules (docs 02–07) + base.py (BrandContext, Finding, ScanReport,
                     derive_run_status) + registry.py
  workers/           celery_app.py (queues, schedule), tasks.py (Celery tasks), scan.py (scan runner)
backend/scripts/     bootstrap admin, UAT report, Telegram login, email accuracy
backend/tests/       unit/, modules/ (acceptance AC-01…08), api/ (AC-10), e2e/ (browser, AC-09)
backend/tests/support/   test-only code: simulated sources (fixture_sources.py), seed_test_brand.py, fixture builders
backend/tests/fixtures/  test-only data: fictional test brand, simulated sources, test website
frontend/src/        app/ (pages), components/, lib/api.ts (typed API client)
```

## 4. The life of a scan (end to end)

| Step | What happens | Where |
|---|---|---|
| 1 | Analyst presses **Run scan now** → `POST /api/v1/scans {brand_id, modules}` | `frontend/src/app/(app)/brands/[id]/page.tsx` → `backend/app/api/scans.py:25` |
| 2 | One `scan_runs` row per runner is created (status *queued*) | `backend/app/workers/scan.py:58` `create_scan_runs()` (older runs stuck > 90 min are closed as *cancelled*) |
| 3 | Tasks are put on Redis; logo is chained to run after domains | `backend/app/workers/tasks.py:44` `enqueue_runs()` |
| 4 | A worker picks the task and runs the scan | `backend/app/workers/tasks.py:17` `run_scan()` → `scan.py:67` `execute_scan()` |
| 5 | Brand is loaded into a read-only **BrandContext** | `backend/app/modules/base.py:201` `BrandContext.from_brand()` |
| 6 | The runner for that module is created and run → yields **Findings** | `backend/app/modules/registry.py:76` `get_runner()` → `<module>.run()`; the runner records each part it ran in `self.report` (a `ScanReport`) |
| 7 | Each finding is **scored**, merged into an **alert**, evidence stored | `backend/app/core/alerts.py:67` `upsert_finding()` → `core/scoring.py:197` `score()` |
| 8 | Scan run stores its **components** (each `ok`, `skipped`, `not_configured`, `unavailable` or `failed`, with message and counts), statistics and the first 50 error lines; its status is derived from the components | `scan.py:67` (end of `execute_scan`) → `modules/base.py` `derive_run_status()` |
| 9 | Dashboard shows the alert; analyst reviews and changes status | `frontend/src/app/(app)/alerts/[id]/page.tsx` → `api/alerts.py:137` |

Automatic scans: `beat` triggers `schedule_all` daily at 02:00 UTC (all modules) and every 6 hours (domains only)
— `backend/app/workers/celery_app.py`, `tasks.py:56`.

## 5. Modules and runners

Eight requirement modules, six runners (the three domain modules share one pipeline — D-19):

| Requirement module | Runner | Queue | Doc |
|---|---|---|---|
| Typosquat, MX, Active Phishing | `domains` → `modules/domains/module.py` | browser | 02 |
| Fake APK | `apk` → `modules/apk/module.py` | default | 03 |
| Rogue mobile apps | `rogue_app` → `modules/rogue_app/module.py` | default | 04 |
| Social impersonation | `social` → `modules/social/module.py` | browser | 05 |
| Sensitive documents | `documents` → `modules/documents/module.py` | default | 06 |
| Logo on websites | `logo` → `modules/logo/module.py` | browser | 07 |

Every module has the same shape: **sources → candidates → analyse → Finding** (doc 01 §3).
Product modules contain only **live** sources. Each runner accepts its sources through its constructor, so the
acceptance tests inject simulated sources (`backend/tests/support/fixture_sources.py`, data in
`backend/tests/fixtures/sources/*.json`) into the real runners — there is no demo mode in the product (D-09, D-32).

**Scan states (D-31).** A run is `queued`, `running`, then ends as one of:

| State | Meaning |
|---|---|
| `completed` | every part of the scan ran successfully |
| `partially_completed` | some sources were not configured or unavailable — results are real, coverage reduced |
| `completed_with_errors` | some lookups or captures failed part-way — results are real but incomplete (wins over `partially_completed`) |
| `failed` | nothing usable was checked (the runner crashed, or a *fatal* component such as "every web search failed" or "no official logo" could not run) |
| `cancelled` | interrupted (worker restart, or stuck longer than 90 minutes) |

**Unknown is never "no":** a DNS timeout/SERVFAIL leaves the domain *unresolved* (retried next scan, not
"unregistered"); a page that answered but could not be captured is "Website Live: unknown (capture failed)" and an
existing alert is left untouched; WHOIS failures show "lookup failed".

## 6. Data model (summary)

```
users ──< alert_events >── alerts ──< evidence
brands ──< brand_assets · brand_allowlist · scan_runs · domain_checks · app_listings
alerts.brand_id → brands
```

| Table | One row = | Written by |
|---|---|---|
| `brands`, `brand_assets`, `brand_allowlist` | a brand and its official things | brand pages / API |
| `scan_runs` | one execution of one runner, with its per-component results (`components`) | scan engine |
| `alerts` | one suspicious entity (domain, app, account, document, page) | `core/alerts.py` |
| `evidence` | one captured artefact (screenshot, file, metadata…) | `core/alerts.py` |
| `alert_events` | one history entry (created, status change, rescored, stage, …) | `core/alerts.py` |
| `domain_checks` | one DNS/WHOIS/HTTP/TLS observation of a domain | domains module |
| `app_listings` | last known state of a Play Store listing | rogue_app module |

Full column list: `docs/guides/DATA-MODEL.md`.

## 7. One risk model for everything

Modules never decide a risk level themselves. They describe what they saw as **Signals**; `core/scoring.py`
turns signals into points (§6 of the requirements + decisions), caps at 100, maps to Low/Medium/High/Critical and
keeps the level inside the range each module allows. Detail and examples: doc 01 §8.

## 8. Glossary

| Term | Meaning |
|---|---|
| **Brand context** | Read-only snapshot of a brand used during a scan (terms, allowlists, logo fingerprints) |
| **Candidate** | Something a source returned that might be abuse (a domain, a listing, a profile, a search result) |
| **Finding** | A candidate the module decided is relevant, with signals, output fields and evidence |
| **Signal** | A fact used for scoring (e.g. "MX present", "official logo detected") |
| **Alert** | The stored, scored, de-duplicated result an analyst works on |
| **Entity key** | The identity that makes re-scans update the same alert (domain, `play:<package>`, `x:<handle>`, URL) |
| **Evidence** | Files and metadata proving the finding, stored once per alert |
| **Scan component** | One part of a scan run (e.g. "DNS resolution", "Telegram API", "Web search - Brave Search API") with its own status: ok, skipped, not configured, unavailable or failed |
| **Integration** | An external tool or service a module depends on; listed with its configuration and last result on the Integrations page (`GET /api/v1/integrations`) |
