# Chapter 01 - Architecture and the End-to-End Process

In this chapter:
- Every container in the Docker Compose file, and why it exists.
- The technology stack, and the decision behind each choice.
- A map of the repository and a plain explanation of the database tables.
- The complete process from adding a brand to seeing a scored finding and alert on the dashboard, with one look-alike
  domain followed through every step.
- The safe fetcher, login and roles, and the scan schedule.

## 1. The system at a glance

The platform has three layers:

1. **A web dashboard** that analysts use in their browser.
2. **A backend** that stores data, runs scans in the background and serves the dashboard.
3. **Supporting services**: a database, a job queue, file storage and email-analysis engines.

```
  Analyst's browser
        |
        v
  +-------------+    REST / JSON     +------------------+
  |  web        | -----------------> |  api             |
  |  Next.js    | <----------------- |  FastAPI         |
  |  port 3000  |                    |  port 8010       |
  +-------------+                    +------------------+
                                       |            |
                          reads/writes |            | puts scan jobs on the queue
                                       v            v
                              +------------+   +---------+   <-- beat (scheduler) also
                              | postgres   |   | redis   |       puts jobs here
                              | database   |   | queue   |
                              +------------+   +---------+
                                    ^            |      |
                                    |   queue "default" queue "browser"
                                    |            v      v
                                    |    +--------+  +----------------+
                                    +----| worker |  | browser-worker |
                                    |    +--------+  +----------------+
                                    |         |              |
                                    |         v              v
                                    |   +-----------------------------+
                                    |   | minio (RustFS) - S3 storage |
                                    |   | evidence files              |
                                    |   +-----------------------------+
                                    |
                     worker also calls rspamd and clamav for email analysis
```

## 2. Every container and why it exists

All containers are defined in `deploy/docker-compose.yml` (decision D-16: the whole platform runs from one
Compose file). The four backend containers (`api`, `worker`, `browser-worker`, `beat`) use the **same
image**, built from `deploy/backend.Dockerfile`, and differ only in their start command.

Some containers belong to a **profile**. A profile is a named group that only starts when asked for:
`--profile app` starts the product; `--profile test` starts the test website.

| Container | Image | Profile | Port (host) | Why it exists |
|---|---|---|---|---|
| `postgres` | `postgres:17-alpine` | always | 5432 | The database. Stores brands, findings, observations, alerts, timelines, scan runs, domain checks, emails. |
| `redis` | `redis:7-alpine` | always | 6379 | The job queue between the API and the workers (Celery broker). Also used for shared rate limits and threat-intel caching. |
| `minio` | `rustfs/rustfs:latest` | always | 9000, 9001 | S3-compatible object storage for evidence files and official logos. The service is still named `minio`, but it runs RustFS, because MinIO stopped publishing Docker images (D-22). Port 9001 is its web console. |
| `api` | backend image | app | 8010 | The REST API (FastAPI). On start it runs database migrations (`alembic upgrade head`), creates the first admin if no users exist (`scripts.bootstrap`), then serves requests with uvicorn. |
| `worker` | backend image | app | none | Celery worker for the `default` queue, 4 jobs at a time. Runs APK, rogue app, document and email-posture scans, and email analysis. |
| `browser-worker` | backend image | app | none | Celery worker for the `browser` queue, 2 jobs at a time. Runs the scans that drive a headless Chromium browser: domains, logo, social and social_media. Has 1 GB of shared memory for the browser. Kept separate so browser work is isolated from the rest (D-18). |
| `beat` | backend image | app | none | The Celery scheduler. Puts scan jobs on the queue at fixed times. |
| `web` | `brandintel-web` (built from `deploy/frontend.Dockerfile`) | app | 3000 | The Next.js dashboard. |
| `rspamd` | `rspamd/rspamd:latest` | app | 11333 | Spam and phishing engine used when analysing emails (D-28). Optional: if it is down, the email result shows "not checked". |
| `clamav` | `clamav/clamav:stable` | app | 3310 | Antivirus engine for email attachments (D-28). Needs about 1.5 GB of memory and a minute to load its virus database. Optional in the same way. |
| `fixtures` | `nginx:alpine` | test | 8088 | A small test website used only by the automated acceptance tests. Not part of the product (D-30). |

Note on isolation: the comment in the Compose file says the browser worker runs "on its own queue and
network". In the current file it has its own queue and container, but no separate Docker network is
defined. Network isolation between containers is therefore not enforced by Compose today. The protection
against reaching internal addresses comes from the safe fetcher and the browser's request guard (section 9).

Commands (from the comment at the top of the Compose file):

```
Infra only (local development):
  docker compose -f deploy/docker-compose.yml up -d postgres redis minio
Test website for automated tests:
  docker compose -f deploy/docker-compose.yml --profile test up -d fixtures
Everything:
  docker compose -f deploy/docker-compose.yml --profile app up -d --build
```

## 3. Technology stack and why

Where a decision ID is given, the reason is recorded in `docs/decisions/DECISION-LOG.md`. Where none is
given, the choice was made in the design spec (`docs/superpowers/specs/2026-10-06-beyond-cloud-brand-intel-design.md`)
without a separate decision entry.

| Layer | Technology | Why |
|---|---|---|
| Hosting | Docker Compose | Runs the same way on a laptop, a VM or a cloud server (D-16). |
| Backend language | Python 3.12 | Most security and parsing libraries (dnstwist, Androguard, YARA, oletools, Playwright) are Python. |
| API framework | FastAPI | Fast to build, validates requests with Pydantic, and publishes interactive API docs at `/docs`. |
| Database | PostgreSQL 17 with SQLAlchemy and Alembic | Reliable relational store with JSON columns (JSONB) for flexible module output. PostgreSQL was kept instead of MongoDB when the email module was added (D-28). Alembic manages schema migrations. |
| Background jobs | Celery with Redis | Scans take minutes; they must run outside the web request, with retries and a schedule (requirement FND-07). |
| Headless browser | Playwright (Chromium) | Takes screenshots and reads pages the way a victim would see them, in an isolated worker (D-18). |
| Object storage | RustFS (S3 protocol) via boto3 | Evidence files are large; S3 storage keeps them out of the database. Any S3 service can replace RustFS by changing `.env` (D-22). |
| Frontend | Next.js 16, React 19, TanStack Query and Table, Recharts, shadcn/ui, Tailwind | A modern dashboard with tables, filters and charts. Next.js was kept when the email module was added (D-28). |
| Login | Email and password hashed with Argon2, JWT tokens | Simple local accounts with two roles (D-15). |
| Domain variants | dnstwist plus a custom word list | Well-tested generator of misspellings (requirements TYP-01 to TYP-08). |
| New domains | crt.sh Certificate Transparency search | Free and catches new HTTPS sites early (D-11). |
| Web search | Brave Search API or SerpAPI if a key is set, otherwise DuckDuckGo public results, paced | Works without paid accounts; a free Brave key makes it reliable (D-23). |
| Image matching | imagehash (pHash, dHash) and mmh3 favicon hash | Logos are matched by fingerprint, not pixel by pixel. |
| APK signatures | Androguard and cryptography | Read the signing certificate without running or decompiling the app (D-26). |
| Email engines | Rspamd, ClamAV, YARA, oletools, dkimpy, pyspf, checkdmarc | Several independent checks, with no single point of truth (D-28). |
| Threat intel | URLhaus, OpenPhish, urlscan.io, AbuseIPDB | Reputation of links and sender IPs (D-28). VirusTotal is not used: its free API forbids commercial use. |
| PDF export | WeasyPrint | Turns an HTML report into a PDF. |
| Logging | structlog | Structured logs with a request ID on every API call. |

Chapter 11 lists every tool in more detail.

## 4. Where things live (folder map)

```
backend/
  app/
    main.py              The FastAPI application: routers, request logging, /health
    config.py            Every setting, read from environment variables / deploy/.env
    db/models.py         Database tables (SQLAlchemy models)
    db/session.py        Database connections
    alembic/versions/    Database migrations
    api/                 REST endpoints: auth, brands, alerts, findings, emails, scans, stats, exports, integrations
    schemas/api.py       Shapes of API requests and responses
    core/                Shared engine used by every module:
      fetch.py             safe fetcher (the only way to reach the internet)
      browser.py           headless browser capture
      search.py            web search providers
      integrations.py      list of every integration and its last result
      similarity.py        name similarity, homoglyph handling
      imaging.py           image fingerprints
      scoring.py           the risk score
      findings.py          findings, observations, timeline, alert rule, analyst decisions (SP2)
      evidence.py          S3 evidence storage
      assets.py            official logo upload
      allowlist.py         cleaning allowlist values
      security.py          passwords, tokens, roles
    modules/             Detection modules:
      base.py              Detection, BrandContext, ScanReport, derive_run_status()
      registry.py          which runner runs which module; output fields
      pagecheck.py         analyse a captured web page
      common.py            shared helpers
      domains/             typosquat + MX + phishing pipeline
      apk/                 fake APKs
      rogue_app/           Google Play
      social/              social media impersonation (accounts)
      social_media/        social media brand misuse (posts, videos, ads, channels)
      documents/           exposed documents
      logo/                logo on websites
      email/               phishing email, email posture, DMARC
    workers/
      celery_app.py        Celery setup and the schedule
      tasks.py             Celery tasks and queue routing
      scan.py              runs one scan for one brand
  scripts/               bootstrap admin, UAT report, email accuracy, Telegram login
  tests/                 unit, module (acceptance), API and end-to-end tests
    support/               test-only code: simulated sources, test brand seeding, fixture builders
    fixtures/              test-only data: fictional test brand, simulated source data, test website
frontend/src/
  app/                   pages: dashboard, alerts, findings, brands, scans, integrations, emails, settings/users, login
  components/            shared UI pieces
  lib/api.ts             typed API client
  lib/constants.ts       labels, decision transitions, alert triggers, rule names
deploy/                  docker-compose.yml, Dockerfiles, .env.example
docs/                    requirements, decisions, specs, guides, reports, this handbook
```

## 5. The data model, simply

The database has 16 tables, all defined in `backend/app/db/models.py`. A full column list is in
`docs/guides/DATA-MODEL.md`. SP2 (2026-10-09, migration `20261009_c41e7a9d2b10_finding_model`) replaced the
single `alerts` table of Phase 1 with four tables: `findings`, `observations`, `finding_events` and a new
`alerts` table (D-33 to D-37).

```
brands --< findings --< observations           (one per scan that saw it)
           findings --< finding_events >-- users (the timeline)
           findings --< alerts                  (each time the alert rule was met)
           findings --< evidence >-- observations
brands --< brand_assets
brands --< brand_allowlist
brands --< scan_runs --< observations
brands --< domain_checks
brands --< app_listings
brands --< email_messages --< email_indicators
brands --< dmarc_reports
brands --< mail_sources
("--<" means "one ... has many ...")
```

| Table | One row is | Most important columns |
|---|---|---|
| `users` | A person who can log in | email, name, password hash (Argon2), role (admin or analyst), active flag |
| `brands` | A monitored brand, e.g. Example Bank | name, keywords, product terms, active flag (there is no demo mode flag since D-32), `alert_min_level` (the "Alert from" risk level, default Medium, D-34) |
| `brand_assets` | An official image: logo, favicon or app icon | storage key in S3, SHA-256, perceptual hashes (pHash, dHash), favicon hash (mmh3) |
| `brand_allowlist` | One official thing | kind (domain, email_domain, package, publisher, social_handle, signing_cert) and value |
| `scan_runs` | One run of one scan runner for one brand | module, trigger (schedule or manual), status (queued, running, completed, partially_completed, completed_with_errors, failed, cancelled), statistics, `components` (the result of each part of the scan, D-31), first 50 error lines |
| `findings` | One suspicious thing per brand (a domain, app, account, post, document, page or email) | module, entity key, **stage** (Candidate or Finding), **decision** (New, Investigating, Confirmed Threat, False Positive, Legitimate, Ignored, Resolved) with `decided_by`, `decided_at`, `decision_note`, title, similarity, score, risk level, suspected phishing flag, `signals` (why the score), `details` (module output fields), `state` (latest comparable facts such as live, login form, logo, MX), source URL, first seen, last seen, `last_alert_at` |
| `observations` | One sighting of a finding | finding, scan (empty for email uploads and mailbox), channel (`scan`, `upload`, `mailbox`, `migration`), time, stage, score, risk level, signals, state, details at that moment |
| `finding_events` | One timeline entry | kind (`discovered`, `promoted`, `changed`, `rescored`, `stage`, `app_status`, `alerted`, `decision`, `reopened`), from and to value, note, user, observation, alert, time |
| `alerts` | One time the alert rule was met for a finding | finding, brand, scan, observation, **trigger** (`first_crossing`, `change`, `reopen`, `migrated`), **reason** (text shown to analysts), score, risk level, `reasons` (rules that fired at that moment), created at |
| `evidence` | One piece of proof for a finding | finding, the observation that captured it, kind (screenshot, favicon, html, metadata, file, ssl, whois, dns, image), S3 storage key, SHA-256, size, metadata |
| `domain_checks` | One observation of a look-alike domain | DNS records (A, MX, NS), WHOIS, HTTP status, final URL, page title, TLS certificate facts, favicon hash |
| `app_listings` | Last known state of a Google Play app | package, title, publisher, installs, version, state (new, updated, unchanged, removed) |
| `email_messages` | One analysed email | sender, reply-to, subject, sender IP, authentication results, raw email location in S3, processing status, link to its finding |
| `email_indicators` | One link, domain, IP or attachment from an email | value, every tool's verdict, number of sources that called it malicious |
| `dmarc_reports` | One row of a DMARC aggregate report | sending IP, message count, SPF and DKIM results, whether DMARC passed |
| `mail_sources` | A configured email intake | kind, name of the `.env` settings that hold the credentials. The table exists, but the current mailbox polling reads its settings directly from `.env` and does not use this table. |

Rules about findings and alerts enforced by the database and the code:

- A finding is unique per **brand + module + entity key** (constraint `uq_finding_entity`). Re-scans add an
  observation to the existing finding instead of creating a new one.
- The three domain modules (typosquat, MX, phishing) share **one finding per domain** (D-19). The code
  looks across all three modules when it searches for an existing finding.
- `findings`, `observations` and `alerts` are written by one function only: `record_detection()` in
  `backend/app/core/findings.py`. Modules never write them (the Google Play module uses the helper
  `mark_state()` from the same file to record an app that disappeared).
- An alert record exists only when the finding was at stage Finding and at or above the brand's "Alert from"
  level at that moment (D-34). Phase 1 alerts were migrated as findings **with the same IDs**, each with one
  `migration` observation and one alert record with trigger `migrated`, so old links still work (D-37).

## 6. The end-to-end process

This is the full path from adding a brand to a score on the dashboard.

```
 [1] Admin adds brand + allowlist + logo         frontend brand form -> api/brands.py
          |
 [2] Scan starts: schedule (beat) or             workers/celery_app.py (beat_schedule)
     "Run scan now"                               api/scans.py -> workers/scan.py create_scan_runs()
          |
 [3] One scan_runs row per runner, status queued
          |
 [4] Jobs put on Redis queues                     workers/tasks.py enqueue_runs()
     default: apk, rogue_app, documents, email_posture
     browser: domains, logo, social   (logo waits for domains to finish)
          |
 [5] Worker picks job -> execute_scan()           workers/scan.py
     loads brand into BrandContext                modules/base.py
          |
 [6] Module runner: discover candidates           modules/<module>/module.py
     (DNS, crt.sh, Google Play, web search, ...)  via core/fetch.py (safe fetcher)
          |
 [7] Checks on each candidate                     core/browser.py, modules/pagecheck.py,
     (page capture, logo/favicon match, ...)      core/similarity.py, core/imaging.py
          |
 [8] Detection = signals + details + evidence     modules/base.py Detection
     + analysed (Candidate or Finding) + state
          |
 [9] record_detection():                          core/findings.py
       score()  -> score, level, rules             core/scoring.py
       find existing finding or create one
       store an observation for this scan
       compare state -> timeline events
       (discovered/promoted/changed/rescored/stage)
       store new evidence in S3                    core/evidence.py
       alert rule met? first time or meaningful
       change? -> alert record + "alerted" event
          |
[10] Detection committed. At the end the run     workers/scan.py
     stores its components (what ran, what        modules/base.py ScanReport,
     could not) and its state is derived          derive_run_status()
     from them
          |
[11] Dashboard asks the API for alerts and       api/alerts.py, api/findings.py, api/stats.py
     findings -> list, detail, timeline           frontend/src/app/(app)/...
          |
[12] Analyst records a decision                  api/findings.py, api/alerts.py ->
     -> "decision" event on the timeline          core/findings.py set_decision()
```

### Step 1 - Brand onboarding

An admin creates a brand in the dashboard (`frontend/src/components/brand-form.tsx`), which calls
`POST /api/v1/brands` (`backend/app/api/brands.py`, admin only). A brand has:

- **Name and keywords**, e.g. "Example Bank". Keywords are the words the platform searches for.
- **Product terms**, e.g. "ExamplePay". Extra brand words.
- **Allowlist entries**: official domains (`examplebank.com`), email domains, app packages
  (`com.examplebank.mobile`), publishers ("Example Bank Ltd"), social handles (`@examplebank`), and app
  signing certificate fingerprints. Values are cleaned on save (`backend/app/core/allowlist.py`), so an
  analyst can paste a full URL and the platform keeps just the domain or handle.
- **Official images** uploaded through `POST /api/v1/brands/{id}/assets`. `backend/app/core/assets.py`
  stores the file in S3 and saves its fingerprints (pHash, dHash, and for favicons the mmh3 hash).

The allowlist matters twice: it tells modules what to search for, and what to ignore as genuine.
`docs/guides/BRAND-CONFIGURATION.md` explains each field.

### Step 2 - Scheduling or "Run scan now"

Scans start in two ways:

- **On a schedule.** The `beat` container runs the schedule in `backend/app/workers/celery_app.py`
  (section 11 below). At 02:00 UTC every day it starts every runner for every active brand.
- **On demand.** On a brand page, the analyst presses **Run scan now** and picks modules. The page calls
  `POST /api/v1/scans` (`backend/app/api/scans.py`).

Both paths call `create_scan_runs()` in `backend/app/workers/scan.py`. It first closes "stale" runs (left
queued or running for more than 90 minutes, for example after a worker restart) as `cancelled`. Then it creates
one `scan_runs` row per **runner**, status `queued`.

A **runner** is the code that executes a module. Twelve modules exist, but there are eight runners,
because the three domain modules share one pipeline (D-19) and the email modules are fed by uploads and
mailboxes rather than by scans (`backend/app/modules/registry.py`, `RUNNERS`):

| Module(s) | Runner | Queue |
|---|---|---|
| Typosquat, MX, Active Phishing | `domains` | browser |
| Fake APK | `apk` | default |
| Rogue mobile app | `rogue_app` | default |
| Social impersonation | `social` | browser |
| Social media brand misuse | `social_media` | browser |
| Sensitive documents | `documents` | default |
| Logo on websites | `logo` | browser |
| Email domain security (posture) | `email_posture` | default |
| Phishing email, DMARC reports | no runner (uploads and mailbox polling) | default |

### Step 3 and 4 - Celery queues

`enqueue_runs()` in `backend/app/workers/tasks.py` puts one `run_scan` job per runner on Redis. The
queue is chosen by `_queue()`: runners in `BROWSER_RUNNERS = {"domains", "logo", "social", "social_media"}` go to the
`browser` queue; the rest go to `default`.

One special case: when both `domains` and `logo` are requested, the logo job is **chained** after the domain
job. The logo module crawls the live look-alike sites that the domain scan just found, so it must wait.

Celery settings that protect the work (`backend/app/workers/celery_app.py`):

| Setting | Value | Meaning |
|---|---|---|
| `task_acks_late` | true | A job is only marked done after it finishes, so a crash does not lose it |
| `worker_prefetch_multiplier` | 1 | A worker takes one job at a time |
| `task_time_limit` | 60 minutes | A job that runs longer is stopped |
| `visibility_timeout` | 2 hours | An unfinished job is handed out again after 2 hours |
| `max_retries` on `run_scan` | 2, 120 seconds apart | Retries when the database or Redis is down |

### Step 5 - The scan runner

A worker takes the job and calls `execute_scan()` in `backend/app/workers/scan.py`:

1. It marks the run as `running`. If the run already ended (a job delivered twice), it skips it.
2. It loads the brand and builds a **BrandContext** (`backend/app/modules/base.py`): a read-only snapshot
   of the brand's terms, allowlist and image fingerprints. Modules never touch the brand record directly.
3. It creates the runner with `get_runner()` and calls `runner.run(ctx, db)`. The product has no demo mode
   (D-32): runners use live sources only. The automated tests build the same runners with simulated sources
   (`backend/tests/support/fixture_sources.py`).
4. While it works, the runner writes the outcome of each part of the scan to its **scan report**
   (`self.report`, a `ScanReport` from `backend/app/modules/base.py`). Each part is a **component**, for
   example "DNS resolution" or "Telegram API" (see Step 10).

### Step 6 - Candidate discovery

Each runner first collects **candidates** from its sources. For example, the domain runner
(`backend/app/modules/domains/module.py`) generates up to 12,000 misspellings of the official domains
(`backend/app/modules/domains/variants.py`) and adds names found in Certificate Transparency logs. Other
runners search Google Play, APK mirror sites, social platforms or the web. Every internet request goes
through the safe fetcher (section 9).

### Step 7 - Checks

Each candidate is checked. The checks depend on the module: DNS and WHOIS lookups, a browser capture of the
page, logo and favicon matching, keyword search, publisher comparison, signing certificate comparison,
document text extraction. The module chapters (03 to 09) describe them.

### Step 8 - Detection

When a candidate is relevant, the module yields a **Detection** (`backend/app/modules/base.py`; it was called
`Finding` before SP2, renamed to avoid a clash with the new `findings` table). A detection has:

- `entity_key`: its identity, e.g. the domain `examp1ebank.com`.
- `title`: a one-line description.
- `signals`: the facts the score is built from (a `Signals` object from `backend/app/core/scoring.py`).
- `details`: the module's output fields, e.g. "MX Enabled", "Page Title".
- `evidence`: screenshots, files and metadata to store.
- `module`: for domains, the stage reached (typosquat, MX or phishing).
- `analysed`: `True` when the module actually looked at the thing and has evidence (stage **Finding**),
  `False` when it only discovered it (stage **Candidate**, D-33). Each module chapter gives its rule; for
  example a registered look-alike domain with no website and no MX is a Candidate.
- `state`: comparable facts the module knows best, for example `{"listed": False}` for a Play app or
  `{"live": None}` (unknown) when a website capture failed.

Modules never decide the risk level, and never decide whether to alert. They only report what they saw.

### Step 9 - Findings, observations, timeline and alerts

`execute_scan()` passes each detection to `record_detection()` in `backend/app/core/findings.py`, each in its
own savepoint. This is the only code that writes findings, observations and alerts (SP2). It does the following:

1. **Score.** It calls `score(detection.signals, module)` in `backend/app/core/scoring.py`. This returns the
   0-100 score, the level, the list of rules that fired, the raw total and any cap. Chapter 02 explains it.
2. **Match** the existing finding with the same brand, module and entity key. For domains it searches all
   three domain modules, so one domain always has one finding (D-19). If there is none, it creates one with
   decision **New** and a `discovered` timeline event, e.g. "Finding found by phishing module, risk High (70)".
3. **Observe.** It stores an **observation**: this scan's ID, stage, score, level, signals, state and details.
4. **Compare** the new state with the finding's previous state (D-36) and write timeline events:
   - `promoted` when a Candidate becomes a Finding ("Analysis found evidence");
   - `changed` for each meaningful change: website went live, login/payment form detected, official logo
     detected, domain can now receive email, APK signed by a non-official certificate, app listed again (and,
     without alerting, "Website no longer live");
   - `rescored` when the level changed, e.g. "Risk Medium -> High (70)";
   - `stage` when a domain moves forward (typosquat -> MX -> phishing). A phishing site that goes offline stays
     a phishing finding.
   An unknown value (`None`, for example a failed capture) is never compared, so it never reads as a change.
5. **Update fields**: title, similarity, score, risk level, suspected phishing flag, `signals` (the score
   explanation), `details`, `state`, source URL, last seen. A Finding never goes back to Candidate. For domain
   modules it also adds a "Score Cap" detail when a D-29 cap lowered the score.
6. **Store evidence** (step 9a below).
7. **Decide on an alert** (D-34, D-36). The rule is met when the stage is Finding and the risk level is at or
   above the brand's "Alert from" level (default Medium). If it is met:
   - decision New or Investigating, and never alerted or below the rule last time: alert with trigger
     `first_crossing` ("First reached High (70)");
   - decision New, Investigating or Confirmed Threat, and a meaningful change (including a risk level increase
     or Candidate -> Finding): alert with trigger `change`;
   - decision False Positive, Legitimate, Ignored or Resolved, and a meaningful change: the decision goes back
     to New with a `reopened` event, and an alert with trigger `reopen` is raised. A threat that gets worse is
     never hidden;
   - otherwise no alert; the observation and "last seen" are all that change.
   Each alert writes an `alerts` row and an `alerted` timeline event.

### Step 9a - Evidence storage

`_store_evidence()` in `backend/app/core/findings.py` and `backend/app/core/evidence.py` handle evidence:

- Files (screenshots, HTML, APKs, documents, WHOIS JSON) go to the S3 bucket `evidence` under
  `findings/<brand id>/<finding id>/<timestamp>-<number>-<kind>.<extension>`. Each file's SHA-256 and size
  are recorded in the `evidence` table, together with the finding and the observation that captured it.
  Files stored before SP2 keep their old `alerts/...` keys.
- Metadata-only evidence (for example DNS records) is stored as JSON in the `evidence` table.
- **Stored once** (D-21): if the same file (same SHA-256) or the same metadata is already stored for this
  finding, it is skipped. A daily re-scan does not pile up identical screenshots; a changed page adds a new one.
- Files that are not images, and SVG images, are stored with "attachment" disposition, so a malicious HTML
  or SVG file never renders inside the browser straight from storage.
- The dashboard shows evidence through **presigned URLs**: temporary links (valid one hour) generated by
  `presigned_url()`.

Nothing fetched from the internet is written anywhere except this bucket.

### Step 10 - Finishing the scan

Each finding is saved in its own small transaction and committed straight away, so progress survives a
later crash. If one finding fails to save, it is recorded on a "Saving findings" component and the scan
carries on. At the end the `scan_runs` row gets:

- **components**: the list of scan parts with their result (D-31);
- **status**: derived from the components (see below);
- **stats**: findings, created, updated, errors, and module-specific counts (for domains: variants
  generated, registered, MX-enabled, unresolved, live websites, and more);
- **error**: the first 50 error lines.

**Components.** Each component has a name, a status, a message and counts. The status is one of:

| Component status | Meaning |
|---|---|
| `ok` (shown as Completed) | This part ran successfully |
| `skipped` | This part did not apply, for example no official domains to check |
| `not_configured` | This part needs a setting or upload that is missing, for example Telegram credentials or an official logo |
| `unavailable` | The source could not be reached or refused, for example the free web search was rate-limited |
| `failed` | This part ran, but some lookups or captures failed part-way |

A component keeps the worst status it reached during the run. A component can also be marked **fatal**: the
run cannot produce results without it.

The components each runner reports:

| Runner | Components |
|---|---|
| `domains` | Variant generation; Certificate Transparency (crt.sh); DNS resolution; WHOIS/RDAP; Website probe & browser capture; TLS certificate; Look-alike email records (SPF/DMARC); Domain checks (only when one domain's check crashes) |
| `apk` | Web search - (provider); Listing pages; Listing analysis (on errors); APK download & analysis |
| `rogue_app` | Google Play search; Listing analysis (on errors); Removal check |
| `social` | Telegram API; Telegram public pages; Web search - (provider); Profile analysis (on errors) |
| `social_media` | YouTube API; Meta Ad Library; Threads API; X API; Telegram post search; Web search - (provider); Browser capture (social media); Content analysis (on errors); Social media sources (fatal, only when no source could be checked) |
| `documents` | Web search - (provider); Download & text extraction; Document analysis (on errors) |
| `logo` | Official logo assets; Target websites; Browser capture |
| `email_posture` | DNS TXT lookups |

"(provider)" is the search provider that actually ran, for example "Web search - Brave Search API" or "Web
search - DuckDuckGo (free, paced)" (`component_name()` in `backend/app/core/search.py`). Any runner can also
get "Saving findings" and "Scan engine" components when something goes wrong in the scan engine itself.

**Scan states.** `derive_run_status()` in `backend/app/modules/base.py` turns the components into one state:

| State | When | Plain meaning |
|---|---|---|
| `queued` | Created, waiting | Waiting for a worker |
| `running` | Being worked on | The scan is in progress |
| `completed` | Every component `ok` or `skipped` | Every part of the scan ran successfully |
| `partially_completed` | At least one component `not_configured` or `unavailable` | Coverage was reduced; results are real but incomplete |
| `completed_with_errors` | At least one component `failed` (this wins over `partially_completed`) | Some lookups or captures failed part-way; results are real but incomplete |
| `failed` | The runner crashed, or a fatal component could not run | Nothing usable was checked, so this is not a clean result |
| `cancelled` | Left queued or running for over 90 minutes | Interrupted (worker restart or timeout); a newer scan replaces it |

Examples of fatal components: the Fake APK and Documents runners end `failed` when **every** web search was
unavailable (with no search results, nothing was checked); the Logo runner ends `failed` with "Official logo
assets: Not configured" when the brand has no official logo.

**Unknown is never "no" (D-31).** A part that could not be checked is never recorded as a negative result:

- A DNS timeout or SERVFAIL leaves the domain **unresolved**, not "not registered". It is counted on the DNS
  resolution component and retried on the next scan (`DnsInfo.status` is `resolved`, `nxdomain` or `unknown`
  in `backend/app/modules/domains/infra.py`).
- A website that answered but could not be captured is shown as "Website Live: unknown (capture failed)". The
  detection carries `live: None` (unknown), so an existing finding only gets a new observation and "last
  seen"; nothing reads as "went offline".
- A failed WHOIS/RDAP lookup shows "lookup failed" for registrar and creation date.
- Without Telegram credentials the social runner reports "Telegram API: Not configured" next to "Telegram
  public pages", so it is clear that only the narrower public-page check ran.
- If one web search of the Fake APK runner fails, the results of the searches that worked are kept.
- A reported email whose analysis still fails after its retries is marked `failed` with the reason
  (`backend/app/workers/tasks.py`) instead of staying `queued`.

The Scans page in the dashboard shows the state, the statistics and, when a row is opened, the component list
under "What this scan checked". The Integrations page uses the same components to show the last result of each
tool (Chapter 10).

### Step 11 - API and dashboard

The API (`backend/app/main.py`) serves everything under `/api/v1`:

| Router | File | What it serves |
|---|---|---|
| auth and users | `backend/app/api/auth.py` | login, current user, user management (admin) |
| brands | `backend/app/api/brands.py` | brands, assets, allowlist |
| alerts | `backend/app/api/alerts.py` | alert list with filters (latest alert per finding), alert detail, decision change (kept as `/status` for compatibility), timeline, evidence links |
| findings | `backend/app/api/findings.py` | findings and candidates with filters, finding detail (timeline, observations, evidence, alerts), single and bulk decisions |
| emails | `backend/app/api/emails.py` | email upload, list, detail |
| scans | `backend/app/api/scans.py` | start a scan, list scan runs |
| stats | `backend/app/api/stats.py` | dashboard numbers and trends, plus scan coverage (last completed scan, scan parts that could not run) |
| integrations | `backend/app/api/integrations.py` | every integration, whether it is configured, how to configure it, its last result |
| exports | `backend/app/api/exports.py` | alerts as CSV or PDF |

The dashboard pages live in `frontend/src/app/(app)/`: the home dashboard (`page.tsx`), `alerts`,
`alerts/[id]`, `findings`, `findings/[id]`, `brands`, `brands/[id]`, `scans`, `integrations`, `emails`,
`emails/[id]` and `settings/users`. The alert detail page shows why the alert was raised (trigger and reason),
the module fields, the **"Why this score"** panel built from the finding's `signals`, the evidence gallery, the
observations and the timeline. Chapter 10 describes the dashboard.

### Step 12 - Analyst workflow

When an analyst records a decision, `POST /api/v1/findings/{id}/decision` (or the compatibility endpoint
`POST /api/v1/alerts/{id}/status`, or the bulk endpoint `POST /api/v1/findings/decision`) calls
`set_decision()` in `backend/app/core/findings.py`. Only these moves are allowed (D-35):

| From | Allowed to |
|---|---|
| New | Investigating, Confirmed Threat, False Positive, Legitimate, Ignored |
| Investigating | New, Confirmed Threat, False Positive, Legitimate, Ignored |
| Confirmed Threat | Investigating, Resolved |
| False Positive, Legitimate, Ignored | New (reopen), Investigating |
| Resolved | New (reopen), Investigating |

A note is required for False Positive, Legitimate and Ignored. Legitimate can also add the entity to the brand
allowlist (domain, app package or social handle). Every change is stored on the finding (`decided_by`,
`decided_at`, `decision_note`) and writes a `decision` (or `reopened`) event on the timeline. A bulk decision
is all-or-nothing. Chapter 10, section 12, explains the workflow in full.

### Email path (a different entry point)

Phishing emails do not come from a scan. They arrive by **upload** (`POST /api/v1/emails`) or by **mailbox
polling** (every 5 minutes, if an IMAP mailbox is configured). The raw email is stored in S3, an
`email_messages` row is created, and the `analyse_email` job runs on the default queue. It ends in the same
`record_detection()` call (with channel `upload` or `mailbox` and no scan ID), so emails get findings,
observations, scores, alerts and evidence exactly like everything else. Chapter 09
explains it.

## 7. Worked example: one look-alike domain, step by step

Example Bank's official domain is `examplebank.com`. Its keyword is "Example Bank". A criminal has
registered `examp1ebank.com` (the "l" replaced by the digit "1"), added a mail server, and put up a login
page that says "Welcome to Example Bank online banking".

| Step | What happens | Files |
|---|---|---|
| 1 | At 02:00 UTC `beat` triggers `schedule_all`. A `scan_runs` row is created for each runner, including `domains`. | `backend/app/workers/celery_app.py`, `backend/app/workers/tasks.py`, `backend/app/workers/scan.py` |
| 2 | The `domains` job goes to the `browser` queue. The `logo` job is chained to run after it. | `backend/app/workers/tasks.py` |
| 3 | The browser worker runs `execute_scan()` and builds the BrandContext for Example Bank. | `backend/app/workers/scan.py`, `backend/app/modules/base.py` |
| 4 | dnstwist generates variants of `examplebank.com`. Its homoglyph fuzzer produces `examp1ebank.com`. | `backend/app/modules/domains/variants.py` |
| 5 | The NS, A and MX records are looked up through public DNS resolvers. `examp1ebank.com` has records, so it is **registered**. It also has an MX record. | `backend/app/modules/domains/infra.py` |
| 6 | WHOIS (RDAP) data is fetched: registrar and creation date. | `backend/app/modules/domains/infra.py` |
| 7 | Ports 443 and 80 are tested. Port 443 answers, so the headless browser opens `https://examp1ebank.com/`, takes a full-page screenshot, and collects title, text, HTML, favicon and images. Every request is checked by the safe fetcher's rules. | `backend/app/core/browser.py`, `backend/app/core/fetch.py` |
| 8 | The page is analysed: the words "login" and "password" are found; "Example Bank" appears in the text (brand evidence); it is not a parked page. The logo does not match closely enough. | `backend/app/modules/pagecheck.py`, `backend/app/core/imaging.py` |
| 9 | The TLS certificate is read: HTTPS is present. The domain has no SPF record. | `backend/app/core/fetch.py`, `backend/app/modules/domains/module.py` |
| 10 | Similarity: reading `1` as `l` gives `examplebank`, so similarity is 100. The exact brand text `examplebank` is not in `examp1ebank`, so "exact match" does not fire. | `backend/app/core/similarity.py` |
| 11 | Signals: typo similarity 100, MX present, HTTPS, login keywords, page live, brand on page. Stage: **phishing** (site is live). Suspected Phishing: **yes** (live, brand shown, not parked, similarity at least 80, login words). | `backend/app/modules/domains/module.py` |
| 12 | A `domain_checks` row records the check. A Detection is yielded with evidence: DNS, WHOIS, screenshot, favicon, HTML, TLS. The site is live, so it is `analysed` (stage **Finding**). | `backend/app/modules/domains/module.py` |
| 13 | Score: typo similarity +25, MX +15, HTTPS +10, login keywords +20 = **70 -> High**. No cap (brand is on the page). | `backend/app/core/scoring.py` |
| 14 | No finding exists for this domain, so one is created: decision New, title "Suspected phishing website: examp1ebank.com", timeline event "Finding found by phishing module, risk High (70)", and one observation for this scan. Email Risk detail: **High** (MX and live site). | `backend/app/core/findings.py` |
| 15 | Evidence files are uploaded to `findings/<brand>/<finding>/...` in the S3 bucket with their SHA-256, linked to the observation. | `backend/app/core/evidence.py` |
| 15a | Alert rule: stage Finding, High is at or above Example Bank's "Alert from" level (Medium). An alert record is raised with trigger `first_crossing` and reason "First reached High (70)". | `backend/app/core/findings.py` |
| 16 | The finding is committed. Every component ran without problems, so the scan run ends `completed` with its statistics and component list. (Had crt.sh returned an error, it would end `completed_with_errors`.) | `backend/app/workers/scan.py`, `backend/app/modules/base.py` |
| 17 | The analyst opens the dashboard. The alert is in the queue as High, with a Suspected Phishing marker and a screenshot thumbnail. "Why this alert" shows "First reached High (70)"; the "Why this score" panel lists the four rules and their points. The analyst sets the decision to Investigating. | `backend/app/api/alerts.py`, `frontend/src/app/(app)/alerts/[id]/page.tsx` |
| 18 | Next day the criminal adds the official logo. The re-scan stores a second observation and finds the logo (+30): 100 -> **Critical**. The timeline gets "Official logo detected" (`changed`) and "Risk High -> Critical (100)" (`rescored`). Because these are meaningful changes, a second alert is raised with trigger `change`. The new screenshot is stored; the unchanged WHOIS data is not stored again. | `backend/app/core/findings.py` |
| 19 | The day after, nothing has changed. The re-scan stores a third observation and updates "last seen". No new alert is raised. | `backend/app/core/findings.py` |

## 8. Why "one finding per domain" matters

Without D-19, `examp1ebank.com` could appear three times: as a typosquat, as an MX domain and as a phishing
site. With D-19 it is one finding whose module moves forward as the domain gets more dangerous. The timeline
and the observations show the story, e.g. "registered on Monday (Candidate), mail server on Tuesday (promoted to
Finding), live login page on Thursday (website went live, risk up, new alert)".

## 9. The safe fetcher, and why it exists

The platform deliberately visits dangerous websites. That creates a risk called **SSRF** (Server-Side
Request Forgery). A criminal could make a look-alike domain point to an internal address, such as
`127.0.0.1` (the server itself), `10.0.0.5` (a private network) or `169.254.169.254` (the cloud metadata
service that can hand out cloud passwords). If the platform blindly fetched that domain, it would be
attacking its own network on the criminal's behalf.

To prevent this, `backend/app/core/fetch.py` is **the only code allowed to fetch URLs** (D-18). Its rules:

| Protection | How |
|---|---|
| Only web addresses | Only `http` and `https` are allowed. |
| No internal addresses | Every IP address the host name resolves to is checked. Private, loopback, link-local, reserved, multicast and cloud-metadata addresses are blocked. |
| Checked on every redirect | Redirects are followed by hand, at most 5, and each new address is checked again. |
| DNS rebinding guard | After connecting, the actual address connected to is checked again, in case DNS changed between check and connect. |
| NAT64 networks | Addresses in `64:ff9b::/96` are judged by the IPv4 address they carry, so public sites work on IPv6-only networks while private ones stay blocked (D-24). |
| Timeouts | 15 seconds by default. |
| Retries | Up to 3 attempts with growing waits, on network errors, server errors (5xx) and "too many requests" (429). |
| Rate limit per host | 30 requests per minute per host by default, shared between all workers through Redis. |
| Size cap | 25 MB by default (150 MB for APKs). Download stops as soon as the limit is passed. |
| No secrets leak | Custom headers such as API keys are not sent when a redirect goes to another host. |
| In memory only | Content is returned in memory. Only `backend/app/core/evidence.py` saves anything, and only to the evidence bucket. |

The headless browser follows the same rules. `backend/app/core/browser.py` checks the start URL, then
checks **every request the page makes** (images, scripts, frames) against the same destination rules and
blocks the ones that fail. Downloads are refused and service workers are blocked.

Downloaded files (APKs, documents, email attachments) are stored, hashed and analysed as data. They are
never opened or run.

## 10. Authentication and roles

Login is handled by `backend/app/api/auth.py` and `backend/app/core/security.py` (D-15):

1. The user sends email and password to `POST /api/v1/auth/login`.
2. The password is checked against an **Argon2** hash. Argon2 is a slow, memory-hungry hashing method that
   makes stolen hashes hard to crack.
3. On success the API returns a **JWT** (JSON Web Token): a signed token that contains the user ID and
   role, valid for 12 hours by default.
4. The dashboard keeps the token in the browser's local storage and sends it on every request as
   `Authorization: Bearer <token>`.
5. Every endpoint checks the token (`current_user`). Admin-only endpoints also check the role
   (`require_admin`) and return "403 Admin role required" otherwise.

| Action | Analyst | Admin |
|---|---|---|
| View dashboard, brands, alerts, evidence, scans, emails | Yes | Yes |
| Run scans, record decisions on findings (alone or in bulk), export, upload emails | Yes | Yes |
| Create, edit, delete brands; upload logos; edit allowlist | No | Yes |
| Create and manage users | No | Yes |

An admin cannot deactivate or demote their own account. In production (`ENV=production`) the API refuses
to start with default secrets, a JWT secret shorter than 32 characters, private-host exceptions in the
fetcher (`check_production()` in `backend/app/config.py`). There is no demo mode setting any more (D-32).

## 11. Scheduling

The schedule is in `backend/app/workers/celery_app.py`. All times are UTC.

| Job | When | What it does |
|---|---|---|
| `daily-full-scan` | Every day at 02:00 | Every runner for every active brand |
| `domain-recheck` | Every 6 hours at minute 30 (00:30, 06:30, 12:30, 18:30) | The `domains` runner only, because domains change fastest |
| `poll-reporting-mailbox` | Every 5 minutes | Reads new emails from the phishing reporting mailbox, if configured |
| `poll-dmarc-mailbox` | Every hour at minute 15 | Reads DMARC aggregate reports, if configured |
| `email-posture` | Every day at 03:00 | Checks SPF, DMARC, DKIM and MTA-STS on the brand's own domains |

Inactive brands (monitoring paused) are skipped by the scheduled scans.

## Key takeaways

- Eleven containers run from one Compose file. Four of them share one backend image with different start commands.
- A scan is a chain: schedule or button, scan run row, Celery queue, runner, candidates, checks, detections, `record_detection()`, finding + observation + timeline, and an alert only when the rule is met.
- Browser-heavy runners (domains, logo, social, social_media) use the `browser` queue; the rest use `default`.
- Every scan run lists its components (what ran, what was not configured or unavailable, what failed). Its state (`completed`, `partially_completed`, `completed_with_errors`, `failed`, `cancelled`) is derived from them. Unknown is never recorded as "no".
- Modules only report signals. `backend/app/core/scoring.py` alone turns them into a score and level.
- Findings are deduplicated by brand, module and entity key; one domain has one finding. Every scan adds an observation. An alert is raised only for a Finding (not a Candidate) at or above the brand's "Alert from" level, on first crossing or a meaningful change; a meaningful change re-opens a closed decision (D-33 to D-36).
- All internet access goes through the safe fetcher, which blocks internal addresses (SSRF), limits size and speed, and never runs downloaded files.
