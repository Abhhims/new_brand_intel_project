# Chapter 12 - Operations and Testing

In this chapter:
- How to install and start the platform with Docker Compose, which ports it uses, and how the first admin is created.
- Day-to-day operation: adding a brand, running scans, schedules, configuration keys, backups, logs and troubleshooting (including Windows notes).
- How the automated tests are organised: unit, module acceptance, API and browser end-to-end tests.
- How requirement markers on tests produce the UAT report, and why the fictional test brand lives only inside the test suite (decisions D-27, D-30 and D-32).

## 1. Plain words first

| Word | Meaning |
|---|---|
| Container | A packaged program with everything it needs, run by Docker. Each part of the platform (database, API, workers, website) is one container. |
| Docker Compose | A tool that starts many containers from one file, `deploy/docker-compose.yml`. |
| Profile | A label in the Compose file. Services with a profile only start when you ask for that profile. This project uses `app` (the product) and `test` (the test website). |
| Environment variable | A setting given to a program from outside, for example `JWT_SECRET=...`. Here they live in `deploy/.env`. |
| Migration | A versioned change to the database tables, applied by Alembic. |
| Worker | A background process that runs scans. Workers take tasks from a queue in Redis. |
| UAT | User Acceptance Testing: the check that the platform does what the requirements ask. |

A note on timing. Roadmap sub-project 1 (SP1, "honest scan status", Chapter 13) is complete as of
2026-10-09. This chapter describes the platform after SP1: scan states `queued`, `running`, `completed`,
`partially_completed`, `completed_with_errors`, `failed` and `cancelled`, per-component scan results, the
Integrations page, and no demo mode in the product (decisions D-31 and D-32). SP2 (the finding model:
candidates, findings, alerts, observations and analyst decisions, D-33 to D-37) and the social media
brand-misuse monitor (D-38, Chapter 14) were completed the same day and are described here too.

## 2. What runs, and on which ports

```
   Analyst browser
         |
         v
   +-----------------+
   | web (Next.js)   |  port 3000
   +-----------------+
         |  REST/JSON
         v
   +-----------------+          +-----------------+
   | api (FastAPI)   |--------->| postgres        |  port 5432
   | port 8010       |          +-----------------+
   +-----------------+                 ^
         | queue tasks                 | read/write
         v                             |
   +-----------------+          +--------------------------------+
   | redis           |--------->| worker          (queue default)|
   | port 6379       |--------->| browser-worker  (queue browser)|
   +-----------------+          +--------------------------------+
         ^                             |
         | scheduled tasks             | evidence files
   +-----------------+          +-----------------+
   | beat            |          | minio (RustFS)  |  ports 9000 and 9001
   +-----------------+          +-----------------+

   Email engines (profile app):  rspamd 11333, clamav 3310
   Test website (profile test):  fixtures (nginx) 8088
```

| Service | Profile | Purpose | Host port (key in `.env`) |
|---|---|---|---|
| `postgres` | always | Database (PostgreSQL 17) | 5432 (`POSTGRES_PORT`) |
| `redis` | always | Task queue, rate limits, caches | 6379 (`REDIS_PORT`) |
| `minio` | always | Evidence store; the image is RustFS (D-22) | 9000 and 9001 (`MINIO_PORT`, `MINIO_CONSOLE_PORT`) |
| `api` | app | REST API. On start it runs `alembic upgrade head`, then `scripts.bootstrap`, then Uvicorn | 8010 (`API_PORT`) |
| `worker` | app | Celery worker, queue `default`, 4 at a time | - |
| `browser-worker` | app | Celery worker, queue `browser` (headless Chromium), 2 at a time, 1 GB shared memory | - |
| `beat` | app | Celery scheduler | - |
| `web` | app | Analyst dashboard | 3000 (`WEB_PORT`) |
| `rspamd` | app | Email spam/phishing engine | 11333 (`RSPAMD_PORT`) |
| `clamav` | app | Antivirus for email attachments (about 1.5 GB RAM) | 3310 (`CLAMAV_PORT`) |
| `fixtures` | test | Test website for automated tests only | 8088 (`FIXTURES_PORT`) |

Server size (from `docs/guides/DEPLOYMENT.md`): Linux with Docker Engine 24 or later, at least 4 vCPU,
8 GB RAM and 60 GB disk for up to about 20 brands. Outbound HTTP/HTTPS and DNS (port 53) are needed. The
browser work is the heaviest part.

## 3. Install and start

### Step by step

1. Get the code and create the settings file:

```
git clone <repository> brandintel
cd brandintel
cp deploy/.env.example deploy/.env
```

2. Edit `deploy/.env`. Change every value marked `CHANGE`: `POSTGRES_PASSWORD`, `S3_SECRET_KEY`,
   `JWT_SECRET` (48 or more random characters), `BOOTSTRAP_ADMIN_PASSWORD`. Set `BOOTSTRAP_ADMIN_EMAIL`. For
   production also set `ENV=production`.

3. Start everything:

```
docker compose -f deploy/docker-compose.yml --profile app up -d --build
docker compose -f deploy/docker-compose.yml --profile app ps
curl -fs http://localhost:8010/health
```

The health check answers `{"status":"ok","database":"ok"}`.

4. Open `http://localhost:3000` and sign in with the bootstrap admin.

### The first admin

`backend/scripts/bootstrap.py` runs every time the API starts. If the `users` table is empty, it creates one
admin from `BOOTSTRAP_ADMIN_EMAIL` and `BOOTSTRAP_ADMIN_PASSWORD`. If any user exists, it does nothing.
Change the password after the first login (Users page). Then create a named account for every analyst. There
is no self-registration (D-15, D-27).

### Production safety check

With `ENV=production`, the backend refuses to start (`check_production` in `backend/app/config.py`) when:

- `JWT_SECRET`, `BOOTSTRAP_ADMIN_PASSWORD` or `S3_SECRET_KEY` still have their default values;
- `JWT_SECRET` is shorter than 32 characters;
- `FETCH_ALLOW_PRIVATE_HOSTS` is not empty.

There is no demo mode setting to check: `ALLOW_DEMO_MODE`, `FIXTURES_DIR` and `FIXTURES_BASE_URL` were
removed from the product settings (D-32).

The error says "Insecure production configuration" and lists the problems.

### Behind a reverse proxy

Put a proxy with TLS (for example Caddy or nginx) in front of ports 3000 and 8010. Then set
`PUBLIC_API_URL` to the public API address and rebuild `web`, because the address is built into the web app.
Set `CORS_ORIGINS` to the dashboard address. If analysts must open evidence files, set
`S3_PUBLIC_ENDPOINT_URL` to a storage address their browsers can reach.

### Upgrades

```
git pull
docker compose -f deploy/docker-compose.yml --profile app up -d --build
```

The API applies new migrations on start.

## 4. Day-to-day operation

### Adding a brand (admin)

Using Example Bank as the example:

1. Brands, then "Add a brand". Name: Example Bank. Keywords: `examplebank`, `example bank`. Product terms:
   `ExamplePay`. Monitoring active: on.
2. On the brand page, upload the official logo, favicon and app icon (PNG, JPG, GIF, WEBP, ICO or BMP, up to 5 MB).
3. Fill the allowlists: official domains (`examplebank.com`), email domains, app packages
   (`com.examplebank.app`), publishers (Example Bank Ltd), social handles, and the app signing certificate
   SHA-256 from Play Console.
4. Click "Run scan now", or wait for the 02:00 UTC schedule.

`docs/guides/BRAND-CONFIGURATION.md` has more detail. Chapter 10 explains every field.

### Running scans

A scan can be started three ways:

| Way | How | Who |
|---|---|---|
| Dashboard | Brand page, "Run scan now", all modules or chosen modules | Any signed-in user |
| API | `POST /api/v1/scans` with `{"brand_id": "...", "modules": ["typosquat", "apk"]}` (omit `modules` for all) | Any signed-in user |
| Schedule | Celery beat (below) | Automatic, active brands only |

One "scan" creates one scan run per **runner**. The runners are `domains` (covers Typosquat, MX and Active
Phishing, D-19), `apk`, `rogue_app`, `social`, `social_media`, `documents`, `logo` and `email_posture`. The `domains`, `logo`,
`social` and `social_media` runners use the browser queue. The logo scan waits until the domain scan ends, so it can crawl the
live look-alike sites just found. Progress shows on the Scans page: each run ends `completed`,
`partially_completed` (some sources not configured or unavailable), `completed_with_errors` (some lookups
failed part-way), `failed` (nothing could be checked) or `cancelled` (interrupted). Open a row to see "What
this scan checked": every component with its result and reason (D-31, Chapter 01 Step 10). The Integrations
page shows which tools are configured and how each one last ran.

### Schedules

Defined in `beat_schedule` in `backend/app/workers/celery_app.py`. All times are UTC.

| Job | When | What |
|---|---|---|
| `daily-full-scan` | 02:00 every day | Every runner for every active brand (TYP-12) |
| `domain-recheck` | Every 6 hours at :30 | The `domains` runner only, because look-alike domains change fastest |
| `email-posture` | 03:00 every day | The brand's own SPF, DMARC, DKIM and MTA-STS records |
| `poll-reporting-mailbox` | Every 5 minutes | Reads the reporting mailbox, if configured |
| `poll-dmarc-mailbox` | Every hour at :15 | Reads DMARC aggregate reports, if configured |

Scan tasks retry twice on infrastructure failure (database or Redis down), with a 2-minute delay. Each task
has a 1-hour limit. A run still queued or running after 90 minutes is closed as `cancelled` with
"Interrupted (worker restarted or timed out); a newer scan replaces it" the next time that brand is scanned.
A reported email whose analysis still fails after its retries is marked `failed` with the reason.

## 5. Configuration keys

All keys are read by `backend/app/config.py` from environment variables or `deploy/.env`. Empty values count
as "not set". The most important keys:

| Group | Key | Default | Meaning |
|---|---|---|---|
| General | `ENV` | development | `production` turns on the safety check |
| Database | `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB` | brandintel | Bundled database |
| Database | `DATABASE_URL` | local brandintel database | Full connection string; set automatically inside Compose |
| Queue | `REDIS_URL` | `redis://localhost:6379/0` | Set automatically inside Compose |
| Storage | `S3_ENDPOINT_URL`, `S3_ACCESS_KEY`, `S3_SECRET_KEY`, `S3_BUCKET`, `S3_REGION` | local RustFS, bucket `evidence` | Any S3-compatible store |
| Storage | `S3_PUBLIC_ENDPOINT_URL` | none | Address browsers use for evidence links |
| Auth | `JWT_SECRET`, `JWT_EXPIRE_MINUTES` | (insecure default), 720 | Token signing key and lifetime |
| Auth | `BOOTSTRAP_ADMIN_EMAIL`, `BOOTSTRAP_ADMIN_PASSWORD` | placeholders | First admin |
| Web | `PUBLIC_API_URL`, `CORS_ORIGINS`, `API_PORT`, `WEB_PORT` | localhost values | Addresses and ports |
| Fetcher | `FETCH_TIMEOUT_SECONDS`, `FETCH_MAX_BYTES`, `FETCH_MAX_APK_BYTES`, `FETCH_MAX_REDIRECTS`, `FETCH_RATE_PER_HOST_PER_MINUTE` | 15 s, 25 MB, 150 MB, 5, 30 | Safe fetcher limits (D-18) |
| Fetcher | `FETCH_ALLOW_PRIVATE_HOSTS` | `[]` | Must stay empty outside tests |
| Search | `BRAVE_SEARCH_API_KEY`, `SERPAPI_API_KEY` | none | Web-search providers (Brave first) |
| Search | `FREE_SEARCH_FALLBACK`, `FREE_SEARCH_INTERVAL_SECONDS` | true, 12 | DuckDuckGo fallback and its pace (D-23) |
| Telegram | `TELEGRAM_API_ID`, `TELEGRAM_API_HASH`, `TELEGRAM_SESSION`, `TELEGRAM_PUBLIC_FALLBACK` | none, none, none, true | Official API; session created once with `python -m scripts.telegram_login`. Also used for Telegram post search (Chapter 14) |
| Social media | `YOUTUBE_API_KEY`, `META_AD_LIBRARY_TOKEN`, `META_AD_COUNTRIES`, `THREADS_ACCESS_TOKEN`, `X_BEARER_TOKEN` | none, none, `["IN"]`, none, none | Official APIs for the social media brand-misuse monitor; each missing key shows "Not configured" for that source. Chapter 14 explains how to obtain each one |
| Social media | `SOCIAL_MEDIA_LOOKBACK_DAYS`, `SOCIAL_MEDIA_MAX_ITEMS` | 30, 60 | Only content from the last N days; at most N items (each with a screenshot) per scan and brand |
| Email engines | `RSPAMD_URL`, `CLAMAV_HOST`, `CLAMAV_PORT`, `CLAMAV_ENABLED`, `YARA_RULES_DIR` | container names, 3310, true, `rules/yara` | Email analysis engines |
| Threat intel | `URLHAUS_AUTH_KEY`, `URLSCAN_API_KEY`, `ABUSEIPDB_API_KEY`, `OPENPHISH_FEED_URL` | none (feed URL set) | Without a key that source is "not checked" |
| Intake | `IMAP_*`, `DMARC_IMAP_*`, `MS_GRAPH_*`, `GMAIL_*` | none | Reporting and DMARC mailboxes |
| Tuning | `TYPO_TLDS`, `LOGO_MATCH_THRESHOLD`, `PHISHING_SIMILARITY_THRESHOLD` | 11 TLDs, 85, 80 | Detection tuning |
| Tests only (not product settings) | `FIXTURES_BASE_URL` | `http://localhost:8088` | Read only by `backend/tests/support/fixture_sources.py` to reach the test website (D-32) |

After changing `.env`, restart the affected containers:
`docker compose -f deploy/docker-compose.yml --profile app up -d`.

## 6. Backups

```
# Database (daily, keep 30 days)
docker compose -f deploy/docker-compose.yml exec -T postgres pg_dump -U brandintel -Fc brandintel > backup-YYYY-MM-DD.dump

# Restore
docker compose -f deploy/docker-compose.yml exec -T postgres pg_restore -U brandintel -d brandintel --clean < backup-YYYY-MM-DD.dump
```

Evidence files are in the `miniodata` Docker volume. Back up that volume, or use an S3 bucket with versioning
or replication. Back up `deploy/.env` separately and keep it secret. A database backup without the matching
evidence files leaves findings whose screenshots cannot be opened.

## 7. Logs and health

Every service writes one JSON object per line to standard output (structlog).

```
docker compose -f deploy/docker-compose.yml logs -f api
docker compose -f deploy/docker-compose.yml logs -f worker browser-worker
```

| Where to look | What you find |
|---|---|
| API log | One line per request with `request_id`, method, path, status and milliseconds |
| Worker logs | `scan_finished`, `detection_recorded` (one per stored detection, with finding ID, stage, level and whether it alerted), `fetch_failed`, `ct_search_failed`, `rspamd_unavailable` and similar events |
| Scans page | State, counts, error text and the component checklist ("What this scan checked") of every scan |
| Integrations page | Every tool: configured or not, how to configure it, last result |
| `x-request-id` header | Every API response carries one; an error body includes it, so a user's report can be matched to a log line |
| `GET /health` | Database check; 503 when degraded. Used by the Docker health check |
| Worker health | `celery inspect ping` every 60 seconds |

## 8. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Scan `partially_completed` with "Web search - DuckDuckGo (free, paced): Unavailable ... paused" | No search key; the free fallback was rate-limited and pauses 15 minutes. Set `BRAVE_SEARCH_API_KEY` and restart workers. |
| Fake APK or Documents scan `failed` because no web search worked | Same cause; with no search results nothing was checked, so the run is not shown as clean. |
| Scan `completed_with_errors` with "Certificate Transparency (crt.sh): ... 502" | crt.sh is overloaded. The next scan retries; typo variants still run. |
| Scan `completed_with_errors` with "DNS resolution: N domains could not be resolved (timeout/SERVFAIL)" | Slow or failing resolvers. Those domains are unresolved, not unregistered, and are retried next scan. If it persists, check outbound port 53. |
| Social scan `partially_completed` with "Telegram API: Not configured" | No Telegram credentials; only public `t.me` pages were checked. Set the three `TELEGRAM_*` values (Integrations page shows how). |
| Logo scan `failed` with "Official logo assets: Not configured" | Upload an official logo on the brand page. |
| Social media scan `partially_completed` with "YouTube API: Not configured" (or Meta Ad Library, Threads API, X API) | That API key is not set in `deploy/.env`; only web search covered that platform. Chapter 14 explains how to obtain each key. |
| Social media scan `failed` with "Social media sources: no source could be checked" | No API key is set and web search was unavailable too. Add a search key (`BRAVE_SEARCH_API_KEY`) or at least one social media API key. |
| A scan finished, findings were stored, but no new alerts appeared | Expected when the findings are Candidates, below the brand's "Alert from" level, or unchanged since the last scan (D-33 to D-36). Check the Findings page with "Not alerted". |
| Scan `cancelled` with "Interrupted" | A worker restarted during the scan. Run it again. |
| Scan `failed` with "Task queue: Could not queue scan" | Redis or the workers are down. Check `docker compose ps`. |
| No screenshots | `browser-worker` not running or out of memory. Check its log. |
| Evidence images do not open | `S3_PUBLIC_ENDPOINT_URL` is not reachable from the analyst's browser. |
| Alerts for an unrelated company with the same abbreviation | Add more distinctive keywords and product terms (D-25). |
| API refuses to start: "Insecure production configuration" | Replace default secrets in `deploy/.env` (section 3). |
| Login rejected with a correct password | The account is deactivated. An admin re-activates it on the Users page. |
| PDF export returns 503 | The API runs outside Docker (for example on Windows) without Pango. Use the Docker image. |
| ClamAV verdicts are "not checked" right after start | ClamAV needs about a minute to load signatures (health check start period is 2 minutes). |

### Windows notes

- **Run the backend in Docker.** WeasyPrint (PDF export) needs GTK/Pango, and python-magic needs libmagic.
  Neither works natively on Windows. On Windows, document type detection falls back to the file extension and
  PDF export returns 503.
- If you still run Python natively for development: install uv with pip and call it as `python -m uv`. On
  machines with Windows Application Control, uv cannot build source-only packages in its temporary
  environment. Pre-built wheels are kept in `backend/wheels/` and found through `[tool.uv] find-links` in
  `backend/pyproject.toml`.
- Celery on Windows needs the solo pool: `celery -A app.workers.celery_app worker -Q default,browser -P solo`.
- Docker Desktop is used on Windows. Large companies need a paid Docker Desktop subscription.

## 9. How the tests are organised

All tests are in `backend/tests` and run with pytest. They are split into four kinds:

| Kind | Folder | Needs | What it proves |
|---|---|---|---|
| Unit | `backend/tests/unit` | Nothing running | Pure logic: scoring and boundaries, similarity, safe fetcher rules, page checks, allowlist normalisation, email parsing, authentication, engines, intel, DMARC parsing, posture, task wiring; scan-state derivation and component reporting (`test_scan_report.py`, `test_domain_reporting.py`, `test_runner_reporting.py`); a guard that product code contains no demo or fixture paths (`test_no_test_data_in_product.py`) |
| Module acceptance | `backend/tests/modules/test_acceptance.py` | PostgreSQL, Redis, the S3 store and the **test website** on port 8088 | Each acceptance criterion AC-01 to AC-10: six runners (all except `email_posture`, which checks the real DNS of real domains; the fictional brand has none) run through the real scan engine with simulated sources injected by `fixture_runner` (`backend/tests/support/fixture_sources.py`), with a real database, real evidence storage and a real headless browser; every run must record its components |
| API | `backend/tests/api` | Same infrastructure | Endpoints: login, roles, brand onboarding (a `demo_mode` field is rejected), filters, search, exports, decision changes through the compatibility status endpoint, email upload, scans with components, `/integrations`, dashboard coverage fields; the finding model in `test_findings.py` (table below) |
| Browser end-to-end | `backend/tests/e2e/test_ui.py` | The full running stack plus `E2E_WEB_URL`, `E2E_EMAIL`, `E2E_PASSWORD` | Real browser clicks through dashboard, queue, detail and decision change; the coverage banner, the error panel when the API fails, the scan component list and the Integrations page. Read-only unless `E2E_ALLOW_WRITE=1`. Saves screenshots to `docs/demo/screenshots/` |

### New tests for SP2 and the social media monitor

The finding model (SP2) is tested in `backend/tests/api/test_findings.py`. It needs the test database; each test
feeds detections straight into `record_detection()` and checks findings, observations, timeline and alerts.

| Test | What it proves | Markers |
|---|---|---|
| `test_candidate_never_alerts_and_promotion_alerts` | A Candidate raises no alert, whatever its score; when the next scan analyses it, it is promoted to Finding and alerts | RDA-12, D-33 |
| `test_brand_alert_level_holds_back_lower_findings` | Findings below the brand's "Alert from" level are stored but not alerted | RDA-12, D-34 |
| `test_rescan_stores_observation_without_new_finding_or_alert` | A second identical scan adds one observation, no new finding and no new alert | RDA-15, D-36 |
| `test_meaningful_change_raises_new_alert_on_timeline` | A site that goes live gets one `changed` event and one new alert | RDA-15, D-36 |
| `test_unknown_state_is_not_a_change` | A failed capture (unknown value) is not treated as a change | RDA-15, D-31 |
| `test_closed_decision_suppresses_until_meaningful_change_reopens` | After False Positive (and the other closed decisions) re-scans stay quiet until a meaningful change reopens the finding to New with a `reopen` alert | RDA-11, D-35, D-36 |
| `test_findings_api_filters_decisions_and_allowlist` | `/findings` filters; Legitimate with "add to allowlist"; a bulk decision without a required note is refused with 409 and changes nothing, with the note it applies to all | RDA-11, RDA-12, D-35 |

The social media brand-misuse module (Chapter 14) is tested in `backend/tests/modules/test_social_media.py`. It
needs nothing running: sources and the browser capture are simulated in the test.

| Test | What it proves | Markers |
|---|---|---|
| `test_contact_details_and_scam_wording` | Phone numbers, WhatsApp and Telegram links and UPI IDs are extracted, and scam phrases are found | SMM-03 |
| `test_scam_video_is_flagged_with_screenshot_and_alert_level` | A scam video with contact details is flagged with a screenshot as evidence and scores at alert level | SMM-01, SMM-02, SMM-03, SMM-06 |
| `test_official_irrelevant_and_mention_only` | The brand's own channel is skipped, unrelated content is dropped, and a bare uncaptured mention is a Candidate scored Low | SMM-04 |
| `test_no_source_checked_fails_the_run` | When no source could be checked, a fatal component is recorded, so the run fails instead of reporting "nothing found" | SMM-05, D-31 |

Isolation rules (`backend/tests/conftest.py`):

- Tests set `ENV=test` and a long test JWT secret.
- They use their own database `brandintel_test` (dropped and rebuilt with the real Alembic migrations each
  session) and their own bucket `evidence-test`. Your product data is never touched.
- There is no demo mode to switch on. The acceptance tests replace the scan engine's `get_runner` with
  `fixture_runner` (`backend/tests/support/fixture_sources.py`), which builds the real module runners with
  simulated sources injected through their constructors.
- Celery runs tasks inline (`CELERY_TASK_ALWAYS_EAGER=1`).
- The safe fetcher may reach `localhost` only inside tests that ask for it (the `fixtures_site` fixture).
- If PostgreSQL, the S3 store or the test website is not reachable, integration tests are **skipped** with a
  message telling you to start the `test` profile.

### Running the tests

```
docker compose -f deploy/docker-compose.yml up -d postgres redis minio
docker compose -f deploy/docker-compose.yml --profile test up -d fixtures
cd backend
python -m uv run pytest                      # unit + acceptance + API (about 90 seconds)
python -m uv run ruff check app scripts tests

# Browser end-to-end, against the running stack:
E2E_WEB_URL=http://localhost:3000 E2E_API_URL=http://localhost:8010 \
E2E_EMAIL=<admin> E2E_PASSWORD=<password> REQ_RESULTS_APPEND=1 \
python -m uv run pytest tests/e2e

python -m uv run python -m scripts.uat_report    # writes docs/reports/UAT-REPORT.md
cd ../frontend && npm run lint && npm run build
```

### The test website

`backend/tests/fixtures/site` holds a small static website served by the `fixtures` container (nginx).
It has pages that play the roles of a phishing site, a parked domain, an innocent unrelated site and a
partner site, plus APK files, documents and social profile pages. The simulated search results,
DNS answers, Certificate Transparency rows, Play Store and social results are JSON files in
`backend/tests/fixtures/sources`, read by the `Fixture*` source classes and `FixtureInfra` in
`backend/tests/support/fixture_sources.py`. Test emails are in `backend/tests/fixtures/emails`. Test APKs are
built by `backend/tests/support/build_apk_fixtures.py` and test emails by
`backend/tests/support/build_email_fixtures.py`.

## 10. From test markers to the UAT report

Every test that proves a requirement carries a marker with the requirement IDs:

```
@pytest.mark.req("AC-02", "MX-01", "MX-02", "MX-03", "MX-04")
def test_ac02_mx_records_resolved_and_stored(scanned, db):
    ...
```

The pipeline:

```
 pytest run
   |  conftest.py hook records every test: name, outcome, requirement IDs, duration
   v
 backend/reports/requirements-results.json
   |  (REQ_RESULTS_APPEND=1 adds the e2e run to the same file)
   v
 python -m scripts.uat_report
   |  reads docs/requirements/01-requirements-register.md
   |  matches each requirement ID with its tests
   v
 docs/reports/UAT-REPORT.md
```

`backend/scripts/uat_report.py` gives every requirement one status:

| Status | Meaning |
|---|---|
| PASS | Every test tagged with the ID passed |
| FAIL | At least one tagged test failed |
| VERIFIED | No test, but a listed artefact exists (for example `docs/guides/DEPLOYMENT.md` for FND-15) |
| N/A | Out of scope, confirmed not built (OOS-01 to OOS-05) |
| DEFERRED | Moved to Phase 2 by a recorded decision (ROG-02, D-13) |
| OPEN | No evidence yet |

The report opens with the acceptance criteria AC-01 to AC-10, then lists every requirement by section. The
last generated report (2026-10-08) shows 271 tests passed, 0 failed, 9 skipped, and 173 of 189 requirements
satisfied. It was generated before SP1, so it does not yet include the SP1 tests tagged RDA-01 to RDA-04,
RDA-17, RDA-19 and RDA-21. Regenerate the report after every test run; never edit it by hand.

## 11. Why the test brand exists only inside the tests

The acceptance criteria ask the platform to detect **simulated** fake APKs and social accounts. To prove that
repeatably, the tests need a brand whose "attackers" are fully under our control. That brand is fictional.
Its official data is in `backend/tests/fixtures/brand/zentrova.json`, with its logo, favicon and app icon
next to it. `seed()` in `backend/tests/support/seed_test_brand.py` creates it in the test database before the
acceptance tests run (it used to be `backend/scripts/seed_demo.py`).

Two decisions keep this test data out of the product:

| Decision | Date | What it says |
|---|---|---|
| D-27 | 2026-10-07 | The product shows only data scanned from live sources. Demo mode is off (`ALLOW_DEMO_MODE=false`). The brand form has no demo switch, the API rejects `demo_mode=true`, scans refuse to run a demo-mode brand, and the test website starts only with the `test` profile. The test brand is used only by the automated tests, in their own database and bucket. D-32 later removed the demo switch from the code entirely. |
| D-30 | 2026-10-09 | The test brand and simulated sources moved from the top-level `fixtures/` folder to `backend/tests/fixtures/`. Product containers do not mount them, and `.dockerignore` keeps `backend/tests` and the fixture build scripts out of the backend image. The UI no longer uses the test brand as example text. |
| D-32 | 2026-10-09 | Demo mode is removed from the product: no `brands.demo_mode` column, no `ALLOW_DEMO_MODE`, `FIXTURES_DIR` or `FIXTURES_BASE_URL` settings, no demo switch, tag, banner or "Demo data" chip. The simulated sources live only in `backend/tests/support/` and are injected into the real runners by the tests. The migration refuses to run while a demo brand exists. DEL-08 (sample data and seed script) is satisfied inside the test suite only. |

Why it matters:

- **Trust.** Every alert an analyst sees must come from a real scan. A made-up alert in the product would
  damage confidence in all alerts.
- **Safety.** The test website needs the safe fetcher to reach `localhost`. That permission
  (`FETCH_ALLOW_PRIVATE_HOSTS`) must never be on in production, and the production check refuses it.
- **Repeatability.** The tests still have a complete, controlled brand, so AC-01 to AC-10 are proven the same
  way on every run.

## Key takeaways

- One Compose file runs everything. Profile `app` starts the product (web 3000, API 8010); profile `test`
  starts only the test website (8088).
- The API migrates the database and creates the first admin from `BOOTSTRAP_ADMIN_*` on start; production mode
  refuses default secrets.
- Scans run daily at 02:00 UTC, domains every 6 hours, email posture daily at 03:00, mailboxes every 5 minutes
  and hourly, and on demand from the brand page or the API.
- Back up the database and the evidence volume together. Logs are JSON lines matched by `request_id`.
- On Windows, run the backend in Docker.
- Tests are unit, module acceptance (against the test website), API and browser end-to-end. Requirement markers
  feed `scripts/uat_report.py`, which writes `docs/reports/UAT-REPORT.md`.
- The fictional test brand lives only in `backend/tests/fixtures` and `backend/tests/support` (D-27, D-30,
  D-32); the product has no demo mode and shows only real scan data.
- Each scan reports its state and components; check the Scans and Integrations pages first when results look
  thin.
- SP2 behaviour is tested in `backend/tests/api/test_findings.py` (candidates, "Alert from" level, observations,
  meaningful changes, decisions); the social media monitor in `backend/tests/modules/test_social_media.py`.
- Social media API keys (`YOUTUBE_API_KEY`, `META_AD_LIBRARY_TOKEN`, `THREADS_ACCESS_TOKEN`, `X_BEARER_TOKEN`)
  go in `deploy/.env`; a missing key shows "Not configured", never "nothing found". Fewer alerts than findings
  is expected: candidates and findings below "Alert from" are on the Findings page.
