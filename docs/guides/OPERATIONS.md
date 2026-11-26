# Operations Guide (FND-13, FND-14)

## Schedules

| Job | When (UTC) | What |
|---|---|---|
| `daily-full-scan` | 02:00 daily | Every module for every active brand (TYP-12 daily discovery) |
| `domain-recheck` | every 6 h at :30 | Domain pipeline only — newly live / newly email-enabled look-alikes surface within hours |

Change them in `backend/app/workers/celery_app.py` (`beat_schedule`). Manual scans: brand page → **Run scan now**,
or `POST /api/v1/scans`.

## Queues and scaling

- `default` queue (`worker`, concurrency 4): DNS, WHOIS, CT, app stores, web search, documents, APKs.
- `browser` queue (`browser-worker`, concurrency 2): domain pipeline, logo crawling, social profile screenshots.
  Each Chromium page needs ~300–500 MB RAM; raise concurrency only with memory.
- Scale horizontally: `docker compose ... up -d --scale browser-worker=3`.
- Tasks are acknowledged late and retried twice on infrastructure failure (DB/Redis down). A failure on one
  entity (one domain, one listing) is recorded on the scan's component (for example "Website probe & browser
  capture: failed") and does not stop the scan (status `completed_with_errors`). A source that is not configured
  or unavailable gives `partially_completed`; a scan that could check nothing is `failed` (D-31).
- A reported email whose analysis still fails after its retries is marked `failed` with the reason (it never stays
  `queued`).

## Performance (measured)

| Step | Measured | Notes |
|---|---|---|
| Typo variant generation | ~7,000–12,000 variants in 0.4 s per official domain | dnstwist + affixes × 11 TLDs, capped at 12,000 (homoglyphs dropped first) |
| Live DNS registration check | **~80 domains/s** (600 in 7.4 s) with 128 threads and public resolvers | One NS query per variant; A/MX only for registered ones → ~2.5 min per 12,000 variants |
| Browser capture of a live site | 2–4 s per page | Screenshot, favicon, images; 30 s page timeout |
| Full test-brand scan, all modules (simulated sources) | ~55 s in tests | 6 domains captured, 25 alerts |
| Alert queue API (filters + pagination) | indexed filters, 25 rows per page by default | `ix_alerts_filters`, `first_seen` index |

Optimisations made: one-NS-query registration check (6× faster than A+NS+MX for every variant); browser work on
its own queue so DNS-heavy scans never wait behind screenshots; evidence de-duplication by SHA256; lazy imports
so the API process does not load detection libraries; paginated and indexed queries for every list view;
per-host rate limiting shared through Redis.

Requirements on the network: outbound UDP/TCP 53 to `1.1.1.1`, `8.8.8.8`, `9.9.9.9` (or change
`LiveInfra.nameservers` in `backend/app/modules/domains/infra.py` to your resolvers).

## Logs

All services log one JSON object per line (structlog) to stdout:

```bash
docker compose -f deploy/docker-compose.yml logs -f api            # requests with request_id, status, ms
docker compose -f deploy/docker-compose.yml logs -f worker browser-worker   # scan_finished, alert_upserted, fetch_failed …
```

Every API response carries an `x-request-id` header; errors return it in the body so a user report can be matched
to the log line. Scan problems are also visible in the dashboard under **Scans** (status, statistics and the **What this scan
checked** list of components with their messages) and under **Integrations** (every tool, whether it is
configured, its last result).

## Health

- `GET /health` → `{"status":"ok","database":"ok"}` (503 when degraded). Used by the Docker health check.
- Workers: `celery inspect ping` health check every 60 s.

## Tests

```bash
docker compose -f deploy/docker-compose.yml --profile test up -d fixtures   # test website (tests only)
cd backend
python -m uv run pytest                                        # unit + acceptance + API  (~90 s, own test database)
# Browser end-to-end against the running stack and its real data (read-only by default):
E2E_WEB_URL=http://localhost:3000 E2E_API_URL=http://localhost:8010 E2E_EMAIL=<admin> E2E_PASSWORD=<pw>   REQ_RESULTS_APPEND=1 python -m uv run pytest tests/e2e
docker compose -f deploy/docker-compose.yml --profile test stop fixtures
python -m uv run python -m scripts.uat_report                  # → docs/reports/UAT-REPORT.md
python -m uv run ruff check app scripts tests                  # lint
cd ../frontend && npm run lint && npm run build
```

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Scan `partially_completed` with "Web search - DuckDuckGo (free, paced): Unavailable … rate-limited / paused" | Expected without a key; free search resumes after 15 min. Set `BRAVE_SEARCH_API_KEY` and restart workers for reliable discovery |
| Fake APK or Documents scan `failed` because every web search was unavailable | No search results at all means nothing was checked, so the run is not reported as clean. Add a search API key, or wait for the free-search pause to end |
| Scan `completed_with_errors` with "Certificate Transparency (crt.sh): failed … HTTP 502" | crt.sh (public service) is overloaded; the next scan retries — typosquat generation still covers variants |
| Scan `completed_with_errors` with "DNS resolution: N domains could not be resolved (timeout/SERVFAIL)" | Resolver timeouts; those domains are *unresolved* (not "unregistered") and retried next scan. Persistent? check outbound port 53 |
| Social scan `partially_completed` with "Telegram API: Not configured" | No Telegram credentials; only the public `t.me` page check ran. Set `TELEGRAM_API_ID`, `TELEGRAM_API_HASH`, `TELEGRAM_SESSION` |
| Logo scan `failed` with "Official logo assets: Not configured" | Upload an official logo under the brand's Official assets |
| Scan shows `cancelled` ("Interrupted") | A worker restarted during the scan; just run it again (stuck runs are closed automatically after 90 min) |
| Many alerts for an unrelated company with the same abbreviation | Expected to be filtered (D-25); add more distinctive keywords/product names to the brand if it still happens |
| No screenshots | `browser-worker` not running or out of memory (`docker compose logs browser-worker`) |
| Evidence images do not open in the browser | `S3_PUBLIC_ENDPOINT_URL` must be reachable from analysts' browsers |
| API refuses to start: "Insecure production configuration" | Replace default secrets in `deploy/.env` (DEPLOYMENT §4) |
| Login rejected for a correct password | Account deactivated — an admin re-activates under Users |
| PDF export returns 503 | Running the API outside Docker on Windows; use the Docker image |
