# SP1 — Honest scan status, failure handling and real-data-only product

**Date:** 2026-10-09 · **Status:** awaiting owner approval · **Roadmap:** sub-project 1 of 5 (approved 2026-10-09)
**Requirements:** RDA-01, RDA-02, RDA-03, RDA-04, RDA-17, RDA-19, RDA-21 (register section Q)

## 1. Problem

The audit of 2026-10-09 found that the platform never invents findings, but it is not always honest about what it
could *not* check:

- A DNS timeout or SERVFAIL is treated as "domain not registered"; a failed page capture as "website not live";
  WHOIS/RDAP, TLS and image-download errors are hidden in detail fields.
- With no Telegram credentials the social module silently switches to guessing public pages; nobody is told which
  web-search provider ran or that it was rate-limited.
- A scan run is only `succeeded` / `partial` / `failed` with free-text errors — there is no per-component result
  such as "Threat intelligence: not configured".
- No page shows which integrations are configured or reachable.
- When the API fails, frontend pages show "No alerts yet", "Alert not found" or endless loading skeletons — an
  error looks like a clean result. There is no "No threats detected." state.
- The demo-mode switch (`brands.demo_mode`, `ALLOW_DEMO_MODE`, fixture sources inside product modules) still ships
  in the product, guarded only in production mode, and nothing on an alert marks it as test data.

## 2. Goals / non-goals

**Goals:** every scan reports exactly which components ran, failed, were unavailable or not configured; an
unknown result is never recorded as a negative one; the product contains no demo/test code path; the dashboard
distinguishes *error*, *empty* and *no threats detected*.

**Non-goals (later sub-projects):** confidence scores, candidate/finding/alert split, new threat-intel sources for
domains (SP3), correlation (SP4), new scanner signals (SP5). SP1 changes how results are *reported*, not how they are
*scored* — except that "unknown" no longer counts as "no".

## 3. Design

### 3.1 Scan states (RDA-17)

`scan_status` enum becomes:

| State | Meaning |
|---|---|
| `queued`, `running` | unchanged |
| `completed` | every component that applies ran successfully |
| `partially_completed` | the scan ran, but at least one component could not run (`not_configured` or `unavailable`) — coverage is reduced, results are real |
| `completed_with_errors` | at least one component failed part-way (some lookups/captures errored) — results are real but incomplete |
| `failed` | the scan could not produce results (core discovery failed or an exception escaped) |
| `cancelled` | interrupted (worker restart, stale > 90 min) — replaces today's "failed: interrupted" |

If both reduced coverage and errors occur, `completed_with_errors` wins. Migration maps `succeeded → completed`,
`partial → completed_with_errors`, and interrupted `failed` runs (by their error text) → `cancelled`.

### 3.2 Per-component results (RDA-03, RDA-17, RDA-21)

New `ScanReport` helper (in `app/modules/base.py`) that every runner writes to, replacing the bare `errors` list:

```text
report.component(name, status, message="", counts={})   status: ok | failed | unavailable | not_configured | skipped
```

Stored in a new `scan_runs.components` JSONB column as an ordered list:
`[{name, status, message, counts, started_at, finished_at}]`. `scan_runs.error` keeps the first 50 error lines.
The run state (3.1) is derived from the component list by one pure function (unit-tested).

Components per runner:

| Runner | Components |
|---|---|
| domains | Variant generation · Certificate Transparency (crt.sh) · DNS resolution · WHOIS/RDAP · Website probe & browser capture · TLS certificate · Look-alike email records (SPF/DMARC) |
| apk | Web search (provider named) · Listing pages · APK download & analysis |
| rogue_app | Google Play search · Removal check |
| social | Telegram API · Telegram public pages · Web search for X/Facebook/Instagram/LinkedIn (provider named) · Profile capture |
| documents | Web search (provider named) · Download & text extraction |
| logo | Official logo assets · Target websites · Browser capture |
| email_posture | DNS TXT lookups · MTA-STS policy fetch |

### 3.3 Unknown is never "no" (RDA-03, RDA-21)

| Today | After SP1 |
|---|---|
| DNS timeout / SERVFAIL → "not registered", domain dropped | counted as *unresolved*; DNS component `failed` with the count; an existing alert for that domain is left unchanged; retried next scan |
| Port open but browser capture fails → "Website Live: false" | "Website Live: unknown (capture failed)"; existing stage/score kept; capture component counts failures |
| RDAP error hidden in `whois.error` | WHOIS component reports failures; field shows "lookup failed" |
| TLS error hidden | TLS component reports failures |
| No Telegram credentials → silent public-page guessing | "Telegram API: not_configured"; "Telegram public pages: ok" — both visible |
| Search provider unknown, rate-limit only in logs | component named with provider ("Web search — DuckDuckGo (free fallback)"); rate limit → `unavailable` with the cooldown |
| APK / icon / image download failure → treated as "no file" | counted in the component; alert detail says "file could not be downloaded" |

### 3.4 Integrations status (RDA-03)

`GET /api/v1/integrations` lists every integration the code uses (search providers, crt.sh, RDAP, Telegram,
Google Play, Playwright/browser worker, Rspamd, ClamAV, YARA, URLhaus, OpenPhish, urlscan, AbuseIPDB, IMAP/Graph/
Gmail intake, object storage, Redis/Celery): category, used by which modules, **configured** (from settings),
**last result** (from the latest scan components or email checks), last error, last checked time. Only integrations
that exist in code are listed — nothing is shown for tools we do not implement.

New **Integrations** page in the dashboard (all signed-in users can view; secrets never shown).

### 3.5 Demo mode removed from the product (RDA-01, RDA-04)

- Drop `brands.demo_mode` (migration; refuses if any brand still has it set — none do), `ALLOW_DEMO_MODE`,
  `FIXTURES_DIR`, `FIXTURES_BASE_URL`, `fetch_allow_private_hosts` from product settings, and every
  `ctx.demo_mode` branch.
- Move `app/modules/fixtures.py`, `FixtureInfra` and the `Fixture*Source` classes into
  `backend/tests/support/`. Product modules keep only their live sources plus the existing constructor parameter
  for injecting a source (dependency injection — standard, not a fallback).
- Tests build runners with the fixture sources and run them through the real `execute_scan` via a test-only
  runner override in `tests/conftest.py`.
- `scripts/seed_demo.py` moves to `backend/tests/support/` (test use only). Original requirement **DEL-08**
  ("sample monitoring data: demo brand + fixtures + seed script") is satisfied by the test fixtures and recorded as
  superseded-in-product by RDA-04 (new decision).
- Frontend: remove the demo toggle, "Demo" tag, demo banner and "Demo data" chip.

### 3.6 Frontend states (RDA-02, RDA-19)

A shared `QueryState` pattern on every data page: **loading** → **error** (message + Retry, never a zero) →
**empty** → data.

- Dashboard: if no scan has ever completed → "No scans have run yet"; if scans ran and nothing is open →
  "No threats detected." with the last-scan time and a coverage note ("N components were unavailable — see
  Integrations"). Tiles keep showing real zeros. The "Open by module" panel includes the email modules (bug found
  in the audit).
- Alerts list: error state; "No threats detected." when unfiltered and empty; "No alerts match these filters" when
  filtered.
- Alert / brand detail: 404 → "not found"; any other failure → error state.
- Scans page: error state; new status badges with plain-English tooltips; expanded row shows the component
  checklist (✓ ok, ⚠ not configured / unavailable, ✗ failed) with messages and counts.

## 4. Data and API changes

- Alembic migration: `scan_status` enum values; `scan_runs.components` JSONB (default `[]`); drop
  `brands.demo_mode`.
- `ScanOut` gains `components`; `BrandIn/BrandOut/BrandPatch` lose `demo_mode`.
- New `GET /api/v1/integrations`.
- Existing scan stats keys are kept.

## 5. Testing

- Unit: run-state derivation for every combination; `ScanReport`; DNS outcome classification (NXDOMAIN vs
  timeout/SERVFAIL); search-provider reporting; integrations endpoint with configured/unconfigured settings.
- Module acceptance (test website + fixture sources injected): component lists recorded for every runner; a
  simulated DNS timeout leaves the domain *unresolved* not *unregistered*; a capture failure keeps the previous
  stage; Telegram without credentials reports `not_configured`.
- API: `/integrations`, scans with components, brand schemas without `demo_mode`, demo flag rejected.
- Guard test: no product module imports test fixtures; `app/` contains no fixture loader.
- Browser e2e (against the running stack): dashboard "No threats detected." / error state, scans component list.
- Every test carries `@pytest.mark.req("RDA-xx")`; UAT report regenerated.

## 6. Decisions to log

- **D-31** Scan states and per-component results (3.1–3.3).
- **D-32** Demo mode removed from the product; DEL-08 satisfied by test fixtures only (3.5).

## 7. Risks

- Enum migration on PostgreSQL needs a type swap (rename old type, create new, cast) — tested on a copy of the
  dev database first.
- Treating timeouts as *unresolved* may hide a newly registered domain until a later scan succeeds; mitigated by the
  DNS component showing the count and retrying next scan.
