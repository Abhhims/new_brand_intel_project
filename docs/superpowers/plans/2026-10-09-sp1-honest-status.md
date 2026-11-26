# SP1 — Honest Scan Status Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every scan reports exactly which components ran, failed, were unavailable or not configured; unknown results are never recorded as negative ones; demo mode leaves the product; the dashboard distinguishes error, empty and "No threats detected."

**Architecture:** A `ScanReport` object (one per runner) collects ordered component results; a pure function derives the run state; `scan_runs.components` stores them. Fixture sources move to `backend/tests/support/` and are injected by tests through the runners' existing constructor parameters. A static integrations registry plus the latest component results feed `GET /api/v1/integrations`. The frontend gets one `QueryState` pattern for loading/error/empty.

**Tech Stack:** FastAPI, SQLAlchemy 2, Alembic (PostgreSQL enum swap), Celery, pytest; Next.js 15, TanStack Query, Tailwind/shadcn.

**Spec:** `docs/superpowers/specs/2026-10-09-sp1-honest-status-design.md`

## Global Constraints

- Run states exactly: `queued, running, completed, partially_completed, completed_with_errors, failed, cancelled`.
- Component statuses exactly: `ok, failed, unavailable, not_configured, skipped`.
- Precedence: crashed or fatal component → `failed`; any `failed` → `completed_with_errors`; any `unavailable`/`not_configured` → `partially_completed`; else `completed`.
- Migration maps `succeeded → completed`, `partial → completed_with_errors`, `failed` whose error contains "Interrupted" → `cancelled`.
- No product module (`backend/app/**`) may import fixture/test data; `brands.demo_mode`, `ALLOW_DEMO_MODE`, `FIXTURES_DIR`, `FIXTURES_BASE_URL` are removed from the product.
- Every new test carries `@pytest.mark.req(...)` with the RDA IDs it proves.
- Commands run from `backend/` with `.venv/Scripts/python.exe -m pytest`; integration tests need `docker compose -f ../deploy/docker-compose.yml --profile test up -d postgres redis minio fixtures`.

## Review Focus

1. A brand scanned while search is rate-limited → run is `failed` (fatal) for search-only modules, never `completed` with zero findings. Pinned in Task 5.
2. A DNS timeout for a domain that already has an alert → the alert is untouched (no stage/score change, no "removed"). Pinned in Task 4.
3. A Telegram run without credentials → `not_configured` for the API and `ok` for public pages, run `partially_completed`. Pinned in Task 5.
4. Dashboard when the stats API returns 500 → visible error with Retry, never zeros or endless skeleton. Pinned in Task 8 (e2e).
5. Old runs stored as `succeeded`/`partial` still render after migration. Pinned in Task 2.

---

### Task 1: ScanReport and run-state derivation

**Files:**
- Modify: `backend/app/modules/base.py` (add `ComponentStatus`, `Component`, `ScanReport`)
- Modify: `backend/app/db/models.py` (`ScanStatus` new values — values only, migration in Task 2)
- Test: `backend/tests/unit/test_scan_report.py`

**Interfaces:**
- Produces: `ScanReport.ok(name, message="", **counts)`, `.failed(name, message, fatal=False, **counts)`, `.unavailable(name, message)`, `.not_configured(name, message)`, `.skipped(name, message)`, `.as_list() -> list[dict]`, `.errors -> list[str]`; `derive_run_status(components: list[dict], crashed: bool) -> ScanStatus`.

- [ ] Step 1: failing tests

```python
import pytest
from app.db.models import ScanStatus
from app.modules.base import ScanReport, derive_run_status

pytestmark = pytest.mark.req("RDA-17", "RDA-21", "RDA-03")

def test_all_ok_is_completed():
    r = ScanReport(); r.ok("DNS resolution", resolved=10)
    assert derive_run_status(r.as_list(), crashed=False) == ScanStatus.completed

def test_not_configured_is_partially_completed():
    r = ScanReport(); r.ok("Telegram public pages"); r.not_configured("Telegram API", "no credentials")
    assert derive_run_status(r.as_list(), False) == ScanStatus.partially_completed

def test_failure_beats_reduced_coverage():
    r = ScanReport(); r.unavailable("Web search", "rate limited"); r.failed("Listing pages", "3 of 9 failed")
    assert derive_run_status(r.as_list(), False) == ScanStatus.completed_with_errors

def test_fatal_component_fails_run():
    r = ScanReport(); r.failed("Web search", "all queries failed", fatal=True)
    assert derive_run_status(r.as_list(), False) == ScanStatus.failed

def test_crash_fails_run():
    assert derive_run_status([], crashed=True) == ScanStatus.failed

def test_repeated_component_keeps_worst_status_and_sums_counts():
    r = ScanReport(); r.ok("DNS resolution", resolved=5); r.failed("DNS resolution", "timeout", unresolved=2)
    (c,) = r.as_list()
    assert c["status"] == "failed" and c["counts"] == {"resolved": 5, "unresolved": 2}

def test_errors_lists_failed_and_unavailable_messages():
    r = ScanReport(); r.failed("A", "boom"); r.unavailable("B", "down"); r.not_configured("C", "no key")
    assert r.errors == ["A: boom", "B: down"]
```

- [ ] Step 2: run, expect ImportError.
- [ ] Step 3: implement in `base.py`:

```python
class ComponentStatus(str, enum.Enum):
    ok = "ok"; skipped = "skipped"; not_configured = "not_configured"; unavailable = "unavailable"; failed = "failed"

_SEVERITY = {"ok": 0, "skipped": 1, "not_configured": 2, "unavailable": 3, "failed": 4}

@dataclass
class Component:
    name: str
    status: str = "ok"
    messages: list[str] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    fatal: bool = False

class ScanReport:
    """Per-component outcome of one scan run (D-31). Unknown is never reported as 'nothing found'."""
    def __init__(self) -> None:
        self._c: dict[str, Component] = {}
    def _add(self, name, status, message="", fatal=False, **counts):
        c = self._c.setdefault(name, Component(name))
        if _SEVERITY[status] > _SEVERITY[c.status]:
            c.status = status
        if message and message not in c.messages:
            c.messages.append(message)
        for k, v in counts.items():
            c.counts[k] = c.counts.get(k, 0) + int(v)
        c.fatal = c.fatal or fatal
    def ok(self, name, message="", **counts): self._add(name, "ok", message, **counts)
    def failed(self, name, message, fatal=False, **counts): self._add(name, "failed", message, fatal, **counts)
    def unavailable(self, name, message, fatal=False): self._add(name, "unavailable", message, fatal)
    def not_configured(self, name, message): self._add(name, "not_configured", message)
    def skipped(self, name, message): self._add(name, "skipped", message)
    def as_list(self) -> list[dict]:
        return [{"name": c.name, "status": c.status, "message": "; ".join(c.messages[:5]),
                 "counts": c.counts, "fatal": c.fatal} for c in self._c.values()]
    @property
    def errors(self) -> list[str]:
        return [f"{c.name}: {m}" for c in self._c.values() if c.status in ("failed", "unavailable") for m in c.messages]

def derive_run_status(components: list[dict], crashed: bool) -> ScanStatus:
    if crashed or any(c.get("fatal") and c["status"] in ("failed", "unavailable", "not_configured") for c in components):
        return ScanStatus.failed
    statuses = {c["status"] for c in components}
    if "failed" in statuses:
        return ScanStatus.completed_with_errors
    if statuses & {"unavailable", "not_configured"}:
        return ScanStatus.partially_completed
    return ScanStatus.completed
```

`ScanStatus` in models gains `completed, partially_completed, completed_with_errors, cancelled` (old `succeeded`, `partial` removed in Task 2).

- [ ] Step 4: run tests, expect PASS.

### Task 2: Migration, scan engine and API use components

**Files:**
- Create: `backend/app/alembic/versions/20261009_sp1_scan_components.py`
- Modify: `backend/app/db/models.py` (`ScanRun.components` JSONB; drop `Brand.demo_mode`), `backend/app/workers/scan.py`, `backend/app/schemas/api.py` (`ScanOut.components`), `backend/app/api/scans.py`
- Test: `backend/tests/unit/test_scan_report.py` (stale → cancelled), `backend/tests/modules/test_acceptance.py::test_scan_runs_recorded`

**Interfaces:** Consumes Task 1. Produces `ScanRun.components: list[dict]`; runners expose `report: ScanReport` (Tasks 4–5 fill it).

- [ ] Migration (PostgreSQL enum swap):

```python
def upgrade():
    op.execute("ALTER TYPE scan_status RENAME TO scan_status_old")
    op.execute("CREATE TYPE scan_status AS ENUM ('queued','running','completed','partially_completed',"
               "'completed_with_errors','failed','cancelled')")
    op.execute("""ALTER TABLE scan_runs ALTER COLUMN status TYPE scan_status USING (
        CASE status::text WHEN 'succeeded' THEN 'completed' WHEN 'partial' THEN 'completed_with_errors'
        WHEN 'failed' THEN CASE WHEN coalesce(error,'') ILIKE '%interrupted%' THEN 'cancelled' ELSE 'failed' END
        ELSE status::text END)::scan_status""")
    op.execute("DROP TYPE scan_status_old")
    op.add_column("scan_runs", sa.Column("components", JSONB, nullable=False, server_default="[]"))
    op.execute("DO $$ BEGIN IF EXISTS (SELECT 1 FROM brands WHERE demo_mode) THEN "
               "RAISE EXCEPTION 'brands with demo_mode=true exist: remove them before upgrading (D-32)'; END IF; END $$")
    op.drop_column("brands", "demo_mode")
```

(Server default for status column reset to 'queued' after the swap; downgrade reverses the mapping.)

- [ ] `execute_scan`: after `runner.run()` completes, `components = runner.report.as_list()`; per-finding upsert errors go into `report.failed("Saving findings", ...)`; crash → `crashed=True` plus `report.failed("Scan engine", msg, fatal=True)`; `status = derive_run_status(components, crashed)`; `run.components = components`; `run.error = "\n".join(report.errors[:50]) or None`. Remove `data_source` and demo checks. `close_stale_runs` sets `ScanStatus.cancelled`.
- [ ] Test: stale run becomes `cancelled`; acceptance `test_scan_runs_recorded` asserts every run has a non-empty `components` list and a status in the new set.

### Task 3: Remove demo mode from the product

**Files:**
- Create: `backend/tests/support/__init__.py`, `backend/tests/support/fixture_sources.py` (moved `fixtures.py` loader, `FixtureInfra`, `FixtureApkSource`, `FixturePlaySource`, `FixtureSocialSource`, `FixtureDocSource`, fixture logo targets), `backend/tests/support/seed_test_brand.py` (moved from `scripts/seed_demo.py`)
- Delete: `backend/app/modules/fixtures.py`, `backend/scripts/seed_demo.py`
- Modify: every module's `run()` (drop `ctx.demo_mode` branch, keep injected-source parameter), `backend/app/modules/domains/module.py` (drop `isinstance(infra, FixtureInfra)` branches → injected `extra_domains` attribute via `getattr(infra, "extra_domains", [])`), `backend/app/modules/base.py` (drop `demo_mode`), `backend/app/config.py` (drop `allow_demo_mode`, `fixtures_dir`, `fixtures_base_url`), `backend/app/api/brands.py`, `backend/app/schemas/api.py`, `backend/scripts/uat_report.py` (DEL-08 artefact path), `backend/tests/conftest.py` + `tests/modules/test_acceptance.py` (runner override)
- Frontend: `brand-form.tsx`, `brands/page.tsx`, `brands/[id]/page.tsx`, `scan-table.tsx`, `lib/api.ts` — remove demo toggle/tag/banner/chip
- Test: `backend/tests/unit/test_no_test_data_in_product.py`

- [ ] Guard test (fails first):

```python
import pathlib, re, pytest
pytestmark = pytest.mark.req("RDA-01", "RDA-04")
APP = pathlib.Path(__file__).resolve().parents[2] / "app"

def test_product_code_has_no_fixture_or_demo_paths():
    offenders = [str(p) for p in APP.rglob("*.py")
                 if re.search(r"demo_mode|allow_demo_mode|from app\.modules import fixtures|Fixture\w+Source|FixtureInfra",
                              p.read_text(encoding="utf-8")) and "alembic" not in p.parts]
    assert offenders == []

def test_brand_api_rejects_unknown_demo_field(client, admin_headers):
    r = client.post("/api/v1/brands", headers=admin_headers, json={"name": "X", "keywords": ["x"], "demo_mode": True})
    assert r.status_code == 422
```

(`BrandIn` gets `model_config = ConfigDict(extra="forbid")`.)

- [ ] Runner override used by acceptance tests:

```python
# tests/support/fixture_sources.py
def fixture_runner(name: str):
    from app.modules.registry import get_runner as live
    return {"domains": lambda: DomainModule(infra=FixtureInfra()), "apk": lambda: ApkModule(source=FixtureApkSource()),
            "rogue_app": lambda: RogueAppModule(source=FixturePlaySource()),
            "social": lambda: SocialModule(source=FixtureSocialSource()),
            "documents": lambda: DocumentsModule(source=FixtureDocSource()),
            "logo": lambda: LogoModule(extra_targets=fixture_logo_targets())}.get(name, lambda: live(name))()
```

`scanned` fixture: `monkeypatch.setattr("app.workers.scan.get_runner", fixture_runner)`; email_posture skipped for the test brand by not selecting it (no real domains).

- [ ] Run full suite; all previous acceptance tests must still pass.

### Task 4: Domains runner — components and unknown ≠ no

**Files:**
- Modify: `backend/app/modules/domains/infra.py` (`DnsInfo.status: "resolved" | "nxdomain" | "unknown"`), `backend/app/modules/domains/module.py`
- Test: `backend/tests/unit/test_domain_reporting.py`

- [ ] DNS classification: NXDOMAIN / NoAnswer → `nxdomain`; Timeout / NoNameservers / SERVFAIL / other DNSException → `unknown`. `registered` stays `bool(a or mx or ns)`.

```python
def _records(self, name, rtype) -> tuple[list[str], bool]:   # (records, definitive)
    try:
        ans = self.resolver.resolve(name, rtype, raise_on_no_answer=False)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.name.LabelTooLong, dns.name.EmptyLabel, ValueError):
        return [], True
    except dns.exception.DNSException:      # Timeout, NoNameservers (SERVFAIL), …
        return [], False
    return (sorted({r.to_text().rstrip(".") for r in ans}) if ans.rrset else []), True
```

- [ ] Module: report components — `Variant generation` (ok, count), `Certificate Transparency (crt.sh)` (ok/failed per term), `DNS resolution` (ok resolved=N registered=M; failed unresolved=K "K domains could not be resolved (timeout/SERVFAIL) — not treated as unregistered"), `WHOIS/RDAP` (failed count when `whois.error`), `Website probe & browser capture` (failed count when a port was open but capture failed), `TLS certificate`, `Look-alike email records`.
- [ ] Unknown DNS: domain skipped this run (no finding yielded) — existing alert untouched.
- [ ] Capture failed on an open port: if an alert already exists for the domain, yield nothing (alert untouched, like unknown DNS); otherwise yield the finding with its DNS stage (typosquat/mx) and `details["Website Live"] = "unknown (capture failed)"`. Either way the capture component counts the failure.
- [ ] Tests with a stub infra: timeout domain → not yielded, DNS component failed with `unresolved=1`; capture failure → details "unknown (capture failed)" and component failed; RDAP error → WHOIS component failed. `req("RDA-03","RDA-21")`.

### Task 5: Other runners — components, provider names, fatal search failures

**Files:**
- Modify: `backend/app/core/search.py` (no behaviour change; `provider_name()` used), `backend/app/modules/apk/module.py`, `rogue_app/module.py`, `social/module.py`, `documents/module.py`, `logo/module.py`, `email/posture.py`
- Test: `backend/tests/unit/test_runner_reporting.py`

Rules:
- Web search component name: `f"Web search — {search.provider_name()}"`. Each `SearchUnavailable` → `unavailable`. If **every** query of a search-only module failed → `fatal=True` (apk, documents; social only if Telegram also produced nothing).
- Social: no Telegram credentials → `not_configured("Telegram API", "TELEGRAM_API_ID/HASH/SESSION not set")`, and public-page checks reported as `Telegram public pages` ok/failed with counts; Telethon import or session error → `failed`.
- Rogue app: Play search failure per term → `failed`; all terms failed → fatal; removal check skipped → `skipped("Removal check", reason)`.
- APK: listing page fetch failures counted under `Listing pages`; download failures under `APK download & analysis` with "file could not be downloaded" in alert details.
- Documents: download failures counted under `Download & text extraction`.
- Logo: no official logo → `not_configured("Official logo assets", ...)` and `fatal=True` (nothing can be compared).
- Posture: per-domain DNS failures under `DNS TXT lookups`; MTA-STS fetch under `MTA-STS policy fetch`.
- Remove each module's `self.errors` (replaced by `report`).
- [ ] Tests with stub sources/search raising `SearchUnavailable`: APK all-searches-down → fatal → run `failed`; social without Telegram creds → `not_configured` + public pages ok → `partially_completed`; logo with no logo → `failed`. `req("RDA-03","RDA-17","RDA-21")`.

### Task 6: Email analysis failures are visible

**Files:** Modify `backend/app/workers/tasks.py`, `backend/app/db/models.py` (EmailMessage already has `error`, `status`). Test `backend/tests/unit/test_tasks.py`.

- [ ] When retries are exhausted (`self.request.retries >= self.max_retries`), set `row.status = "failed"`, `row.error = f"{type(exc).__name__}: {exc}"[:2000]` in its own session, then re-raise. Test: patch `analyse_stored` to raise, call task with `retries=max_retries` → row status `failed`. `req("RDA-21")`.

### Task 7: Integrations registry and endpoint

**Files:** Create `backend/app/core/integrations.py`, `backend/app/api/integrations.py`; modify `backend/app/main.py`, `backend/app/schemas/api.py`. Test `backend/tests/api/test_integrations_api.py`.

- [ ] Registry entries (id, name, category, modules, configured predicate, matching component-name prefixes, env vars to set): web search (Brave / SerpAPI / DuckDuckGo), crt.sh, RDAP, DNS resolvers, browser (Playwright), Telegram API, Google Play, Rspamd, ClamAV, YARA rules, URLhaus, OpenPhish, urlscan.io, AbuseIPDB, IMAP report mailbox, DMARC mailbox, Microsoft Graph, Gmail, object storage, task queue.
- [ ] `GET /api/v1/integrations` → `[{id, name, category, modules, configured, last_status, last_message, last_checked_at, how_to_configure}]`; `last_*` from the newest `scan_runs.components` entry whose name matches, or for email tools from the newest analysed email's `auth.not_checked`. Never returns secret values.
- [ ] Tests: unconfigured urlscan → `configured=false`; a scan run with a failed `Web search — Brave Search API` component → search integration `last_status="failed"`; response contains no key values. `req("RDA-03")`.

### Task 8: Frontend states, scan components, integrations page

**Files:**
- Create: `frontend/src/components/query-state.tsx`, `frontend/src/app/(app)/integrations/page.tsx`, `frontend/src/components/scan-components.tsx`
- Modify: `frontend/src/lib/api.ts` (types: `ScanStatus` union, `ScanComponent`, `Integration`, `api.integrations()`), `lib/constants.ts` (status labels/tooltips, nav item), `components/badges.tsx`, `components/scan-table.tsx`, `app/(app)/page.tsx`, `app/(app)/alerts/page.tsx`, `app/(app)/alerts/[id]/page.tsx`, `app/(app)/brands/[id]/page.tsx`, `app/(app)/scans/page.tsx`, sidebar nav
- Modify backend `backend/app/api/stats.py`: executive stats add `last_completed_scan_at` and `components_unavailable` (count of non-ok components in each runner's latest run)
- Test: `backend/tests/e2e/test_ui.py` (new cases), `backend/tests/api/test_api.py` (stats fields)

- [ ] `QueryState`: props `{query, isEmpty?, empty, children}` → skeleton while loading; `ErrorPanel` (title "Couldn't load this", the `ApiError` message, Retry button calling `query.refetch()`) on error; `empty` node when `isEmpty(data)`.
- [ ] Dashboard: error → ErrorPanel; `last_completed_scan_at == null` → "No scans have run yet"; `open_alerts == 0` → "No threats detected." + "Last scan {time}" + (if `components_unavailable > 0`) "{n} scan components were unavailable — see Integrations". "Open by module" iterates every module in `by_module`.
- [ ] Alerts list: error → ErrorPanel; empty & no filters → "No threats detected."; empty & filters → "No alerts match these filters".
- [ ] Alert/brand detail: `ApiError.status === 404` → not found; other errors → ErrorPanel.
- [ ] Scans: badges for 7 states with tooltips (e.g. partially_completed: "Ran, but some sources were not configured or unavailable — coverage reduced"); expanded row renders `ScanComponents` checklist (✓ ok, – skipped, ⚠ not configured/unavailable, ✗ failed + message + counts).
- [ ] Integrations page: table grouped by category: name, used by, Configured (Yes/No + env vars to set), Last result badge + message + time.
- [ ] e2e: route-intercept `/api/v1/stats/executive` → 500 → page shows "Couldn't load"; scans page shows component names for a finished run; integrations page lists "urlscan.io". `req("RDA-02","RDA-19","RDA-17","RDA-03")`.

### Task 9: Docs, decisions, UAT, handbook

**Files:** `docs/decisions/DECISION-LOG.md` (D-31, D-32), `docs/requirements/01-requirements-register.md` (DEL-08 note), `docs/architecture/*.md` + `docs/guides/*.md` mentions of demo mode / scan states, `docs/handbook/**` chapters mentioning demo mode, scan states, failures, `README.md`, `deploy/.env.example` (remove ALLOW_DEMO_MODE / FIXTURES_*), `backend/scripts/uat_report.py`.

- [ ] Full suite green, ruff clean, `npm run build` + lint clean, e2e green against the rebuilt stack.
- [ ] Regenerate UAT report; RDA-01/02/03/04/17/19/21 show Tested.
