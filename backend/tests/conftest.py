"""Test configuration.

* Unit tests need nothing running.
* Integration / acceptance tests need the Docker infra (Postgres, Redis, S3 store, fixtures site) and use
  a separate database `brandintel_test` and bucket `evidence-test`.
* Every test result is recorded against its @pytest.mark.req(...) IDs in reports/requirements-results.json,
  which scripts/uat_report.py turns into docs/reports/UAT-REPORT.md (DEL-07).
"""

import json
import os
from datetime import UTC, datetime
from pathlib import Path

# ---- environment must be set before any app module reads settings
os.environ["ENV"] = "test"
os.environ["JWT_SECRET"] = "test-secret-" + "x" * 40
os.environ["FETCH_ALLOW_PRIVATE_HOSTS"] = "[]"  # unit tests never inherit the dev allowlist
os.environ["CELERY_TASK_ALWAYS_EAGER"] = "1"  # .delay() runs inline in tests
_base_db = os.environ.get("DATABASE_URL", "postgresql+psycopg://brandintel:brandintel@localhost:5432/brandintel")
os.environ["DATABASE_URL"] = _base_db.rsplit("/", 1)[0] + "/brandintel_test"
os.environ["S3_BUCKET"] = "evidence-test"
os.environ.setdefault("FIXTURES_BASE_URL", "http://localhost:8088")

import pytest  # noqa: E402

REPORT_DIR = Path(__file__).resolve().parents[1] / "reports"
_results: list[dict] = []


# ------------------------------------------------------------------ requirement traceability
@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    if rep.when == "call" or (rep.when == "setup" and rep.outcome != "passed"):
        ids = []
        for mark in item.iter_markers("req"):
            ids.extend(mark.args)
        _results.append({"test": item.nodeid, "outcome": rep.outcome, "requirements": sorted(set(ids)),
                         "duration": round(rep.duration, 2),
                         "doc": (item.function.__doc__ or "").strip().splitlines()[0] if item.function.__doc__ else ""})


def pytest_sessionfinish(session, exitstatus):
    if not _results:
        return
    REPORT_DIR.mkdir(exist_ok=True)
    path = REPORT_DIR / "requirements-results.json"
    previous = []
    if path.exists() and os.environ.get("REQ_RESULTS_APPEND"):
        previous = json.loads(path.read_text(encoding="utf-8")).get("results", [])
    path.write_text(json.dumps({"generated_at": datetime.now(UTC).isoformat(), "results": previous + _results},
                               indent=2), encoding="utf-8")


# ------------------------------------------------------------------ infrastructure
def _infra_available() -> str | None:
    import socket

    for host, port, name in [("localhost", 5432, "Postgres"), ("localhost", 9000, "S3 store"),
                             ("localhost", 8088, "fixtures site")]:
        try:
            socket.create_connection((host, port), timeout=1).close()
        except OSError:
            return (f"{name} not reachable on {host}:{port} — start test infrastructure with "
                    "`docker compose -f deploy/docker-compose.yml --profile test up -d`")
    return None


@pytest.fixture(scope="session")
def infra():
    reason = _infra_available()
    if reason:
        pytest.skip(reason)


@pytest.fixture(scope="session")
def database(infra):
    """Fresh test database, created with the real Alembic migrations (DEL-03)."""
    import psycopg
    from alembic import command
    from alembic.config import Config

    admin_url = _base_db.replace("postgresql+psycopg://", "postgresql://")
    with psycopg.connect(admin_url, autocommit=True) as conn:
        conn.execute("DROP DATABASE IF EXISTS brandintel_test WITH (FORCE)")
        conn.execute("CREATE DATABASE brandintel_test")
    cfg = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
    command.upgrade(cfg, "head")
    yield


@pytest.fixture
def db(database):
    from app.db.session import SessionLocal

    s = SessionLocal()
    yield s
    s.close()


@pytest.fixture
def fixtures_site(monkeypatch):
    """Let the safe fetcher reach the local fixtures website (test-only allowlist)."""
    from app.config import get_settings

    monkeypatch.setattr(get_settings(), "fetch_allow_private_hosts", ["localhost", "127.0.0.1"])


def _truncate():
    from sqlalchemy import text

    from app.db.session import engine

    with engine.begin() as conn:
        conn.execute(text("TRUNCATE finding_events, evidence, alerts, observations, findings, scan_runs, domain_checks, app_listings, "
                          "brand_allowlist, brand_assets, brands, users RESTART IDENTITY CASCADE"))


@pytest.fixture
def clean_db(database):
    _truncate()
    yield
