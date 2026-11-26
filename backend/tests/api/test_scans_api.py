"""SP1 / D-31: scan runs carry honest states and per-component results through the API."""

from datetime import UTC, datetime, timedelta

import pytest

from app.db.models import Brand, ModuleName, ScanRun, ScanStatus
from app.db.session import session_scope
from tests.api.test_api import admin, analyst, client  # noqa: F401 - shared fixtures

pytestmark = pytest.mark.req("RDA-17")


def _brand() -> str:
    with session_scope() as db:
        b = Brand(name="Example Bank", keywords=["examplebank"])
        db.add(b)
        db.flush()
        return str(b.id)


def test_interrupted_run_is_cancelled_not_failed(client, admin):  # noqa: F811
    from app.workers.scan import create_scan_runs

    brand_id = _brand()
    with session_scope() as db:
        db.add(ScanRun(brand_id=brand_id, module=ModuleName.apk, status=ScanStatus.running, stats={"runner": "apk"},
                       created_at=datetime.now(UTC) - timedelta(hours=3)))
    with session_scope() as db:
        create_scan_runs(db, brand_id, [], "manual")  # closes stale runs first
    with session_scope() as db:
        run = db.query(ScanRun).filter(ScanRun.module == ModuleName.apk).one()
        assert run.status == ScanStatus.cancelled and "Interrupted" in run.error


def test_scans_api_returns_components(client, admin):  # noqa: F811
    brand_id = _brand()
    comps = [{"name": "Web search - Brave Search API", "status": "unavailable", "message": "HTTP 429",
              "counts": {}, "fatal": True}]
    with session_scope() as db:
        db.add(ScanRun(brand_id=brand_id, module=ModuleName.documents, status=ScanStatus.failed,
                       stats={"runner": "documents"}, components=comps, error="Web search - Brave Search API: HTTP 429"))
    (scan,) = client.get("/api/v1/scans", headers=admin).json()
    assert scan["status"] == "failed" and scan["components"] == comps


@pytest.mark.req("RDA-02", "RDA-17")
def test_dashboard_reports_scan_coverage(client, admin):  # noqa: F811
    """'No threats detected' needs to know a scan actually ran, and how much of it could not run."""
    stats = client.get("/api/v1/stats/executive", headers=admin).json()
    assert stats["last_completed_scan_at"] is None and stats["components_unavailable"] == 0
    brand_id = _brand()
    now = datetime.now(UTC)
    with session_scope() as db:
        old = ScanRun(brand_id=brand_id, module=ModuleName.social, status=ScanStatus.partially_completed,
                      stats={"runner": "social"}, finished_at=now - timedelta(hours=2),
                      components=[{"name": "Telegram API", "status": "not_configured", "message": "", "counts": {}}])
        new = ScanRun(brand_id=brand_id, module=ModuleName.social, status=ScanStatus.partially_completed,
                      stats={"runner": "social"}, finished_at=now - timedelta(hours=1),
                      components=[{"name": "Telegram API", "status": "not_configured", "message": "", "counts": {}},
                                  {"name": "Web search - Brave Search API", "status": "ok", "message": "",
                                   "counts": {}}])
        failed = ScanRun(brand_id=brand_id, module=ModuleName.apk, status=ScanStatus.failed, stats={"runner": "apk"},
                         finished_at=now, components=[{"name": "Web search - Brave Search API", "status": "failed",
                                                       "message": "x", "counts": {}, "fatal": True}])
        db.add_all([old, new, failed])
    stats = client.get("/api/v1/stats/executive", headers=admin).json()
    # the newest *completed* scan (a failed one does not count as "scanned"); latest run per runner only
    assert stats["last_completed_scan_at"].startswith((now - timedelta(hours=1)).isoformat()[:16])
    assert stats["components_unavailable"] == 1  # social: Telegram API
    assert stats["scans_failed"] == 1  # apk: its latest run checked nothing


@pytest.mark.req("RDA-02", "RDA-17", "RDA-22")
def test_failed_latest_scan_blocks_no_threats_claim(client, admin):  # noqa: F811
    """A scanner whose latest run failed or was cancelled checked nothing: it is counted, per brand and scanner,
    however many older runs exist."""
    brand_id = _brand()
    now = datetime.now(UTC)
    with session_scope() as db:
        # an older good run, then a newer failed run, of the same scanner
        db.add(ScanRun(brand_id=brand_id, module=ModuleName.apk, status=ScanStatus.completed, stats={"runner": "apk"},
                       finished_at=now - timedelta(days=2), components=[{"name": "x", "status": "ok"}]))
        db.add(ScanRun(brand_id=brand_id, module=ModuleName.apk, status=ScanStatus.failed, stats={"runner": "apk"},
                       finished_at=now - timedelta(hours=1), components=[]))
        db.add(ScanRun(brand_id=brand_id, module=ModuleName.documents, status=ScanStatus.cancelled,
                       stats={"runner": "documents"}, finished_at=now, components=[]))
        # many newer runs of another scanner must not push these out of the window
        for i in range(600):
            db.add(ScanRun(brand_id=brand_id, module=ModuleName.social, status=ScanStatus.completed,
                           stats={"runner": "social"}, finished_at=now - timedelta(minutes=i), components=[]))
    stats = client.get("/api/v1/stats/executive", headers=admin).json()
    assert stats["scans_failed"] == 2


def test_scan_that_could_not_be_queued_is_finished(client, admin, monkeypatch):  # noqa: F811
    from app.workers import tasks

    def broker_down(runs):
        raise ConnectionError("redis down")
    monkeypatch.setattr(tasks, "enqueue_runs", broker_down)
    brand_id = _brand()
    (scan,) = client.post("/api/v1/scans", headers=admin, json={"brand_id": brand_id, "modules": ["apk"]}).json()
    assert scan["status"] == "failed" and scan["finished_at"]
