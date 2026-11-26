"""Automatic scan control (D-39): master switch, per-brand on/off, frequency, scanners; manual scans unaffected."""

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core import autoscan
from app.core.security import hash_password
from app.db.models import Brand, Role, ScanRun, User
from app.db.session import session_scope

PASSWORD = "Correct-Horse-9"


def _brand(**kw) -> Brand:
    b = Brand(name="B", keywords=["b"], is_active=True, auto_scan_enabled=True, auto_scan_frequency="daily",
              auto_scan_runners=[], last_auto_scan_at=None)
    for k, v in kw.items():
        setattr(b, k, v)
    return b


@pytest.mark.req("D-39")
def test_plan_respects_switch_frequency_and_scanners():
    now = datetime(2026, 10, 10, 2, 0, tzinfo=UTC)
    assert autoscan.plan(_brand(auto_scan_enabled=False), None, now) == []
    assert autoscan.plan(_brand(), None, now) == autoscan.ALL_RUNNERS  # never scanned, empty selection = all
    weekly = _brand(auto_scan_frequency="weekly", last_auto_scan_at=now - timedelta(days=3))
    assert autoscan.plan(weekly, None, now) == []
    assert autoscan.plan(_brand(auto_scan_frequency="weekly", last_auto_scan_at=now - timedelta(days=7, minutes=-5)),
                         None, now) != []
    chosen = _brand(auto_scan_runners=["domains", "rogue_app"])
    assert autoscan.plan(chosen, None, now) == ["domains", "rogue_app"]
    assert autoscan.plan(chosen, ["social_media"], now) == []        # narrower job, scanner not selected
    assert autoscan.plan(chosen, ["domains"], now) == ["domains"]    # 6-hourly domain re-check
    assert autoscan.plan(weekly, ["domains"], now) == []             # re-checks only for daily brands


@pytest.fixture
def admin(clean_db):
    from app.main import app

    with session_scope() as db:
        db.add(User(email="adm@test.local", name="Adm", password_hash=hash_password(PASSWORD), role=Role.admin))
    c = TestClient(app)
    token = c.post("/api/v1/auth/login", json={"email": "adm@test.local", "password": PASSWORD}).json()
    c.headers["Authorization"] = f"Bearer {token['access_token']}"
    return c


@pytest.mark.req("D-39")
def test_master_switch_and_brand_settings_api(admin, monkeypatch):
    from app.workers import tasks

    queued = []
    monkeypatch.setattr(tasks, "enqueue_runs", lambda runs: queued.extend(runs))
    b = admin.post("/api/v1/brands", json={"name": "Acme"}).json()
    assert b["auto_scan_enabled"] is False and b["next_auto_scan_at"] is None  # off by default
    assert tasks.schedule_all() == 0

    b = admin.patch(f"/api/v1/brands/{b['id']}", json={"auto_scan_enabled": True, "auto_scan_frequency": "weekly",
                                                       "auto_scan_runners": ["rogue_app"]}).json()
    assert b["auto_scan_enabled"] and b["auto_scan_runners"] == ["rogue_app"] and b["next_auto_scan_at"]
    assert admin.put("/api/v1/settings/auto-scan", json={"enabled": False}).json()["enabled"] is False
    assert tasks.schedule_all() == 0  # master switch off

    s = admin.put("/api/v1/settings/auto-scan", json={"enabled": True}).json()
    assert s["enabled"] and s["brands_enabled"] == 1
    assert tasks.schedule_all() == 1 and [r for _, r in queued] == ["rogue_app"]
    assert tasks.schedule_all() == 0  # weekly: not due again
    with session_scope() as db:
        assert {r.trigger for r in db.scalars(select(ScanRun))} == {"schedule"}
