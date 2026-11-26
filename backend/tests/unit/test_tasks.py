import uuid

import pytest

from app.workers import tasks

pytestmark = pytest.mark.req("FND-07", "LOGO-01")


@pytest.fixture
def sent(monkeypatch):
    calls = []
    monkeypatch.setattr(tasks.run_scan, "apply_async",
                        lambda args, kwargs=None, queue=None: calls.append((args[0], (kwargs or {}).get("then"), queue)))
    return calls


def test_logo_follows_domain_scan(sent):
    ids = {r: uuid.uuid4() for r in ["domains", "apk", "logo", "documents"]}
    tasks.enqueue_runs([(i, r) for r, i in ids.items()])
    by_id = {s[0]: s for s in sent}
    assert str(ids["logo"]) not in by_id, "logo must not start before the domain scan"
    assert by_id[str(ids["domains"])] == (str(ids["domains"]), [str(ids["logo"]), "logo"], "browser")
    assert by_id[str(ids["apk"])][2] == "default" and by_id[str(ids["documents"])][1] is None


def test_logo_alone_runs_immediately(sent):
    logo = uuid.uuid4()
    tasks.enqueue_runs([(logo, "logo")])
    assert sent == [(str(logo), None, "browser")]


def test_follow_up_queued_after_scan(monkeypatch, sent):
    monkeypatch.setattr(tasks, "execute_scan", lambda scan_id: {"findings": 1})
    logo = str(uuid.uuid4())
    tasks.run_scan.run(str(uuid.uuid4()), then=[logo, "logo"])
    assert sent == [(logo, None, "browser")]
