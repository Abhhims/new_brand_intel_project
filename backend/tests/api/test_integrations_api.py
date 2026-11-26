"""SP1 / RDA-03: every integration the platform uses is listed with whether it is configured and how it last ran."""

from datetime import UTC, datetime

import pytest

from app.config import get_settings
from app.db.models import Brand, EmailMessage, ModuleName, ScanRun, ScanStatus
from app.db.session import session_scope
from tests.api.test_api import admin, analyst, client  # noqa: F401 - shared fixtures

pytestmark = pytest.mark.req("RDA-03")


def _by_id(client, headers) -> dict:  # noqa: F811
    r = client.get("/api/v1/integrations", headers=headers)
    assert r.status_code == 200, r.text
    return {i["id"]: i for i in r.json()}


def test_lists_every_integration_with_configuration(client, analyst, monkeypatch):  # noqa: F811
    s = get_settings()
    monkeypatch.setattr(s, "urlscan_api_key", None)
    monkeypatch.setattr(s, "brave_search_api_key", "secret-brave-key-123")
    items = _by_id(client, analyst)
    for key in ("web_search", "crtsh", "rdap", "dns", "browser", "telegram_api", "google_play", "rspamd", "clamav",
                "yara", "urlhaus", "openphish", "urlscan", "abuseipdb", "imap_reports", "dmarc_mailbox"):
        assert key in items, key
    assert items["urlscan"]["configured"] is False and "URLSCAN_API_KEY" in items["urlscan"]["how_to_configure"]
    assert items["web_search"]["configured"] is True and items["web_search"]["name"].endswith("Brave Search API")
    assert items["urlscan"]["last_status"] is None  # never ran: unknown, not "ok"
    assert "secret-brave-key-123" not in str(items)


def test_last_status_comes_from_latest_scan_component(client, admin, monkeypatch):  # noqa: F811
    s = get_settings()
    monkeypatch.setattr(s, "brave_search_api_key", None)
    monkeypatch.setattr(s, "serpapi_api_key", None)
    monkeypatch.setattr(s, "free_search_fallback", True)
    with session_scope() as db:
        b = Brand(name="Example Bank", keywords=["examplebank"])
        db.add(b)
        db.flush()
        db.add(ScanRun(brand_id=b.id, module=ModuleName.documents, status=ScanStatus.failed, stats={"runner": "documents"},
                       finished_at=datetime.now(UTC), components=[{"name": "Web search - DuckDuckGo (free, paced)", "status": "unavailable",
                                    "message": "rate-limited", "counts": {}, "fatal": True}]))
    item = _by_id(client, admin)["web_search"]
    assert item["last_status"] == "unavailable" and item["last_message"] == "rate-limited"
    assert item["last_checked_at"]


def test_email_tool_status_comes_from_latest_analysed_email(client, admin):  # noqa: F811
    with session_scope() as db:
        b = Brand(name="Example Bank", keywords=["examplebank"])
        db.add(b)
        db.flush()
        db.add(EmailMessage(brand_id=b.id, fingerprint="f", channel="upload", raw_sha256="0" * 64, status="analysed",
                            auth={"not_checked": [{"tool": "urlscan", "target": "https://x.example/",
                                                   "status": "not_checked"}]}))
    items = _by_id(client, admin)
    assert items["urlscan"]["last_status"] == "unavailable"
    assert items["rspamd"]["last_status"] == "ok"
