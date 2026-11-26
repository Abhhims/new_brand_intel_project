import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.security import hash_password
from app.db.models import Role, User
from app.db.session import session_scope

pytestmark = pytest.mark.req("EML-13", "EML-14")

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "emails"
PASSWORD = "Correct-Horse-9"


@pytest.fixture
def client(clean_db, monkeypatch):
    # Analysis runs inline in tests (no Celery/engines/network): patch external calls to deterministic verdicts.
    from app.modules.email import analysis
    from app.modules.email.model import ToolVerdict

    monkeypatch.setattr(analysis.intel, "url_reputation", lambda url: [
        ToolVerdict("urlhaus", status="ok", malicious=True), ToolVerdict("openphish", status="ok", malicious=True)])
    monkeypatch.setattr(analysis.intel, "urlhaus_hash", lambda h: ToolVerdict("urlhaus", status="not_checked"))
    monkeypatch.setattr(analysis.intel, "abuseipdb_check", lambda ip: ToolVerdict("abuseipdb", status="not_checked"))
    monkeypatch.setattr(analysis.engines, "rspamd_check", lambda raw: ToolVerdict("rspamd", status="not_checked"))
    monkeypatch.setattr(analysis.engines, "clamav_scan", lambda d: ToolVerdict("clamav", status="not_checked"))
    monkeypatch.setattr(analysis.engines, "yara_scan", lambda d: ToolVerdict("yara", status="not_checked"))
    monkeypatch.setattr(analysis, "_domain_age_days", lambda d: None)
    monkeypatch.setattr(analysis, "_live_page_phishing", lambda urls, ctx: [])

    from app.main import app

    with session_scope() as db:
        db.add(User(email="a@test.local", name="A", password_hash=hash_password(PASSWORD), role=Role.admin))
    return TestClient(app)


@pytest.fixture
def brand_id(client):
    from app.db.models import Brand

    with session_scope() as db:
        b = Brand(name="Zentrova Bank", keywords=["zentrova", "zentrova bank"])
        from app.db.models import AllowKind, BrandAllow

        b.allowlist = [BrandAllow(kind=AllowKind.domain, value="zentrova.com"),
                       BrandAllow(kind=AllowKind.email_domain, value="zentrova.com")]
        db.add(b)
        db.flush()
        return str(b.id)


def _auth(client):
    r = client.post("/api/v1/auth/login", json={"email": "a@test.local", "password": PASSWORD})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _upload(client, brand_id, name="lookalike.eml"):
    headers = _auth(client)
    return client.post("/api/v1/emails", headers=headers, data={"brand_id": brand_id},
                       files={"file": (name, (FIX / name).read_bytes(), "message/rfc822")})


def test_upload_creates_email_alert_with_evidence(client, brand_id):
    r = _upload(client, brand_id)
    assert r.status_code == 202, r.text
    email_id = r.json()["id"]
    detail = client.get(f"/api/v1/emails/{email_id}", headers=_auth(client)).json()
    assert detail["status"] == "analysed"
    assert detail["finding"]["module"] == "email"
    assert detail["finding"]["risk_level"] == "Critical"
    assert any(e["kind"] == "metadata" for e in detail["finding"]["evidence"])
    assert detail["finding"]["details"]["Malicious URLs"]


def test_same_email_twice_updates_one_alert(client, brand_id):
    first = _upload(client, brand_id).json()
    second = _upload(client, brand_id).json()
    assert first["id"] == second["id"]
    listing = client.get("/api/v1/emails", headers=_auth(client), params={"brand_id": brand_id}).json()
    assert listing["total"] == 1


def test_non_email_file_rejected(client, brand_id):
    r = client.post("/api/v1/emails", headers=_auth(client), data={"brand_id": brand_id},
                    files={"file": ("photo.png", b"\x89PNG not an email", "image/png")})
    assert r.status_code == 422


def test_unknown_brand(client):
    import uuid

    r = client.post("/api/v1/emails", headers=_auth(client), data={"brand_id": str(uuid.uuid4())},
                    files={"file": ("x.eml", (FIX / "official.eml").read_bytes(), "message/rfc822")})
    assert r.status_code == 404


def test_official_email_low_risk(client, brand_id):
    r = _upload(client, brand_id, "official.eml")
    detail = client.get(f"/api/v1/emails/{r.json()['id']}", headers=_auth(client)).json()
    assert detail["finding"]["risk_level"] in ("Low", "Medium")
    assert detail["finding"]["details"]["Official Sender"] is True


@pytest.mark.req("RDA-21", "EML-13")
def test_failed_analysis_is_marked_failed_not_left_queued(client, brand_id, monkeypatch):
    """When every retry of the analysis fails, the email shows 'failed' with the reason — never 'queued' forever."""
    from app.core import evidence
    from app.db.models import EmailMessage
    from app.modules.email import service
    from app.workers import tasks

    with session_scope() as db:
        row = EmailMessage(brand_id=brand_id, fingerprint="fp-1", channel="upload", raw_sha256="0" * 64,
                           raw_storage_key="emails/x/fp-1.eml", status="queued")
        db.add(row)
        db.flush()
        email_id = str(row.id)
    monkeypatch.setattr(evidence, "get", lambda key: b"Subject: hi\r\n\r\nbody")

    def boom(db, row, raw, filename="email.eml"):
        raise ConnectionError("rspamd unreachable")
    monkeypatch.setattr(service, "analyse_stored", boom)
    with pytest.raises(ConnectionError):
        tasks.analyse_email.apply(args=[email_id], retries=tasks.analyse_email.max_retries).get()
    with session_scope() as db:
        row = db.get(EmailMessage, uuid.UUID(email_id))
        assert row.status == "failed" and "rspamd unreachable" in row.error
