"""REST API tests: auth & roles, brand onboarding, alert queue filters, workflow, exports, dashboard stats."""

import csv
import io
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.findings import record_detection
from app.core.scoring import Signals
from app.core.security import hash_password
from app.db.models import Brand, ModuleName, RiskLevel, Role, User
from app.db.session import session_scope
from app.modules.base import Detection

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
PASSWORD = "Correct-Horse-9"


@pytest.fixture
def client(clean_db):
    from app.main import app

    with session_scope() as db:
        db.add(User(email="admin@test.local", name="Admin", password_hash=hash_password(PASSWORD), role=Role.admin))
        db.add(User(email="analyst@test.local", name="Ana Lyst", password_hash=hash_password(PASSWORD),
                    role=Role.analyst))
    return TestClient(app)


def _login(client, email):
    r = client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture
def admin(client):
    return _login(client, "admin@test.local")


@pytest.fixture
def analyst(client):
    return _login(client, "analyst@test.local")


@pytest.fixture
def alerts(client):
    """One brand with an alert per module, created through the real alert engine."""
    samples = [
        (ModuleName.phishing, "zentrova-login.com", Signals(brand_exact_in_domain=True, typo_similarity=100, https=True,
                                                            mx_present=True, login_payment_keywords=True,
                                                            page_live=True, brand_on_page=True)),
        (ModuleName.mx, "zentr0va.com", Signals(typo_similarity=95, mx_present=True)),
        (ModuleName.typosquat, "zentorva.in", Signals(typo_similarity=87)),
        (ModuleName.apk, "apk:com.zentrova.fake", Signals(typo_similarity=90, publisher_mismatch=True)),
        (ModuleName.rogue_app, "play:com.rogue", Signals(publisher_mismatch=True)),
        (ModuleName.social, "x:zentrova_support", Signals(typo_similarity=95, social_image_match=True)),
        (ModuleName.documents, "https://x.test/salary.pdf", Signals(doc_brand_keyword=True, doc_sensitive_pattern=True)),
        (ModuleName.logo, "https://partner.test/", Signals(official_logo=True)),
    ]
    with session_scope() as db:
        # alert from Low so every sample becomes an alert (D-34 threshold tested separately)
        brand = Brand(name="Zentrova Bank", keywords=["zentrova"], alert_min_level=RiskLevel.low)
        other = Brand(name="Other Brand", keywords=["other"], alert_min_level=RiskLevel.low)
        db.add_all([brand, other])
        db.flush()
        for module, key, sig in samples:
            record_detection(db, brand.id, module, Detection(entity_key=key, title=f"{module.value} {key}", signals=sig,
                                                        details={"Domain": key}))
        record_detection(db, other.id, ModuleName.typosquat, Detection(entity_key="0ther.com", title="other",
                                                                  signals=Signals(), details={}))
        return {"brand_id": str(brand.id), "other_id": str(other.id)}


# ------------------------------------------------------------------ auth
@pytest.mark.req("FND-03", "D-15")
def test_login_and_protected_routes(client):
    assert client.get("/api/v1/alerts").status_code == 401
    bad = client.post("/api/v1/auth/login", json={"email": "admin@test.local", "password": "wrong-password"})
    assert bad.status_code == 401
    headers = _login(client, "ADMIN@test.local")  # case-insensitive email
    me = client.get("/api/v1/auth/me", headers=headers).json()
    assert me["role"] == "admin" and "password_hash" not in me
    assert client.get("/api/v1/alerts", headers={"Authorization": "Bearer forged.token.value"}).status_code == 401


@pytest.mark.req("FND-03", "D-15")
def test_analyst_cannot_administer(client, analyst):
    assert client.post("/api/v1/brands", json={"name": "X"}, headers=analyst).status_code == 403
    assert client.get("/api/v1/users", headers=analyst).status_code == 403


@pytest.mark.req("FND-03")
def test_admin_manages_users(client, admin):
    r = client.post("/api/v1/users", json={"email": "new@test.local", "name": "New", "password": "LongEnough-1",
                                           "role": "analyst"}, headers=admin)
    assert r.status_code == 201
    uid = r.json()["id"]
    assert client.patch(f"/api/v1/users/{uid}", json={"is_active": False}, headers=admin).json()["is_active"] is False
    login = client.post("/api/v1/auth/login", json={"email": "new@test.local", "password": "LongEnough-1"})
    assert login.status_code == 401  # deactivated


# ------------------------------------------------------------------ brands
@pytest.mark.req("FND-04", "FND-05", "FND-06", "OUT-01")
def test_brand_onboarding_with_logo_and_allowlists(client, admin):
    r = client.post("/api/v1/brands", headers=admin, json={
        "name": "Acme Pay", "keywords": ["acme", " acme pay ", "acme"], "product_terms": ["acme wallet"],
        "allowlist": [{"kind": "domain", "value": "https://www.AcmePay.com/"},
                      {"kind": "publisher", "value": "Acme Payments Ltd"}]})
    assert r.status_code == 201, r.text
    brand = r.json()
    assert brand["keywords"] == ["acme", "acme pay"]
    assert {(a["kind"], a["value"]) for a in brand["allowlist"]} == {("domain", "acmepay.com"),
                                                                      ("publisher", "Acme Payments Ltd")}
    logo = (FIXTURES / "brand" / "logo.png").read_bytes()
    up = client.post(f"/api/v1/brands/{brand['id']}/assets", headers=admin, data={"kind": "logo"},
                     files={"file": ("logo.png", logo, "image/png")})
    assert up.status_code == 201, up.text
    assert up.json()["phash"] and up.json()["url"]
    fav = client.post(f"/api/v1/brands/{brand['id']}/assets", headers=admin, data={"kind": "favicon"},
                      files={"file": ("favicon.ico", (FIXTURES / "brand" / "favicon.ico").read_bytes(), "image/x-icon")})
    assert fav.json()["mmh3"] is not None
    bad = client.post(f"/api/v1/brands/{brand['id']}/assets", headers=admin, data={"kind": "logo"},
                      files={"file": ("x.png", b"not an image", "image/png")})
    assert bad.status_code == 422
    add = client.post(f"/api/v1/brands/{brand['id']}/allowlist", headers=admin,
                      json={"kind": "social_handle", "value": "@acmepay"})
    assert add.json()["value"] == "acmepay"
    assert client.post(f"/api/v1/brands/{brand['id']}/allowlist", headers=admin,
                       json={"kind": "social_handle", "value": "acmepay"}).status_code == 409
    assert client.post("/api/v1/brands", headers=admin, json={"name": "Acme Pay"}).status_code == 409


# ------------------------------------------------------------------ alert queue
@pytest.mark.req("DSH-07", "DSH-09", "DSH-11", "DSH-12", "DSH-13", "DSH-14", "DSH-15", "DSH-16", "DSH-21", "AC-09")
def test_alert_queue_filters_and_search(client, analyst, alerts):
    def q(**params):
        r = client.get("/api/v1/alerts", params=params, headers=analyst)
        assert r.status_code == 200, r.text
        return r.json()

    everything = q(page_size=100)
    assert everything["total"] == 9
    from app.modules.registry import PHASE1_MODULES

    assert {a["module"] for a in everything["items"]} == {m.value for m in PHASE1_MODULES}
    assert q(brand_id=alerts["brand_id"])["total"] == 8
    assert q(module=["social", "apk"])["total"] == 2
    crit = q(risk_level="Critical")
    assert crit["total"] >= 1 and all(a["risk_level"] == "Critical" for a in crit["items"])
    assert q(status="New")["total"] == 9 and q(status="Resolved")["total"] == 0
    assert q(q="zentr0va")["total"] == 1
    assert q(q="ZENTROVA BANK")["total"] == 8  # search matches brand name
    today = everything["items"][0]["first_seen"][:10]
    assert q(date_from=today, date_to=today)["total"] == 9
    assert q(date_from="2000-01-01", date_to="2000-01-02")["total"] == 0
    page = q(page=2, page_size=4, sort="risk")
    assert page["page"] == 2 and len(page["items"]) == 4
    scores = [a["score"] for a in q(sort="risk", page_size=100)["items"]]
    assert scores == sorted(scores, reverse=True)


# ------------------------------------------------------------------ workflow
@pytest.mark.req("AC-10", "DSH-10", "D-07")
def test_ac10_analyst_changes_alert_status(client, analyst, alerts):
    """AC-10: an analyst moves an alert through the workflow; every change is audited."""
    alert = client.get("/api/v1/alerts", params={"module": "phishing"}, headers=analyst).json()["items"][0]
    url = f"/api/v1/alerts/{alert['id']}/status"
    r = client.post(url, json={"status": "Investigating", "note": "Checking hosting provider"}, headers=analyst)
    assert r.status_code == 200 and r.json()["status"] == "Investigating"
    assert client.post(url, json={"status": "Confirmed Threat"}, headers=analyst).json()["status"] == "Confirmed Threat"
    bad = client.post(url, json={"status": "False Positive", "note": "x"}, headers=analyst)
    assert bad.status_code == 409 and "Allowed" in bad.json()["detail"]
    final = client.post(url, json={"status": "Resolved", "note": "Taken down"}, headers=analyst).json()
    assert final["status"] == "Resolved"
    events = [e for e in final["events"] if e["kind"] == "decision"]
    assert [(e["from_status"], e["to_status"]) for e in reversed(events)] == [
        ("New", "Investigating"), ("Investigating", "Confirmed Threat"), ("Confirmed Threat", "Resolved")]
    assert events[0]["user_name"] == "Ana Lyst" and events[0]["note"] == "Taken down"
    assert client.get("/api/v1/alerts", params={"status": "Resolved"}, headers=analyst).json()["total"] == 1


@pytest.mark.req("DSH-10", "D-07", "RDA-11")
def test_false_positive_path(client, analyst, alerts):
    alert = client.get("/api/v1/alerts", params={"module": "social"}, headers=analyst).json()["items"][0]
    url = f"/api/v1/alerts/{alert['id']}/status"
    no_note = client.post(url, json={"status": "False Positive"}, headers=analyst)
    assert no_note.status_code == 409 and "note is required" in no_note.json()["detail"]
    r = client.post(url, json={"status": "False Positive", "note": "Fan page, not impersonation"}, headers=analyst)
    assert r.json()["status"] == "False Positive"


@pytest.mark.req("DSH-08", "FND-12")
def test_alert_detail_has_scoring_explanation(client, analyst, alerts):
    alert = client.get("/api/v1/alerts", params={"module": "phishing"}, headers=analyst).json()["items"][0]
    d = client.get(f"/api/v1/alerts/{alert['id']}", headers=analyst).json()
    assert d["signals"]["rules"]["brand_exact_in_domain"] == 40
    assert d["details"]["Risk Level"] == d["risk_level"]
    assert {"discovered", "alerted"} <= {e["kind"] for e in d["events"]}
    assert d["finding_id"] and d["reason"].startswith("First reached") and d["trigger"] == "first_crossing"


# ------------------------------------------------------------------ dashboard + exports
@pytest.mark.req("DSH-01", "DSH-02", "DSH-03", "DSH-04", "DSH-05", "DSH-06", "DSH-17")
def test_executive_dashboard_numbers(client, analyst, alerts):
    s = client.get("/api/v1/stats/executive", headers=analyst).json()
    assert s["total_alerts_today"] == 9
    assert s["new_phishing_domains"] == 4  # typosquat + mx + phishing stages, incl. other brand
    assert s["new_impersonation_accounts"] == 1
    assert s["new_rogue_apps"] == 2  # fake APK + rogue Play app
    assert s["sensitive_document_exposures"] == 1
    assert s["phishing_emails_today"] == 0 and s["spoofed_sender_attempts"] == 0  # no email alerts in this fixture
    assert s["high_critical_alerts"] == sum(v for k, v in s["by_risk"].items() if k in ("High", "Critical"))
    one = client.get("/api/v1/stats/executive", params={"brand_id": alerts["other_id"]}, headers=analyst).json()
    assert one["total_alerts_today"] == 1
    trend = client.get("/api/v1/stats/trends", params={"days": 7}, headers=analyst).json()
    assert len(trend) == 7 and trend[-1]["total"] == 9


@pytest.mark.req("DSH-18")
def test_csv_export_matches_filters(client, analyst, alerts):
    r = client.get("/api/v1/exports/alerts.csv", params={"brand_id": alerts["brand_id"]}, headers=analyst)
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    rows = list(csv.reader(io.StringIO(r.text.lstrip("﻿"))))
    assert rows[0][:7] == ["Alert ID", "Finding ID", "Scan ID", "Brand", "Module", "Title", "Risk Level"]
    assert "Domain" in rows[0] and len(rows) == 9  # header + 8
    r = client.get("/api/v1/exports/alerts.csv", params={"brand_id": alerts["brand_id"], "simple": True},
                   headers=analyst)
    simple = list(csv.reader(io.StringIO(r.text.lstrip("﻿"))))
    assert simple[0] == ["Brand", "Module", "Title", "Risk Level", "Score", "Status", "Alerted (UTC)", "Link"]
    assert len(simple) == 9 and all(len(row) == 8 for row in simple)


@pytest.mark.req("DSH-19")
def test_pdf_export_html_renders_all_rows(client, analyst, alerts):
    """PDF layout is generated from HTML; the binary render runs in the Docker image (WeasyPrint)."""
    from app.api.alerts import AlertFilters
    from app.api.exports import _pdf_html, _rows
    from app.db.session import SessionLocal

    db = SessionLocal()
    try:
        filters = AlertFilters(brand_id=None, module=None, risk_level=None, status=None, date_from=None,
                               date_to=None, q=None, suspected_phishing=None, sort="risk")
        rows = _rows(db, filters)
        doc = _pdf_html(rows, filters)
    finally:
        db.close()
    assert doc.count("<tr class='r-") == 9 and "Alert Report" in doc
    r = client.get("/api/v1/exports/alerts.pdf", headers=analyst)
    assert r.status_code in (200, 503)
    if r.status_code == 200:
        assert r.content.startswith(b"%PDF")


def test_findings_export_social_media(client, analyst, alerts):
    params = {"module": ["social_media", "social"]}
    r = client.get("/api/v1/exports/findings.csv", params=params, headers=analyst)
    assert r.status_code == 200 and "social-media-" in r.headers["content-disposition"]
    rows = list(csv.reader(io.StringIO(r.text.lstrip("﻿"))))
    assert rows[0][:4] == ["Finding ID", "Brand", "Module", "Title"]
    listed = client.get("/api/v1/findings", params={**params, "page_size": 200}, headers=analyst).json()["total"]
    assert len(rows) == listed + 1
    r = client.get("/api/v1/exports/findings.csv", params={**params, "links_only": True}, headers=analyst)
    links = list(csv.reader(io.StringIO(r.text.lstrip("﻿"))))
    levels = [h.split(" (")[0] for h in links[0]]  # one column per risk level, e.g. "Critical (54)"
    order = ["Critical", "High", "Medium", "Low"]
    assert levels == sorted(levels, key=order.index) and set(levels) <= set(order)
    assert all(cell.startswith("http") for row in links[1:] for cell in row if cell)
    r = client.get("/api/v1/exports/findings.pdf", params=params, headers=analyst)
    assert r.status_code in (200, 503)


@pytest.mark.req("FND-08", "DEL-04")
def test_openapi_documents_every_endpoint(client):
    paths = client.get("/openapi.json").json()["paths"]
    for p in ["/api/v1/auth/login", "/api/v1/brands", "/api/v1/alerts", "/api/v1/alerts/{alert_id}/status",
              "/api/v1/scans", "/api/v1/stats/executive", "/api/v1/exports/alerts.csv", "/api/v1/exports/alerts.pdf"]:
        assert p in paths


@pytest.mark.req("FND-13")
def test_health_and_request_ids(client):
    r = client.get("/health")
    assert r.json()["status"] == "ok" and r.headers["x-request-id"]


@pytest.mark.req("D-27", "D-32", "RDA-01", "RDA-04")
def test_brand_api_has_no_demo_mode(client, admin):
    """The product has no demo mode: the field is rejected and never returned (D-32)."""
    r = client.post("/api/v1/brands", headers=admin, json={"name": "Real Co", "demo_mode": True})
    assert r.status_code == 422
    brand = client.post("/api/v1/brands", headers=admin, json={"name": "Real Co"}).json()
    assert "demo_mode" not in brand
    assert client.patch(f"/api/v1/brands/{brand['id']}", headers=admin, json={"demo_mode": True}).status_code == 422
