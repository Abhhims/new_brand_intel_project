"""SP2 finding model: candidate → finding → alert, re-scan observations, meaningful changes, analyst decisions."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.core.findings import record_detection, set_decision
from app.core.scoring import Signals
from app.core.security import hash_password
from app.db.models import (
    Alert,
    AllowKind,
    Brand,
    BrandAllow,
    Finding,
    FindingDecision,
    FindingStage,
    ModuleName,
    Observation,
    RiskLevel,
    Role,
    User,
)
from app.db.session import session_scope
from app.modules.base import Detection

PASSWORD = "Correct-Horse-9"
LIVE = Signals(brand_exact_in_domain=True, typo_similarity=95, mx_present=True, https=True, page_live=True,
               brand_on_page=True)
LOGIN = Signals(brand_exact_in_domain=True, typo_similarity=95, mx_present=True, https=True, page_live=True,
                brand_on_page=True, login_payment_keywords=True)


def _det(key="zentrova-pay.com", signals=LIVE, analysed=True, **kw) -> Detection:
    return Detection(entity_key=key, title=f"Look-alike {key}", signals=signals, details={"Domain": key},
                     analysed=analysed, **kw)


@pytest.fixture
def brand_id(clean_db):
    with session_scope() as db:
        b = Brand(name="Zentrova Bank", keywords=["zentrova"])
        db.add(b)
        db.flush()
        return b.id


def _counts(db, brand_id):
    return (db.scalar(select(func.count()).select_from(Finding).where(Finding.brand_id == brand_id)),
            db.scalar(select(func.count()).select_from(Alert).where(Alert.brand_id == brand_id)),
            db.scalar(select(func.count()).select_from(Observation)))


@pytest.mark.req("RDA-12", "D-33")
def test_candidate_never_alerts_and_promotion_alerts(brand_id):
    with session_scope() as db:
        f, alert, created = record_detection(db, brand_id, ModuleName.typosquat,
                                             _det(signals=Signals(brand_exact_in_domain=True, typo_similarity=95),
                                                  analysed=False))
        assert created and f.stage == FindingStage.candidate and alert is None
        f, alert, _ = record_detection(db, brand_id, ModuleName.phishing, _det())
        assert f.stage == FindingStage.finding and alert is not None
        assert "Candidate → Finding" in alert.reason or alert.trigger == "first_crossing"
        assert {e.kind for e in f.events} >= {"discovered", "promoted", "alerted"}


@pytest.mark.req("RDA-12", "D-34")
def test_brand_alert_level_holds_back_lower_findings(brand_id):
    with session_scope() as db:
        db.get(Brand, brand_id).alert_min_level = RiskLevel.high
        f, alert, _ = record_detection(db, brand_id, ModuleName.mx, _det(signals=Signals(typo_similarity=90,
                                                                                       mx_present=True)))
        assert f.risk_level in (RiskLevel.low, RiskLevel.medium) and alert is None and f.last_alert_at is None


@pytest.mark.req("RDA-15", "D-36")
def test_rescan_stores_observation_without_new_finding_or_alert(brand_id):
    with session_scope() as db:
        record_detection(db, brand_id, ModuleName.phishing, _det())
        _, alert, created = record_detection(db, brand_id, ModuleName.phishing, _det())
        assert alert is None and not created
        assert _counts(db, brand_id) == (1, 1, 2)


@pytest.mark.req("RDA-15", "D-36")
def test_meaningful_change_raises_new_alert_on_timeline(brand_id):
    with session_scope() as db:
        record_detection(db, brand_id, ModuleName.phishing, _det())
        f, alert, _ = record_detection(db, brand_id, ModuleName.phishing, _det(signals=LOGIN))
        assert alert is not None and alert.trigger == "change"
        assert "Login/payment form detected" in alert.reason
        assert any(e.kind == "changed" and "Login" in (e.note or "") for e in f.events)


@pytest.mark.req("RDA-15", "D-31")
def test_unknown_state_is_not_a_change(brand_id):
    with session_scope() as db:
        record_detection(db, brand_id, ModuleName.phishing, _det(signals=LOGIN))
        f, alert, _ = record_detection(db, brand_id, ModuleName.phishing,
                                       _det(signals=LOGIN, state={"live": None, "login_form": None}))
        assert alert is None and f.state["live"] is True


@pytest.mark.req("RDA-11", "D-35", "D-36")
def test_closed_decision_suppresses_until_meaningful_change_reopens(brand_id):
    with session_scope() as db:
        f, _, _ = record_detection(db, brand_id, ModuleName.phishing, _det())
        set_decision(db, f, FindingDecision.false_positive, None, "Partner site")
        _, alert, _ = record_detection(db, brand_id, ModuleName.phishing, _det())
        assert alert is None and f.decision == FindingDecision.false_positive
        _, alert, _ = record_detection(db, brand_id, ModuleName.phishing, _det(signals=LOGIN))
        assert alert is not None and alert.trigger == "reopen" and f.decision == FindingDecision.new
        assert any(e.kind == "reopened" for e in f.events)


@pytest.fixture
def client(brand_id):
    from app.main import app

    with session_scope() as db:
        db.add(User(email="ana@test.local", name="Ana", password_hash=hash_password(PASSWORD), role=Role.analyst))
    c = TestClient(app)
    token = c.post("/api/v1/auth/login", json={"email": "ana@test.local", "password": PASSWORD}).json()
    c.headers["Authorization"] = f"Bearer {token['access_token']}"
    return c


@pytest.mark.req("RDA-11", "RDA-12", "D-35")
def test_findings_api_filters_decisions_and_allowlist(client, brand_id):
    with session_scope() as db:
        record_detection(db, brand_id, ModuleName.phishing, _det())
        record_detection(db, brand_id, ModuleName.typosquat, _det("zentrova-x.com", Signals(typo_similarity=90),
                                                                  analysed=False))
        record_detection(db, brand_id, ModuleName.social, Detection(
            entity_key="x:zentrova_fans", title="fan page", signals=Signals(typo_similarity=90),
            details={}, analysed=True))
    cands = client.get("/api/v1/findings", params={"stage": "Candidate"}).json()
    assert cands["total"] == 1 and cands["items"][0]["entity_key"] == "zentrova-x.com"
    assert client.get("/api/v1/findings", params={"alerted": True}).json()["total"] >= 1

    social = client.get("/api/v1/findings", params={"module": "social"}).json()["items"][0]
    r = client.post(f"/api/v1/findings/{social['id']}/decision",
                    json={"decision": "Legitimate", "note": "Official fan club", "add_to_allowlist": True})
    assert r.status_code == 200 and r.json()["decision"] == "Legitimate"
    with session_scope() as db:
        assert db.scalar(select(BrandAllow).where(BrandAllow.kind == AllowKind.social_handle,
                                                  BrandAllow.value == "zentrova_fans"))

    ids = [f["id"] for f in client.get("/api/v1/findings", params={"module": "typosquat"}).json()["items"]]
    bad = client.post("/api/v1/findings/decision", json={"finding_ids": ids, "decision": "Ignored"})
    assert bad.status_code == 409  # note required, nothing changed
    ok = client.post("/api/v1/findings/decision", json={"finding_ids": ids, "decision": "Ignored", "note": "noise"})
    assert ok.status_code == 200 and all(f["decision"] == "Ignored" for f in ok.json())

    detail = client.get(f"/api/v1/findings/{social['id']}").json()
    assert detail["observations"] and detail["events"][0]["kind"] == "decision"
