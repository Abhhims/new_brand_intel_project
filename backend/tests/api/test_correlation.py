"""SP4 / D-49: findings that share a stable identifier are linked; shared hosting alone never forms a campaign."""

import pytest

from app.core import correlation
from app.core.findings import record_detection
from app.core.scoring import Signals
from app.db.models import Brand, Finding, ModuleName, RiskLevel
from app.db.session import session_scope
from app.modules.base import Detection
from tests.api.test_api import admin, analyst, client  # noqa: F401 - fixtures

pytestmark = pytest.mark.req("RDA-14", "RDA-16", "D-49")
SM, PH = ModuleName.social_media, ModuleName.phishing


# ------------------------------------------------------------------ extraction (no database)
def test_extract_normalises_contacts_and_skips_providers():
    got = correlation.extract(SM, "youtube:video:1", {"Scam Contacts": [
        "phone: +91 98765 43210", "whatsapp: wa.me/919876543210", "upi: Refund.Desk@ybl"]}, [])
    assert {(i.kind, i.value) for i in got} == {("contact_phone", "9876543210"), ("contact_upi", "refund.desk@ybl")}
    dom = correlation.extract(PH, "examp1ebank.com", {"A Records": ["203.0.113.5"], "MX Records": [
        "10 mx1.examp1ebank.com", "1 aspmx.l.google.com", "5 mail.evil-mailer.net"]}, [])
    assert {(i.kind, i.value) for i in dom} == {("domain", "examp1ebank.com"), ("ip", "203.0.113.5"),
                                                ("mail_server", "evil-mailer.net")}


def test_certificate_counts_only_when_issued_for_the_domain():
    own = {"sha256": "ab" * 32, "subject_cn": "examp1ebank.com", "san": ["examp1ebank.com", "exampiebank.com"]}
    parking = {"sha256": "cd" * 32, "subject_cn": "*.parkinghost.net", "san": ["*.parkinghost.net"]}
    kinds = {i.kind for i in correlation.extract(PH, "exampiebank.com", {}, [("ssl", own)])}
    assert "tls_cert" in kinds
    assert "tls_cert" not in {i.kind for i in correlation.extract(PH, "exampiebank.com", {}, [("ssl", parking)])}


def test_apk_signer_only_when_not_official():
    fake = correlation.extract(ModuleName.apk, "apk:x", {"Signer Matches Official": False,
                                                        "Signer SHA-256": "AA:BB", "SHA256": "f1"}, [])
    real = correlation.extract(ModuleName.apk, "apk:y", {"Signer Matches Official": True,
                                                        "Signer SHA-256": "CC:DD", "SHA256": "f2"}, [])
    assert ("apk_signer", "aa:bb") in {(i.kind, i.value) for i in fake}
    assert "apk_signer" not in {i.kind for i in real}


# ------------------------------------------------------------------ engine + API (database)
def _seed():
    with session_scope() as db:
        brand = Brand(name="Zentrova Bank", keywords=["zentrova"], alert_min_level=RiskLevel.low)
        db.add(brand)
        db.flush()

        def post(key, contacts):
            record_detection(db, brand.id, SM, Detection(
                entity_key=key, title=key, signals=Signals(brand_in_content=True, scam_contact_details=True,
                                                           fake_support_claim=True),
                details={"Platform": "YouTube", "Scam Contacts": contacts}, analysed=True))

        post("youtube:video:a", ["phone: 9876543210"])
        post("youtube:video:b", ["whatsapp: wa.me/919876543210", "upi: help@ybl"])
        post("youtube:video:c", ["upi: help@ybl"])      # linked to b by UPI → same campaign as a
        post("youtube:video:d", ["phone: 9123456789"])  # unrelated
        # two domains on one shared-hosting IP: a weak link only
        for d in ("zentrova-help.com", "zentrova-care.com"):
            record_detection(db, brand.id, PH, Detection(entity_key=d, title=d, signals=Signals(typo_similarity=90),
                                                         details={"A Records": ["198.51.100.7"]}))
        ids = {f.entity_key: str(f.id) for f in db.query(Finding).filter(Finding.brand_id == brand.id)}
        return str(brand.id), ids


def test_shared_contacts_form_one_campaign_and_shared_ip_does_not(client, analyst):  # noqa: F811
    brand_id, ids = _seed()
    camps = client.get(f"/api/v1/brands/{brand_id}/campaigns", headers=analyst).json()
    assert len(camps) == 1 and camps[0]["size"] == 3
    assert {f["entity_key"] for f in camps[0]["findings"]} == {"youtube:video:a", "youtube:video:b",
                                                               "youtube:video:c"}
    assert {s["kind"] for s in camps[0]["shared"]} == {"contact_phone", "contact_upi"}

    rel = client.get(f"/api/v1/findings/{ids['youtube:video:a']}/related", headers=analyst).json()
    assert [(r["entity_key"], r["kind"], r["strong"]) for r in rel] == [("youtube:video:b", "contact_phone", True)]
    weak = client.get(f"/api/v1/findings/{ids['zentrova-help.com']}/related", headers=analyst).json()
    assert [(r["entity_key"], r["strong"]) for r in weak] == [("zentrova-care.com", False)]
    assert client.get(f"/api/v1/findings/{ids['youtube:video:d']}/related", headers=analyst).json() == []


def test_link_raises_confidence_with_a_reason(client, analyst):  # noqa: F811
    _, ids = _seed()
    b = client.get(f"/api/v1/findings/{ids['youtube:video:b']}", headers=analyst).json()
    factors = {f["factor"]: f for f in b["signals"]["confidence"]["factors"]}
    assert "correlated" in factors and "1 other finding" in factors["correlated"]["why"]


def test_mail_server_links_only_through_a_lookalike_domain(client, analyst):  # noqa: F811
    """Two look-alikes using mail.zentrova-mail.com (itself a look-alike) are one operator; two parked domains
    on a parking company's mail server are not linked."""
    with session_scope() as db:
        brand = Brand(name="Zentrova Bank", keywords=["zentrova"], alert_min_level=RiskLevel.low)
        db.add(brand)
        db.flush()
        for key, mx in (("zentrova-mail.com", "10 mx.zentrova-mail.com"), ("zentrova-pay.com", "10 mail.zentrova-mail.com"),
                        ("zentrova-kyc.com", "10 mail.zentrova-mail.com"), ("zentrova1.com", "10 mx.parkco.com"),
                        ("zentrova2.com", "10 mx.parkco.com")):
            record_detection(db, brand.id, ModuleName.mx, Detection(entity_key=key, title=key,
                             signals=Signals(typo_similarity=90, mx_present=True), details={"MX Records": [mx]}))
        brand_id = str(brand.id)
    camps = client.get(f"/api/v1/brands/{brand_id}/campaigns", headers=analyst).json()
    assert [sorted(f["entity_key"] for f in c["findings"]) for c in camps] == [
        ["zentrova-kyc.com", "zentrova-mail.com", "zentrova-pay.com"]]
