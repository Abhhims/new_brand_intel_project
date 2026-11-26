import uuid
from pathlib import Path

import pytest

from app.modules.email import analysis
from app.modules.email.model import ToolVerdict
from app.modules.email.parser import parse

pytestmark = pytest.mark.req("EML-10", "EML-11")

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "emails"


def _ctx(**over):
    from app.modules.base import BrandContext

    base = dict(id=uuid.uuid4(), name="Zentrova Bank", keywords=["zentrova", "zentrova bank"],
                product_terms=[], official_domains=["zentrova.com"], official_packages=[],
                official_publishers=[], official_handles=[], email_domains=["zentrova.com"], logo_hashes=[],
                favicon_hashes=[], favicon_mmh3=[])
    base.update(over)
    return BrandContext(**base)


@pytest.fixture
def no_network(monkeypatch):
    """Neutralise every external call; each test sets the verdicts it wants."""
    monkeypatch.setattr(analysis.intel, "url_reputation", lambda url: [])
    monkeypatch.setattr(analysis.intel, "urlhaus_hash", lambda h: ToolVerdict("urlhaus", status="not_checked"))
    monkeypatch.setattr(analysis.intel, "abuseipdb_check", lambda ip: ToolVerdict("abuseipdb", status="not_checked"))
    monkeypatch.setattr(analysis.engines, "rspamd_check", lambda raw: ToolVerdict("rspamd", status="not_checked"))
    monkeypatch.setattr(analysis.engines, "clamav_scan", lambda d: ToolVerdict("clamav", status="not_checked"))
    monkeypatch.setattr(analysis.engines, "yara_scan", lambda d: ToolVerdict("yara", status="not_checked"))
    monkeypatch.setattr(analysis, "_domain_age_days", lambda d: None)
    monkeypatch.setattr(analysis, "_live_page_phishing", lambda urls, ctx: [])


def test_lookalike_phish_is_critical(no_network, monkeypatch):
    monkeypatch.setattr(analysis.intel, "url_reputation", lambda url: [
        ToolVerdict("urlhaus", status="ok", malicious=True), ToolVerdict("openphish", status="ok", malicious=True)])
    p = parse((FIX / "lookalike.eml").read_bytes())
    r = analysis.analyse(p, b"raw", _ctx())
    assert r.signals.known_malicious_url and r.signals.lookalike_sender and r.signals.reply_to_mismatch
    assert r.signals.credential_or_payment_language
    from app.core.scoring import score
    from app.db.models import ModuleName
    assert score(r.signals, ModuleName.email).level.value == "Critical"


def test_official_email_is_not_impersonation(no_network):
    p = parse((FIX / "official.eml").read_bytes())
    # Authentication header says dmarc=pass from zentrova.com → official sender
    r = analysis.analyse(p, b"raw", _ctx())
    assert r.signals.brand_impersonation is False
    assert r.signals.lookalike_sender is False
    assert r.signals.auth_fail_brand_from is False
    from app.core.scoring import score
    from app.db.models import ModuleName
    assert score(r.signals, ModuleName.email).score < 30


def test_single_source_is_not_known_malicious(no_network, monkeypatch):
    monkeypatch.setattr(analysis.intel, "url_reputation", lambda url: [
        ToolVerdict("urlhaus", status="ok", malicious=True),
        ToolVerdict("urlscan", status="not_checked")])
    p = parse((FIX / "lookalike.eml").read_bytes())
    r = analysis.analyse(p, b"raw", _ctx())
    assert r.signals.single_source_url_hit is True and r.signals.known_malicious_url is False
    assert any(n["tool"] == "urlscan" and n["status"] == "not_checked" for n in r.not_checked)


def test_malware_attachment_from_clamav(no_network, monkeypatch):
    monkeypatch.setattr(analysis.engines, "clamav_scan",
                        lambda d: ToolVerdict("clamav", status="ok", malicious=True, details={"signature": "Eicar"}))
    p = parse((FIX / "lookalike.eml").read_bytes())
    r = analysis.analyse(p, b"raw", _ctx())
    assert r.signals.malware_attachment is True


def test_auth_fail_from_brand_domain(no_network):
    raw = (b"From: <ceo@zentrova.com>\r\nTo: r@example.org\r\nSubject: hi\r\n"
           b"Authentication-Results: mx; spf=fail smtp.mailfrom=evil.test; dkim=fail; dmarc=fail header.from=zentrova.com\r\n"
           b"Message-ID: <x@y>\r\n\r\nbody\r\n")
    p = parse(raw)
    r = analysis.analyse(p, raw, _ctx())
    assert r.signals.auth_fail_brand_from is True
