"""D-46: threat intelligence for look-alike domains — corroboration, honest 'not checked', scoring effect."""

import pytest

from app.config import get_settings
from app.core.scoring import Signals, score
from app.db.models import ModuleName, RiskLevel
from app.modules.domains import reputation
from app.modules.domains.infra import DnsInfo
from app.modules.domains.module import DomainModule
from app.modules.email import intel
from app.modules.email.model import ToolVerdict
from tests.unit.test_domain_reporting import StubInfra, _components, _db, ctx

pytestmark = pytest.mark.req("D-46")

DOMAIN = "examplebank-secure.com"
DNS = {DOMAIN: DnsInfo(a=["203.0.113.5"], ns=["ns1.x"], mx=["10 mx.examplebank-secure.com"], status="resolved")}


class IntelInfra(StubInfra):
    def __init__(self, verdicts):
        super().__init__(DNS)
        self.verdicts = verdicts

    def reputation(self, domain):
        return self.verdicts


def _v(tool, malicious=False, status="ok"):
    return ToolVerdict(tool, status=status, malicious=malicious)


def test_openphish_matches_the_domain_and_its_subdomains_only(monkeypatch):
    monkeypatch.setattr(intel, "_openphish_set", lambda: {"https://login.examplebank-secure.com/x",
                                                         "https://notexamplebank-secure.com/"})
    v = reputation.openphish_domain(DOMAIN)
    assert v.malicious and v.details["urls"] == ["https://login.examplebank-secure.com/x"]
    monkeypatch.setattr(intel, "_openphish_set", lambda: set())
    assert reputation.openphish_domain(DOMAIN).status == "not_checked"  # feed down is not "clean"


def test_keyless_sources_are_not_checked(monkeypatch):
    monkeypatch.setattr(get_settings(), "urlscan_api_key", None)
    monkeypatch.setattr(get_settings(), "urlhaus_auth_key", None)
    assert reputation.urlscan_domain(DOMAIN).status == "not_checked"
    assert reputation.urlhaus_host(DOMAIN).status == "not_checked"


def test_summary_says_what_was_and_was_not_checked():
    assert reputation.summary([_v("openphish", True), _v("urlscan", status="not_checked")]) == \
        "Listed by OpenPhish (not checked: urlscan.io)"
    assert reputation.summary([_v("openphish"), _v("urlhaus")]) == "Not listed by OpenPhish, URLhaus"
    assert reputation.summary([_v("urlscan", status="not_checked")]) == "Not checked"


def test_two_independent_listings_lift_the_no_website_cap():
    two = DomainModule(infra=IntelInfra([_v("openphish", True), _v("urlscan", True), _v("urlhaus")]))
    (f,) = list(two.run(ctx(), _db()))
    result = score(f.signals, f.module)
    assert f.signals.known_malicious_url and "known_malicious_url" in result.fired
    assert result.cap is None and result.level == RiskLevel.critical
    assert f.details["Threat Intel"] == "Listed by OpenPhish, urlscan.io"
    assert any(e.meta.get("role") == "threat_intel" for e in f.evidence)
    assert _components(two)["Threat intel - OpenPhish"]["counts"] == {"checked": 1, "listed": 1}


def test_one_listing_adds_points_but_keeps_the_caps(monkeypatch):
    monkeypatch.setattr(get_settings(), "urlscan_api_key", None)
    one = DomainModule(infra=IntelInfra([_v("openphish", True), _v("urlscan", status="not_checked")]))
    (f,) = list(one.run(ctx(), _db()))
    result = score(f.signals, f.module)
    assert f.signals.single_source_url_hit and not f.signals.known_malicious_url
    assert result.cap == "no_website" and result.level == RiskLevel.high
    comps = _components(one)
    assert comps["Threat intel - urlscan.io"]["status"] == "not_configured"
    assert "URLSCAN_API_KEY" in comps["Threat intel - urlscan.io"]["message"]


def test_parked_page_stays_low_even_when_listed():
    s = Signals(brand_exact_in_domain=True, typo_similarity=95, known_malicious_url=True, page_live=True,
                parked_page=True)
    assert score(s, ModuleName.phishing).level == RiskLevel.low


def test_urlscan_reads_each_scan_verdict_on_free_plans(monkeypatch):
    """Free plans cannot search on verdicts: search the domain, then read each scan's own verdict."""
    import json as _json

    from app.core.fetch import FetchResult

    monkeypatch.setattr(get_settings(), "urlscan_api_key", "k")
    monkeypatch.setattr(intel, "_cache_get", lambda key: None)
    monkeypatch.setattr(intel, "_cache_set", lambda key, value, ttl: None)
    verdicts = {"s1": False, "s2": True}
    calls = []

    def fake_fetch(url, headers=None, **_):
        calls.append(url)
        if "/search/" in url:
            body = {"results": [{"_id": u, "page": {"url": f"https://{DOMAIN}/{u}"}, "task": {"time": "t"}}
                                for u in verdicts]}
        else:
            body = {"verdicts": {"overall": {"malicious": verdicts[url.rstrip("/").rsplit("/", 1)[-1]], "score": 9}}}
        return FetchResult(url=url, final_url=url, status=200, headers={}, content=_json.dumps(body).encode(),
                           peer_ip=None)

    monkeypatch.setattr(reputation, "fetch", fake_fetch)
    v = reputation.urlscan_domain(DOMAIN)
    assert v.status == "ok" and v.malicious and [s["uuid"] for s in v.details["scans"]] == ["s2"]
    assert "verdicts.malicious" not in calls[0]  # no plan-restricted field in the search
