"""SP1 / D-31: the domain pipeline reports every component, and an unknown result is never recorded as 'no'."""

import uuid
from unittest.mock import MagicMock

import pytest

from app.core.fetch import FetchError
from app.modules.base import BrandContext, derive_run_status
from app.modules.domains.infra import DnsInfo
from app.modules.domains.module import DomainModule

pytestmark = pytest.mark.req("RDA-03", "RDA-17", "RDA-21")


def ctx() -> BrandContext:
    return BrandContext(id=uuid.uuid4(), name="Example Bank", keywords=["examplebank"], product_terms=[],
                        official_domains=["examplebank.com"], official_packages=[], official_publishers=[],
                        official_handles=[], email_domains=[], logo_hashes=[], favicon_hashes=[], favicon_mmh3=[])


class StubInfra:
    def __init__(self, dns: dict[str, DnsInfo], web: dict[str, list[str]] | None = None, ct_error=False, whois=None):
        self.dns, self.web, self.ct_error, self._whois = dns, web or {}, ct_error, whois or {}

    def resolve_many(self, domains):
        return {d: self.dns.get(d, DnsInfo(status="nxdomain")) for d in domains}

    def whois(self, domain):
        return self._whois.get(domain, {"registrar": "R"})

    def ct_search(self, term):
        if self.ct_error:
            raise FetchError("crt.sh HTTP 503")
        return []

    def web_urls(self, domain, info=None):
        return self.web.get(domain, [])

    def tls(self, domain):
        return {"present": True}

    def email_records(self, domain):
        return [], []


def _db(existing_alert=None) -> MagicMock:
    db = MagicMock()
    db.execute.return_value.all.return_value = []
    db.scalar.return_value = existing_alert
    return db


def _broken_capture(url, collect_images=False):
    raise RuntimeError("browser crashed")


def _components(mod) -> dict:
    return {c["name"]: c for c in mod.report.as_list()}


def test_dns_timeout_is_unresolved_not_unregistered():
    infra = StubInfra({"examp1ebank.com": DnsInfo(status="unknown")})
    mod = DomainModule(infra=infra)
    findings = list(mod.run(ctx(), _db()))
    assert findings == []  # not reported as unregistered, not reported at all
    dns = _components(mod)["DNS resolution"]
    assert dns["status"] == "failed" and dns["counts"]["unresolved"] == 1
    assert "not treated as unregistered" in dns["message"]
    assert derive_run_status(mod.report.as_list(), False).value == "completed_with_errors"


def test_capture_failure_on_new_domain_is_unknown_not_offline():
    infra = StubInfra({"examp1ebank.com": DnsInfo(a=["203.0.113.5"], ns=["ns1.x"], status="resolved")},
                      web={"examp1ebank.com": ["https://examp1ebank.com/"]})
    mod = DomainModule(infra=infra, capture_fn=_broken_capture)
    (f,) = list(mod.run(ctx(), _db(existing_alert=None)))
    assert f.details["Website Live"] == "unknown (capture failed)"
    assert f.module.value == "typosquat"
    cap = _components(mod)["Website probe & browser capture"]
    assert cap["status"] == "failed" and cap["counts"]["capture_failed"] == 1


def test_capture_failure_leaves_existing_alert_untouched():
    infra = StubInfra({"examp1ebank.com": DnsInfo(a=["203.0.113.5"], ns=["ns1.x"], status="resolved")},
                      web={"examp1ebank.com": ["https://examp1ebank.com/"]})
    mod = DomainModule(infra=infra, capture_fn=_broken_capture)
    assert list(mod.run(ctx(), _db(existing_alert=object()))) == []


def test_ct_failure_and_whois_error_are_reported():
    infra = StubInfra({"examp1ebank.com": DnsInfo(a=["203.0.113.5"], ns=["ns1.x"], status="resolved")},
                      ct_error=True, whois={"examp1ebank.com": {"error": "HTTPError: 429"}})
    mod = DomainModule(infra=infra)
    list(mod.run(ctx(), _db()))
    comps = _components(mod)
    assert comps["Certificate Transparency (crt.sh)"]["status"] == "failed"
    assert comps["WHOIS/RDAP"]["status"] == "failed" and comps["WHOIS/RDAP"]["counts"]["failed"] == 1
    assert comps["Variant generation"]["status"] == "ok"


def test_all_ok_components_complete():
    infra = StubInfra({"examp1ebank.com": DnsInfo(a=["203.0.113.5"], ns=["ns1.x"], status="resolved")})
    mod = DomainModule(infra=infra)
    list(mod.run(ctx(), _db()))
    assert derive_run_status(mod.report.as_list(), False).value == "completed"


def _timed_out_capture(url, collect_images=False):
    """The real browser.capture never raises on a navigation failure: it returns status=None with an error."""
    from app.core.browser import PageCapture

    return PageCapture(url=url, final_url=url, status=None, title="", text="", html="", screenshot=None,
                       error="Timeout 30000ms exceeded")


def test_page_timeout_is_unknown_not_offline():
    infra = StubInfra({"examp1ebank.com": DnsInfo(a=["203.0.113.5"], ns=["ns1.x"], status="resolved")},
                      web={"examp1ebank.com": ["https://examp1ebank.com/"]})
    mod = DomainModule(infra=infra, capture_fn=_timed_out_capture)
    (f,) = list(mod.run(ctx(), _db(existing_alert=None)))
    assert f.details["Website Live"] == "unknown (capture failed)"
    cap = _components(mod)["Website probe & browser capture"]
    assert cap["status"] == "failed" and "Timeout" in cap["message"]


def test_page_timeout_leaves_existing_alert_untouched():
    infra = StubInfra({"examp1ebank.com": DnsInfo(a=["203.0.113.5"], ns=["ns1.x"], status="resolved")},
                      web={"examp1ebank.com": ["https://examp1ebank.com/"]})
    mod = DomainModule(infra=infra, capture_fn=_timed_out_capture)
    assert list(mod.run(ctx(), _db(existing_alert=object()))) == []


class AllTimeoutInfra(StubInfra):
    def resolve_many(self, domains):
        return {d: DnsInfo(status="unknown") for d in domains}


def test_total_dns_outage_fails_the_run():
    mod = DomainModule(infra=AllTimeoutInfra({}))
    assert list(mod.run(ctx(), _db())) == []
    assert derive_run_status(mod.report.as_list(), False).value == "failed"


@pytest.mark.req("MX-03")
def test_null_mx_is_not_email_enabled(monkeypatch):
    from app.modules.domains.infra import LiveInfra
    li = LiveInfra()
    records = {"banknavi.com": ["0 "], "navi.com": ["0 mxa.pphosted.com", "10 mxb.pphosted.com"]}
    monkeypatch.setattr(li, "_records", lambda name, rtype: (records.get(name, []), True))
    assert li._mx("banknavi.com") == [] and li._mx("navi.com") == records["navi.com"]


@pytest.mark.req("RDA-03", "D-48")
def test_time_budget_defers_domains_honestly(monkeypatch):
    from app.config import get_settings

    dns = {d: DnsInfo(a=["203.0.113.5"], ns=["ns1.x"], status="resolved") for d in ("examp1ebank.com",
                                                                                     "exampiebank.com")}
    monkeypatch.setattr(get_settings(), "domain_scan_budget_seconds", 0)
    mod = DomainModule(infra=StubInfra(dns))
    assert list(mod.run(ctx(), _db())) == []
    comp = _components(mod)["Domain checks"]
    assert comp["status"] == "unavailable" and "2 of 2" in comp["message"] and "next scan" in comp["message"]
    assert derive_run_status(mod.report.as_list(), False).value == "partially_completed"
    assert mod.stats["domains_deferred"] == 2


@pytest.mark.req("D-48")
def test_never_checked_domains_go_first():
    from datetime import UTC, datetime

    db = _db()
    db.execute.return_value.all.return_value = [("a-old.com", datetime(2026, 1, 1, tzinfo=UTC)),
                                                 ("b-new.com", datetime(2026, 10, 1, tzinfo=UTC))]
    order = DomainModule().check_order(ctx(), db, ["b-new.com", "a-old.com", "z-never.com", "c-never.com"])
    assert order == ["c-never.com", "z-never.com", "a-old.com", "b-new.com"]


@pytest.mark.req("D-48")
def test_parallel_probes_keep_every_domain(monkeypatch):
    from app.config import get_settings

    names = [f"examp{i}ebank.com" for i in range(7)]
    dns = {d: DnsInfo(a=["203.0.113.5"], ns=["ns1.x"], mx=["10 mx.x"], status="resolved") for d in names}
    monkeypatch.setattr(get_settings(), "domain_check_workers", 3)
    infra = StubInfra(dns)
    infra.extra_domains = names  # not generated variants: inject them as discovered domains
    mod = DomainModule(infra=infra)
    assert sorted(f.entity_key for f in mod.run(ctx(), _db())) == sorted(names)
    assert _components(mod)["Domain checks"]["status"] == "ok" and mod.stats["domains_checked"] == 7
