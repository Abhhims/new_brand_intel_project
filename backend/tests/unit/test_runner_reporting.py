"""SP1 / D-31: every runner reports its components; a source that could not run is never 'nothing found'."""

import uuid
from unittest.mock import MagicMock

import pytest

from app.config import get_settings
from app.core import search
from app.modules.apk.module import ApkModule
from app.modules.base import BrandContext, derive_run_status
from app.modules.documents.module import DocumentsModule
from app.modules.logo.module import LogoModule
from app.modules.rogue_app.module import RogueAppModule
from app.modules.social.module import SocialModule

pytestmark = pytest.mark.req("RDA-03", "RDA-17", "RDA-21")


@pytest.fixture(autouse=True)
def _offline_apk_stores(monkeypatch):
    """Unit tests never reach the real APK stores; tests that need them patch these again."""
    from app.modules.apk import module as apk_module

    monkeypatch.setattr(apk_module, "aptoide_listings", lambda c, report: [])
    monkeypatch.setattr(apk_module, "apkmirror_candidates", lambda c, report: [])
    monkeypatch.setattr(apk_module.commoncrawl, "find_pages", lambda c, report: [])


def ctx() -> BrandContext:
    return BrandContext(id=uuid.uuid4(), name="Example Bank", keywords=["examplebank", "example bank"],
                        product_terms=[], official_domains=["examplebank.com"], official_packages=[],
                        official_publishers=[], official_handles=[], email_domains=[], logo_hashes=[],
                        favicon_hashes=[], favicon_mmh3=[])


def _status(mod) -> str:
    return derive_run_status(mod.report.as_list(), crashed=False).value


def _components(mod) -> dict:
    return {c["name"]: c for c in mod.report.as_list()}


@pytest.fixture
def search_down(monkeypatch):
    def down(query, count=20):
        raise search.SearchUnavailable("Free search (DuckDuckGo) rate-limited this server")
    monkeypatch.setattr(search, "search", down)


@pytest.fixture
def free_search(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "brave_search_api_key", "")
    monkeypatch.setattr(s, "serpapi_api_key", "")
    monkeypatch.setattr(s, "free_search_fallback", True)


def test_apk_scan_fails_when_every_search_is_unavailable(search_down, free_search, monkeypatch):
    from app.modules.apk import module as apk_module

    def stores_down(c, report):
        report.unavailable("Aptoide store search", "no response")
        return []

    monkeypatch.setattr(apk_module, "aptoide_listings", stores_down)
    monkeypatch.setattr(apk_module, "apkmirror_candidates", lambda c, report: [])
    mod = ApkModule()
    assert list(mod.run(ctx(), MagicMock())) == []
    comp = _components(mod)["Web search - DuckDuckGo (free, paced)"]
    assert comp["status"] == "unavailable"
    assert _components(mod)["APK sources"]["fatal"] is True
    assert _status(mod) == "failed"


def test_apk_store_search_keeps_scan_alive_when_web_search_is_down(search_down, free_search, monkeypatch):
    from app.modules.apk import module as apk_module

    def stores_ok(c, report):
        report.ok("Aptoide store search", queries=1)
        return []

    monkeypatch.setattr(apk_module, "aptoide_listings", stores_ok)
    monkeypatch.setattr(apk_module, "apkmirror_candidates", lambda c, report: [])
    mod = ApkModule()
    list(mod.run(ctx(), MagicMock()))
    assert "APK sources" not in _components(mod) and _status(mod) != "failed"


def test_apk_keeps_results_of_searches_that_worked(monkeypatch, free_search):
    calls = []

    def flaky(query, count=20):
        calls.append(query)
        if len(calls) == 2:
            raise search.SearchUnavailable("HTTP 503")
        return []
    monkeypatch.setattr(search, "search", flaky)
    mod = ApkModule()
    list(mod.run(ctx(), MagicMock()))
    assert len(calls) == 2  # both brand terms were tried; the failure did not stop the scan
    comp = _components(mod)["Web search - DuckDuckGo (free, paced)"]
    assert comp["status"] == "unavailable" and comp["fatal"] is False
    assert _status(mod) == "partially_completed"


def test_documents_scan_fails_when_every_search_is_unavailable(search_down, free_search):
    mod = DocumentsModule()
    assert list(mod.run(ctx(), MagicMock())) == []
    assert _status(mod) == "failed"


def test_social_without_telegram_credentials_is_not_configured(monkeypatch, search_down, free_search):
    s = get_settings()
    monkeypatch.setattr(s, "telegram_api_id", 0)
    monkeypatch.setattr(s, "telegram_api_hash", "")
    monkeypatch.setattr(s, "telegram_session", "")
    monkeypatch.setattr(s, "telegram_public_fallback", True)
    monkeypatch.setattr("app.modules.social.module._telegram_page", lambda name: None)
    mod = SocialModule()
    list(mod.run(ctx(), MagicMock()))
    comps = _components(mod)
    assert comps["Telegram API"]["status"] == "not_configured"
    assert comps["Telegram public pages"]["status"] == "ok"
    assert comps["Web search - DuckDuckGo (free, paced)"]["status"] == "unavailable"
    assert _status(mod) == "partially_completed"


def test_rogue_app_fails_when_every_store_search_fails(monkeypatch):
    def boom(*a, **kw):
        raise ConnectionError("network down")
    monkeypatch.setattr("google_play_scraper.search", boom)
    monkeypatch.setattr("app.modules.rogue_app.module.time.sleep", lambda s: None)

    class AppleDown:
        def search(self, c, report):
            report.unavailable("Apple App Store search", "no response")
            return []

    mod = RogueAppModule(apple_source=AppleDown())
    assert list(mod.run(ctx(), MagicMock())) == []
    comps = _components(mod)
    assert comps["Google Play search"]["status"] == "failed"
    assert comps["App store searches"]["fatal"] is True
    assert _status(mod) == "failed"


def test_logo_without_official_logo_is_not_configured_and_fails():
    mod = LogoModule(extra_targets=[])
    assert list(mod.run(ctx(), MagicMock())) == []
    comp = _components(mod)["Official logo assets"]
    assert comp["status"] == "not_configured"
    assert _status(mod) == "failed"


# ---------------------------------------------------------------- review fixes (D-31)
@pytest.fixture
def no_telegram(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "telegram_api_id", 0)
    monkeypatch.setattr(s, "telegram_api_hash", "")
    monkeypatch.setattr(s, "telegram_session", "")


def test_social_with_every_source_down_fails(monkeypatch, search_down, free_search, no_telegram):
    monkeypatch.setattr(get_settings(), "telegram_public_fallback", False)
    mod = SocialModule()
    assert list(mod.run(ctx(), MagicMock())) == []
    assert _status(mod) == "failed"


def test_blocked_telegram_pages_are_not_reported_as_not_found(monkeypatch, search_down, free_search, no_telegram):
    from app.core.fetch import FetchResult

    monkeypatch.setattr(get_settings(), "telegram_public_fallback", True)
    blocked = FetchResult(url="https://t.me/x", final_url="https://t.me/x", status=429, headers={}, content=b"",
                          peer_ip=None)
    monkeypatch.setattr("app.modules.social.module.try_fetch", lambda url, **kw: blocked)
    mod = SocialModule()
    list(mod.run(ctx(), MagicMock()))
    pages = _components(mod)["Telegram public pages"]
    assert pages["status"] != "ok" and pages["counts"]["failed"] > 0
    assert _status(mod) == "failed"  # Telegram blocked, search down: nothing was checked


def test_unconfigured_search_is_not_configured_not_unavailable(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "brave_search_api_key", "")
    monkeypatch.setattr(s, "serpapi_api_key", "")
    monkeypatch.setattr(s, "free_search_fallback", False)
    mod = DocumentsModule()
    list(mod.run(ctx(), MagicMock()))
    (comp,) = [c for c in mod.report.as_list() if c["name"].startswith("Web search")]
    assert comp["status"] == "not_configured"
    assert _status(mod) == "failed"


def test_logo_fails_when_no_target_page_could_be_captured():
    from app.core.imaging import ImageHashes

    def timed_out(url, collect_images=False):
        from app.core.browser import PageCapture

        return PageCapture(url=url, final_url=url, status=None, title="", text="", html="", screenshot=None,
                           error="Timeout")
    c = ctx()
    c.logo_hashes.append(ImageHashes("0" * 16, "0" * 16, "0" * 16))
    mod = LogoModule(capture_fn=timed_out, extra_targets=["https://a.example/", "https://b.example/"])
    db = MagicMock()
    db.scalars.return_value.all.return_value = []
    assert list(mod.run(c, db)) == []
    assert _status(mod) == "failed"


def test_txt_timeout_is_unknown_not_missing(monkeypatch):
    """A DNS timeout on SPF/DMARC must not become a 'missing SPF/DMARC' security-gap alert."""
    import dns.exception

    from app.modules.email import posture

    def timeout(*a, **kw):
        raise dns.exception.Timeout()
    monkeypatch.setattr("dns.resolver.Resolver.resolve", timeout)
    with pytest.raises(posture.DnsUnknown):
        posture._resolve_txt("examplebank.com")
    mod = posture.PostureModule()
    assert list(mod.run(ctx(), MagicMock())) == []
    comp = _components(mod)["DNS TXT lookups"]
    assert comp["status"] == "failed"


def test_txt_nxdomain_is_a_definitive_empty_answer(monkeypatch):
    import dns.resolver

    from app.modules.email import posture

    def nx(*a, **kw):
        raise dns.resolver.NXDOMAIN()
    monkeypatch.setattr("dns.resolver.Resolver.resolve", nx)
    assert posture._resolve_txt("nothing.examplebank.com") == []
