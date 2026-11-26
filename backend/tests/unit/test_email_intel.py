import httpx
import pytest
import respx

from app.modules.email import intel

pytestmark = pytest.mark.req("EML-09")


@pytest.fixture(autouse=True)
def _keys(monkeypatch):
    s = intel.get_settings()
    monkeypatch.setattr(s, "urlhaus_auth_key", "k")
    monkeypatch.setattr(s, "urlscan_api_key", "k")
    monkeypatch.setattr(s, "abuseipdb_api_key", "k")
    monkeypatch.setattr(intel, "_cache_get", lambda key: None)
    monkeypatch.setattr(intel, "_cache_set", lambda key, val, ttl: None)
    monkeypatch.setattr(intel, "_openphish_set", lambda: {"https://bad.test/login"})


@respx.mock
def test_urlhaus_known_url():
    respx.post("https://urlhaus-api.abuse.ch/v1/url/").mock(return_value=httpx.Response(
        200, json={"query_status": "ok", "threat": "malware_download", "url_status": "online"}))
    v = intel.urlhaus_url("https://bad.test/x")
    assert v.malicious is True and v.tool == "urlhaus"


@respx.mock
def test_urlhaus_unknown_url():
    respx.post("https://urlhaus-api.abuse.ch/v1/url/").mock(return_value=httpx.Response(
        200, json={"query_status": "no_results"}))
    assert intel.urlhaus_url("https://good.test/x").malicious is False


def test_openphish_hit():
    assert intel.openphish_hit("https://bad.test/login").malicious is True
    assert intel.openphish_hit("https://good.test/x").malicious is False


@respx.mock
def test_urlscan_malicious_verdict():
    respx.get(url__regex=r"https://urlscan\.io/api/v1/search/.*").mock(return_value=httpx.Response(
        200, json={"results": [{"task": {"uuid": "abc"}, "verdicts": {"overall": {"malicious": True, "score": 80}}}]}))
    v = intel.urlscan_lookup("https://bad.test/x")
    assert v.malicious is True


@respx.mock
def test_abuseipdb_high_confidence():
    respx.get("https://api.abuseipdb.com/api/v2/check").mock(return_value=httpx.Response(
        200, json={"data": {"abuseConfidenceScore": 90, "totalReports": 12}}))
    v = intel.abuseipdb_check("45.33.22.11")
    assert v.malicious is True and v.score == 90


def test_no_key_is_not_checked(monkeypatch):
    monkeypatch.setattr(intel.get_settings(), "urlhaus_auth_key", None)
    assert intel.urlhaus_url("https://x.test/y").status == "not_checked"


@respx.mock
def test_quota_error_is_not_checked():
    respx.post("https://urlhaus-api.abuse.ch/v1/url/").mock(return_value=httpx.Response(429))
    assert intel.urlhaus_url("https://x.test/y").status in ("not_checked", "error")


def test_corroborated_counts_distinct_malicious_tools():
    from app.modules.email.model import ToolVerdict

    vs = [ToolVerdict("urlhaus", malicious=True), ToolVerdict("openphish", malicious=True),
          ToolVerdict("urlscan", malicious=False), ToolVerdict("urlhaus", malicious=True)]
    assert intel.corroborated(vs) == 2
