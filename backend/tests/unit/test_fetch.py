import httpx
import pytest
import respx

from app.core import fetch as f

pytestmark = pytest.mark.req("FND-12", "FND-13")


@pytest.fixture(autouse=True)
def public_dns(monkeypatch):
    """Pretend every test host resolves to a public IP unless a test overrides it."""
    table = {"evil.test": ["10.0.0.5"], "meta.test": ["169.254.169.254"], "loop.test": ["127.0.0.1"]}
    monkeypatch.setattr(f, "resolve_host", lambda host: table.get(host, ["93.184.216.34"]))
    monkeypatch.setattr(f._limiter, "wait", lambda host: None)


@pytest.mark.parametrize("url", ["http://evil.test/", "http://meta.test/latest/meta-data",
                                 "http://loop.test/", "http://127.0.0.1/", "http://[::1]/"])
def test_blocks_internal_destinations(url, monkeypatch):
    if "://1" in url or "[" in url:
        monkeypatch.setattr(f, "resolve_host", lambda host: [host.strip("[]")])
    with pytest.raises(f.BlockedDestination):
        f.fetch(url)


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://example.com/x", "gopher://x"])
def test_blocks_non_http_schemes(url):
    with pytest.raises(f.BlockedDestination):
        f.check_destination(url)


@respx.mock
def test_redirect_to_internal_host_is_blocked():
    respx.get("http://public.test/").mock(return_value=httpx.Response(302, headers={"location": "http://evil.test/"}))
    with pytest.raises(f.BlockedDestination):
        f.fetch("http://public.test/")


@respx.mock
def test_follows_public_redirects():
    respx.get("http://a.test/").mock(return_value=httpx.Response(301, headers={"location": "https://b.test/x"}))
    respx.get("https://b.test/x").mock(return_value=httpx.Response(200, text="hello"))
    r = f.fetch("http://a.test/")
    assert (r.status, r.final_url, r.text, r.redirects) == (200, "https://b.test/x", "hello", ["https://b.test/x"])


@respx.mock
def test_size_cap():
    respx.get("http://big.test/").mock(return_value=httpx.Response(200, content=b"x" * 2000))
    with pytest.raises(f.TooLarge):
        f.fetch("http://big.test/", max_bytes=1000)


@respx.mock
def test_retries_server_errors_then_succeeds():
    route = respx.get("http://flaky.test/").mock(
        side_effect=[httpx.Response(503), httpx.Response(200, text="ok")]
    )
    assert f.fetch("http://flaky.test/").text == "ok"
    assert route.call_count == 2


@respx.mock
def test_gives_up_after_retries():
    respx.get("http://down.test/").mock(return_value=httpx.Response(500))
    with pytest.raises(f.FetchError):
        f.fetch("http://down.test/")


def test_allowlisted_private_host(monkeypatch):
    monkeypatch.setattr(f.get_settings(), "fetch_allow_private_hosts", ["evil.test"])
    assert f.check_destination("http://evil.test/") == "evil.test"


@pytest.mark.parametrize(("ip", "forbidden"), [
    ("64:ff9b::14cc:f4c0", False),   # NAT64 of 20.204.244.192 (public) — e.g. DuckDuckGo on this network
    ("64:ff9b::a00:5", True),        # NAT64 of 10.0.0.5 (private)
    ("64:ff9b::7f00:1", True),       # NAT64 of 127.0.0.1
    ("64:ff9b::a9fe:a9fe", True),    # NAT64 of 169.254.169.254 (cloud metadata)
])
def test_nat64_addresses_judged_by_embedded_ipv4(ip, forbidden):
    import ipaddress

    assert f._is_forbidden_ip(ipaddress.ip_address(ip)) is forbidden
