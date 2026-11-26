"""Safe fetcher — the ONLY way platform code reaches external URLs (decision D-18, skill: safe-fetcher).

Guarantees:
  * http/https only, timeouts on every request
  * retries with backoff (tenacity) on transport errors and 5xx/429
  * per-host rate limit (Redis token bucket; in-process fallback)
  * blocks private / loopback / link-local / reserved / metadata addresses — before connecting,
    on every redirect hop, and again on the actual connected peer address (DNS-rebinding guard)
  * response size cap (streamed; aborts once exceeded)
  * returns bytes in memory; persisting is done only by app.core.evidence into the evidence bucket
"""

from __future__ import annotations

import hashlib
import ipaddress
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import urljoin, urlsplit

import httpx
import structlog
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from app.config import get_settings

log = structlog.get_logger(__name__)

METADATA_IPS = {ipaddress.ip_address("169.254.169.254"), ipaddress.ip_address("fd00:ec2::254"),
                ipaddress.ip_address("100.100.100.200")}


class FetchError(Exception):
    """Fetch failed in a way the caller should record (not retried further)."""


class BlockedDestination(FetchError):
    """Destination is not allowed (internal address, bad scheme)."""


class TooLarge(FetchError):
    pass


class _Retryable(Exception):
    pass


@dataclass
class FetchResult:
    url: str
    final_url: str
    status: int
    headers: dict[str, str]
    content: bytes
    peer_ip: str | None
    redirects: list[str] = field(default_factory=list)
    elapsed_ms: int = 0

    @property
    def text(self) -> str:
        charset = "utf-8"
        ctype = self.headers.get("content-type", "")
        if "charset=" in ctype:
            charset = ctype.split("charset=")[-1].split(";")[0].strip() or "utf-8"
        return self.content.decode(charset, errors="replace")

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "").split(";")[0].strip().lower()


# --------------------------------------------------------------------------- destination checks

NAT64_PREFIX = ipaddress.ip_network("64:ff9b::/96")  # RFC 6052 well-known prefix (IPv6-only networks)


def _is_forbidden_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if ip in METADATA_IPS:
        return True
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if isinstance(ip, ipaddress.IPv6Address) and ip in NAT64_PREFIX:
        # NAT64/DNS64 networks present public IPv4 hosts as 64:ff9b::a.b.c.d — judge the embedded IPv4
        ip = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        if ip in METADATA_IPS:
            return True
    return (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
            or ip.is_multicast or ip.is_unspecified or not ip.is_global)


def _host_allowed_private(host: str) -> bool:
    return host.lower() in {h.lower() for h in get_settings().fetch_allow_private_hosts}


def resolve_host(host: str) -> list[str]:
    # Container resolvers occasionally fail under load; retry briefly before treating the name as unresolvable
    for attempt in range(3):
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
            return sorted({info[4][0] for info in infos})
        except socket.gaierror as exc:
            if attempt == 2 or exc.errno == socket.EAI_NONAME and attempt == 1:
                raise FetchError(f"DNS resolution failed for {host}: {exc}") from exc
            time.sleep(1.5 * (attempt + 1))
    raise FetchError(f"DNS resolution failed for {host}")


def check_destination(url: str) -> str:
    """Validate scheme + every resolved IP. Returns the host. Raises BlockedDestination."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise BlockedDestination(f"scheme not allowed: {parts.scheme!r}")
    host = parts.hostname
    if not host:
        raise BlockedDestination("URL has no host")
    if _host_allowed_private(host):
        return host
    for raw in resolve_host(host):
        if _is_forbidden_ip(ipaddress.ip_address(raw.split("%")[0])):
            raise BlockedDestination(f"{host} resolves to a non-public address ({raw})")
    return host


def _check_peer(host: str, peer_ip: str | None) -> None:
    if peer_ip is None or _host_allowed_private(host):
        return
    if _is_forbidden_ip(ipaddress.ip_address(peer_ip.split("%")[0])):
        raise BlockedDestination(f"{host} connected to a non-public address ({peer_ip})")


# --------------------------------------------------------------------------- rate limiting

class _RateLimiter:
    """Token bucket per host. Uses Redis when reachable so all workers share the budget."""

    def __init__(self) -> None:
        self._local: dict[str, list[float]] = {}
        self._lock = threading.Lock()
        self._redis = None
        self._redis_checked = False

    def _get_redis(self):
        if not self._redis_checked:
            self._redis_checked = True
            try:
                import redis

                client = redis.Redis.from_url(get_settings().redis_url, socket_timeout=1)
                client.ping()
                self._redis = client
            except Exception:  # noqa: BLE001 - fall back to in-process limiting
                self._redis = None
        return self._redis

    def wait(self, host: str) -> None:
        per_minute = max(1, get_settings().fetch_rate_per_host_per_minute)
        r = self._get_redis()
        while True:
            now = time.time()
            if r is not None:
                key = f"ratelimit:{host}:{int(now // 60)}"
                try:
                    count = r.incr(key)
                    if count == 1:
                        r.expire(key, 61)
                    if count <= per_minute:
                        return
                    time.sleep(60 - now % 60 + 0.05)
                    continue
                except Exception:  # noqa: BLE001
                    r = None
            with self._lock:
                window = [t for t in self._local.get(host, []) if now - t < 60]
                if len(window) < per_minute:
                    window.append(now)
                    self._local[host] = window
                    return
                sleep_for = 60 - (now - window[0]) + 0.05
            time.sleep(sleep_for)


_limiter = _RateLimiter()


# --------------------------------------------------------------------------- fetching

def _client(timeout: float | None = None) -> httpx.Client:
    s = get_settings()
    timeout = timeout or s.fetch_timeout_seconds
    return httpx.Client(
        timeout=httpx.Timeout(timeout, connect=min(10.0, timeout)),
        follow_redirects=False,
        headers={"User-Agent": s.fetch_user_agent, "Accept": "*/*"},
        verify=False,  # suspicious sites often have broken TLS; we record TLS facts separately
    )


@retry(
    retry=retry_if_exception_type(_Retryable),
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=0.5, max=8),
    reraise=True,
)
def _one_hop(client: httpx.Client, method: str, url: str, max_bytes: int,
             headers: dict[str, str] | None = None,
             content: bytes | None = None) -> tuple[httpx.Response, bytes, str | None]:
    host = check_destination(url)
    _limiter.wait(host)
    try:
        with client.stream(method, url, headers=headers, content=content) as resp:
            stream = resp.extensions.get("network_stream")
            peer = None
            if stream is not None:
                addr = stream.get_extra_info("server_addr")
                peer = addr[0] if addr else None
            _check_peer(host, peer)
            declared = resp.headers.get("content-length")
            if declared and declared.isdigit() and int(declared) > max_bytes:
                raise TooLarge(f"{url}: content-length {declared} exceeds {max_bytes}")
            body = bytearray()
            for chunk in resp.iter_bytes():
                body.extend(chunk)
                if len(body) > max_bytes:
                    raise TooLarge(f"{url}: body exceeds {max_bytes} bytes")
            # a 5xx on a POST may already have been acted on (e.g. a paid scraper run started): not retried
            if resp.status_code == 429 or (resp.status_code >= 500 and method in ("GET", "HEAD")):
                raise _Retryable(f"{url}: HTTP {resp.status_code}")
            return resp, bytes(body), peer
    except httpx.TransportError as exc:
        raise _Retryable(f"{url}: {type(exc).__name__}: {exc}") from exc


def fetch(url: str, *, method: str = "GET", max_bytes: int | None = None,
          headers: dict[str, str] | None = None, content: bytes | None = None,
          timeout: float | None = None) -> FetchResult:
    """Fetch `url` safely, following redirects manually with re-validation on every hop.
    `content` is a request body (e.g. JSON for an API POST); it is sent to the requested URL only."""
    s = get_settings()
    limit = max_bytes or s.fetch_max_bytes
    started = time.monotonic()
    redirects: list[str] = []
    current = url
    with _client(timeout) as client:
        for _ in range(s.fetch_max_redirects + 1):
            try:
                # custom headers (e.g. API keys) never follow a redirect to another host
                same_host = urlsplit(current).hostname == urlsplit(url).hostname
                resp, body, peer = _one_hop(client, method, current, limit, headers if same_host else None,
                                            content if current == url else None)
            except _Retryable as exc:
                raise FetchError(str(exc)) from exc
            if resp.is_redirect and "location" in resp.headers:
                nxt = urljoin(current, resp.headers["location"])
                redirects.append(nxt)
                current = nxt
                continue
            return FetchResult(
                url=url, final_url=current, status=resp.status_code,
                headers={k.lower(): v for k, v in resp.headers.items()}, content=body, peer_ip=peer,
                redirects=redirects, elapsed_ms=int((time.monotonic() - started) * 1000),
            )
    raise FetchError(f"{url}: too many redirects")


def try_fetch(url: str, **kwargs) -> FetchResult | None:
    try:
        return fetch(url, **kwargs)
    except FetchError as exc:
        log.info("fetch_failed", url=url, error=str(exc))
        return None


def port_open(host: str, port: int, timeout: float = 5.0) -> bool:
    """Quick reachability check (same destination rules) before spending a browser session on a host."""
    try:
        check_destination(f"http://{host}:{port}/")
        with socket.create_connection((host, port), timeout=timeout) as sock:
            _check_peer(host, sock.getpeername()[0])
        return True
    except (OSError, FetchError):
        return False


# --------------------------------------------------------------------------- TLS certificate facts

def fetch_certificate(host: str, port: int = 443) -> dict:
    """Connect (with the same destination checks) and describe the server certificate (PHI-05)."""
    check_destination(f"https://{host}:{port}/")
    _limiter.wait(host)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    timeout = get_settings().fetch_timeout_seconds
    with socket.create_connection((host, port), timeout=timeout) as sock:
        _check_peer(host, sock.getpeername()[0])
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
            protocol = tls.version()
    cert = x509.load_der_x509_certificate(der)

    def _name(n: x509.Name, oid) -> str | None:
        vals = n.get_attributes_for_oid(oid)
        return vals[0].value if vals else None

    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        sans = san.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    not_after = cert.not_valid_after_utc
    return {
        "present": True,
        "subject_cn": _name(cert.subject, NameOID.COMMON_NAME),
        "issuer_cn": _name(cert.issuer, NameOID.COMMON_NAME),
        "issuer_org": _name(cert.issuer, NameOID.ORGANIZATION_NAME),
        "san": sans[:50],
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": not_after.isoformat(),
        "expired": not_after < datetime.now(UTC),
        "self_signed": cert.issuer == cert.subject,
        "serial": format(cert.serial_number, "x"),
        "sha256": hashlib.sha256(der).hexdigest(),  # certificate fingerprint (correlation, D-49)
        "protocol": protocol,
    }
