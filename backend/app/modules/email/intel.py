"""Threat-intelligence adapters: URLhaus, OpenPhish, urlscan.io, AbuseIPDB.

Each returns a ToolVerdict and is cached in Redis (24 h; the OpenPhish feed 6 h). No API key → `not_checked`.
A URL is only treated as "known malicious" when `corroborated()` counts >= 2 independent malicious verdicts
(spec §4): no single source can push an email to Critical on its own.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

import structlog

from app.config import get_settings
from app.core.fetch import FetchError, fetch
from app.modules.email.model import ToolVerdict

log = structlog.get_logger(__name__)

CACHE_TTL = 24 * 3600
FEED_TTL = 6 * 3600


def _now() -> datetime:
    return datetime.now(UTC)


def _redis():
    try:
        import redis

        client = redis.Redis.from_url(get_settings().redis_url, socket_timeout=1)
        client.ping()
        return client
    except Exception:  # noqa: BLE001
        return None


def _cache_get(key: str):
    r = _redis()
    if r is None:
        return None
    try:
        raw = r.get(key)
        return json.loads(raw) if raw else None
    except Exception:  # noqa: BLE001
        return None


def _cache_set(key: str, value: dict, ttl: int) -> None:
    r = _redis()
    if r is None:
        return
    try:
        r.set(key, json.dumps(value), ex=ttl)
    except Exception:  # noqa: BLE001
        pass


def _cached(tool: str, ident: str, fn) -> ToolVerdict:
    key = f"intel:{tool}:{hashlib.sha256(ident.encode()).hexdigest()[:24]}"
    hit = _cache_get(key)
    if hit is not None:
        return ToolVerdict(tool=tool, status=hit["status"], malicious=hit["malicious"], score=hit.get("score"),
                           details=hit.get("details", {}), checked_at=_now())
    verdict = fn()
    if verdict.status == "ok":
        _cache_set(key, {"status": "ok", "malicious": verdict.malicious, "score": verdict.score,
                         "details": verdict.details}, CACHE_TTL)
    return verdict


def urlhaus_url(url: str) -> ToolVerdict:
    s = get_settings()
    if not s.urlhaus_auth_key:
        return ToolVerdict("urlhaus", status="not_checked", checked_at=_now())

    return _cached("urlhaus", url, lambda: _urlhaus_post("url", url, s.urlhaus_auth_key))


def _urlhaus_post(field: str, value: str, key: str) -> ToolVerdict:
    import httpx

    endpoint = "https://urlhaus-api.abuse.ch/v1/url/" if field == "url" else "https://urlhaus-api.abuse.ch/v1/payload/"
    try:
        with httpx.Client(timeout=15.0) as client:
            resp = client.post(endpoint, data={field if field == "url" else "sha256_hash": value},
                               headers={"Auth-Key": key})
        if resp.status_code != 200:
            return ToolVerdict("urlhaus", status="not_checked", details={"http": resp.status_code}, checked_at=_now())
        data = resp.json()
    except Exception as exc:  # noqa: BLE001
        return ToolVerdict("urlhaus", status="not_checked", details={"reason": str(exc)[:120]}, checked_at=_now())
    malicious = data.get("query_status") == "ok"
    return ToolVerdict("urlhaus", status="ok", malicious=malicious,
                       details={k: data.get(k) for k in ("threat", "url_status", "file_type") if data.get(k)},
                       checked_at=_now())


def urlhaus_hash(sha256: str) -> ToolVerdict:
    s = get_settings()
    if not s.urlhaus_auth_key:
        return ToolVerdict("urlhaus", status="not_checked", checked_at=_now())
    return _cached("urlhaus_hash", sha256, lambda: _urlhaus_post("hash", sha256, s.urlhaus_auth_key))


def _openphish_set() -> set[str]:
    key = "intel:openphish:feed"
    cached = _cache_get(key)
    if cached is not None:
        return set(cached)
    try:
        r = fetch(get_settings().openphish_feed_url, max_bytes=10 * 1024 * 1024)
        urls = {line.strip() for line in r.text.splitlines() if line.strip().startswith("http")}
    except FetchError:
        return set()
    _cache_set(key, list(urls), FEED_TTL)
    return urls


def openphish_hit(url: str) -> ToolVerdict:
    feed = _openphish_set()
    if not feed:
        return ToolVerdict("openphish", status="not_checked", checked_at=_now())
    hit = url in feed or url.rstrip("/") in feed
    return ToolVerdict("openphish", status="ok", malicious=hit, checked_at=_now())


def urlscan_lookup(url: str) -> ToolVerdict:
    s = get_settings()
    if not s.urlscan_api_key:
        return ToolVerdict("urlscan", status="not_checked", checked_at=_now())

    def call() -> ToolVerdict:
        from urllib.parse import quote

        q = quote(f'page.url:"{url}"')
        try:
            r = fetch(f"https://urlscan.io/api/v1/search/?q={q}&size=1",
                      headers={"API-Key": s.urlscan_api_key})
        except FetchError as exc:
            return ToolVerdict("urlscan", status="not_checked", details={"reason": str(exc)[:120]}, checked_at=_now())
        if r.status != 200:
            return ToolVerdict("urlscan", status="not_checked", details={"http": r.status}, checked_at=_now())
        results = json.loads(r.content or b"{}").get("results", [])
        if not results:
            return ToolVerdict("urlscan", status="ok", malicious=False, checked_at=_now())
        verdict = results[0].get("verdicts", {}).get("overall", {})
        return ToolVerdict("urlscan", status="ok", malicious=bool(verdict.get("malicious")),
                           score=verdict.get("score"),
                           details={"uuid": results[0].get("task", {}).get("uuid")}, checked_at=_now())

    return _cached("urlscan", url, call)


def abuseipdb_check(ip: str) -> ToolVerdict:
    s = get_settings()
    if not s.abuseipdb_api_key:
        return ToolVerdict("abuseipdb", status="not_checked", checked_at=_now())

    def call() -> ToolVerdict:
        try:
            r = fetch(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
                      headers={"Key": s.abuseipdb_api_key, "Accept": "application/json"})
        except FetchError as exc:
            return ToolVerdict("abuseipdb", status="not_checked", details={"reason": str(exc)[:120]}, checked_at=_now())
        if r.status != 200:
            return ToolVerdict("abuseipdb", status="not_checked", details={"http": r.status}, checked_at=_now())
        data = json.loads(r.content or b"{}").get("data", {})
        confidence = data.get("abuseConfidenceScore", 0)
        return ToolVerdict("abuseipdb", status="ok", malicious=confidence >= 75, score=confidence,
                           details={"total_reports": data.get("totalReports")}, checked_at=_now())

    return _cached("abuseipdb", ip, call)


def url_reputation(url: str) -> list[ToolVerdict]:
    return [urlhaus_url(url), openphish_hit(url), urlscan_lookup(url)]


def corroborated(verdicts: list[ToolVerdict]) -> int:
    """Number of *distinct* tools that returned a malicious verdict."""
    return len({v.tool for v in verdicts if v.malicious})
