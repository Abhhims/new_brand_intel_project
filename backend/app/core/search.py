"""Web search provider used for discovery of APK listings, social profiles and documents (D-10, D-12, D-23).

Order of preference:
  1. Brave Search API (BRAVE_SEARCH_API_KEY) — official API, most reliable
  2. SerpAPI (SERPAPI_API_KEY) — Google results through an official API
  3. Free fallback (FREE_SEARCH_FALLBACK=true, default): DuckDuckGo's public HTML results page, read like a
     browser through the safe fetcher. It honours site: and filetype: but throttles bursts, so free searches are
     paced (FREE_SEARCH_INTERVAL_SECONDS, shared by all workers via Redis) and retried after a pause. No key
     needed; use an API key for production volumes. (Bing's public page was tested and ignores site:/filetype:.)
"""

from __future__ import annotations

import html
import json
import re
import time
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import date
from urllib.parse import parse_qs, unquote, urlencode, urlsplit

import structlog

from app.config import get_settings
from app.core.fetch import FetchError, fetch

log = structlog.get_logger(__name__)


# Date range of the scan being run (D-50); every module's web searches honour it without passing it around
_DATE_RANGE: ContextVar[tuple[date | None, date | None]] = ContextVar("search_date_range", default=(None, None))


def set_date_range(date_from: date | None, date_to: date | None) -> None:
    _DATE_RANGE.set((date_from, date_to))


def date_range() -> tuple[date | None, date | None]:
    return _DATE_RANGE.get()


class SearchUnavailable(Exception):
    pass


class SearchNotConfigured(SearchUnavailable):
    """No search provider is configured at all (reported as 'not configured', not 'unavailable')."""


@dataclass
class SearchResult:
    title: str
    url: str
    snippet: str
    source: str = "search-engine"


def configured() -> bool:
    s = get_settings()
    return bool(s.brave_search_api_key or s.serpapi_api_key or s.free_search_fallback)


def provider_name() -> str:
    s = get_settings()
    if s.brave_search_api_key:
        return "Brave Search API"
    if s.serpapi_api_key:
        return "SerpAPI"
    return "DuckDuckGo (free, paced)" if s.free_search_fallback else "none"


def component_name() -> str:
    """Name of the web-search component on the Scans page, naming the provider that actually ran (D-31)."""
    return f"Web search - {provider_name()}"


class _Pacer:
    """At most one free search per interval across every worker (Redis lock), in-process fallback."""

    def __init__(self) -> None:
        self._last = 0.0

    def wait(self, interval: float) -> None:
        try:
            import redis

            r = redis.Redis.from_url(get_settings().redis_url, socket_timeout=2)
            deadline = time.time() + 600
            while not r.set("search:free:slot", "1", nx=True, px=int(interval * 1000)):
                if time.time() > deadline:
                    raise SearchUnavailable("timed out waiting for a free-search slot")
                time.sleep(0.5)
            return
        except SearchUnavailable:
            raise
        except Exception:  # noqa: BLE001 - Redis unavailable (tests, scripts): pace in-process
            pass
        delay = self._last + interval - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        self._last = time.monotonic()


_pacer = _Pacer()
_RESULT_RE = re.compile(r'class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>(.*?)(?=class="result__a"|$)', re.S)
_SNIPPET_RE = re.compile(r'class="result__snippet"[^>]*>(.*?)</a>', re.S)


def _strip_tags(text: str) -> str:
    return html.unescape(re.sub(r"<[^>]+>", "", text)).strip()


COOLDOWN_KEY = "search:free:cooldown"
COOLDOWN_SECONDS = 15 * 60


def _cooling_down() -> bool:
    try:
        import redis

        return bool(redis.Redis.from_url(get_settings().redis_url, socket_timeout=2).exists(COOLDOWN_KEY))
    except Exception:  # noqa: BLE001
        return False


def _start_cooldown() -> None:
    try:
        import redis

        redis.Redis.from_url(get_settings().redis_url, socket_timeout=2).set(COOLDOWN_KEY, "1", ex=COOLDOWN_SECONDS)
    except Exception:  # noqa: BLE001
        pass


def _duckduckgo(query: str, count: int) -> list[SearchResult]:
    """Best effort. DuckDuckGo blocks bursts of automated searches; we never try to get around that — after one
    refusal free search pauses for 15 minutes (shared by all workers) and the module records it."""
    s = get_settings()
    if _cooling_down():
        raise SearchUnavailable("Free search (DuckDuckGo) is paused after being rate-limited — add a search API "
                                "key (BRAVE_SEARCH_API_KEY) for reliable results")
    params = {"q": query}
    start, end = date_range()
    if start or end:
        params["df"] = f"{start or date(1995, 1, 1)}..{end or date.today()}"
    url = "https://html.duckduckgo.com/html/?" + urlencode(params)
    _pacer.wait(s.free_search_interval_seconds)
    r = fetch(url, headers={"Accept-Language": "en-US,en;q=0.9", "Accept": "text/html"})
    if r.status != 200 or "anomaly" in r.text[:30000].lower():
        _start_cooldown()
        log.info("free_search_rate_limited", status=r.status)
        raise SearchUnavailable("Free search (DuckDuckGo) rate-limited this server — add a search API key "
                                "(BRAVE_SEARCH_API_KEY) for reliable results")
    out: list[SearchResult] = []
    for href, title, rest in _RESULT_RE.findall(r.text):
        href = html.unescape(href)
        if "uddg=" in href:
            href = unquote(parse_qs(urlsplit(href).query).get("uddg", [""])[0])
        if not href.startswith("http") or "duckduckgo.com/" in href:
            continue
        snip = _SNIPPET_RE.search(rest)
        out.append(SearchResult(title=_strip_tags(title), url=href, snippet=_strip_tags(snip.group(1)) if snip else ""))
        if len(out) >= count:
            break
    return out


def _brave(query: str, count: int) -> list[SearchResult]:
    s = get_settings()
    params = {"q": query, "count": min(count, 20)}
    start, end = date_range()
    if start or end:
        params["freshness"] = f"{start or date(1995, 1, 1)}to{end or date.today()}"
    url = "https://api.search.brave.com/res/v1/web/search?" + urlencode(params)
    r = fetch(url, headers={"X-Subscription-Token": s.brave_search_api_key, "Accept": "application/json"})
    if r.status != 200:
        raise SearchUnavailable(f"Brave search HTTP {r.status}")
    data = json.loads(r.content or b"{}")
    return [SearchResult(title=i.get("title", ""), url=i.get("url", ""), snippet=i.get("description", ""))
            for i in data.get("web", {}).get("results", []) if i.get("url")]


def _serpapi(query: str, count: int) -> list[SearchResult]:
    s = get_settings()
    params = {"engine": "google", "q": query, "num": min(count, 100), "api_key": s.serpapi_api_key}
    start, end = date_range()
    if start or end:  # Google's custom date range
        params["tbs"] = "cdr:1" + (f",cd_min:{start:%m/%d/%Y}" if start else "") + (f",cd_max:{end:%m/%d/%Y}" if end else "")
    url = "https://serpapi.com/search.json?" + urlencode(params)
    r = fetch(url)
    if r.status != 200:
        raise SearchUnavailable(f"SerpAPI HTTP {r.status}")
    data = json.loads(r.content or b"{}")
    return [SearchResult(title=i.get("title", ""), url=i.get("link", ""), snippet=i.get("snippet", ""))
            for i in data.get("organic_results", []) if i.get("link")]


def search(query: str, count: int = 20) -> list[SearchResult]:
    """Run one web search. Raises SearchUnavailable when no provider is configured or it fails."""
    s = get_settings()
    try:
        if s.brave_search_api_key:
            return _brave(query, count)
        if s.serpapi_api_key:
            return _serpapi(query, count)
        if s.free_search_fallback:
            return _duckduckgo(query, count)
    except (FetchError, ValueError) as exc:
        raise SearchUnavailable(f"search failed: {exc}") from exc
    raise SearchNotConfigured("No search configured (set BRAVE_SEARCH_API_KEY or SERPAPI_API_KEY, "
                              "or FREE_SEARCH_FALLBACK=true)")
