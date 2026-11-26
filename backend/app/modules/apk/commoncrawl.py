"""Common Crawl as an extra APK source (D-42).

Common Crawl publishes a monthly, sampled crawl of the web with a URL index (CDX API) and the archived pages (WARC).
APK sites put the app name first in the URL (apkpure.com/<app-slug>/<package>), so a URL-prefix lookup per brand
slug finds archived listing pages — including on sites that are unreachable live from this network. The archived
HTML is read straight from Common Crawl (range request on the WARC file), never from the APK site.

The index is slow and rate-limited: lookups are paced, retried with back-off, capped by a time budget, and cached
in Redis for 30 days (a published crawl never changes).
"""

from __future__ import annotations

import gzip
import json
import re
import time
from dataclasses import dataclass
from urllib.parse import urlencode

import structlog

from app.config import get_settings
from app.core.fetch import try_fetch
from app.modules.base import BrandContext, ScanReport

log = structlog.get_logger(__name__)

COMPONENT = "Common Crawl index"
INDEX = "https://index.commoncrawl.org"
DATA = "https://data.commoncrawl.org/"
CACHE_TTL = 30 * 24 * 3600
# APK sites whose listing URLs start with the app's name: <host>/<slug>
SLUG_SITES = ["apkpure.com", "apkpure.net", "apkcombo.com", "m.apkpure.com", "apkfab.com", "apksupport.org"]


@dataclass
class ArchivedPage:
    url: str
    timestamp: str
    filename: str
    offset: int
    length: int
    collection: str


def _redis():
    try:
        import redis

        return redis.Redis.from_url(get_settings().redis_url, socket_timeout=2)
    except Exception:  # noqa: BLE001
        return None


def slugs(ctx: BrandContext) -> list[str]:
    """URL slugs an APK site would use for the brand ('Navi UPI' -> 'navi-upi', 'navi')."""
    out = []
    for t in ctx.terms[:4] + ctx.product_terms[:3]:
        s = re.sub(r"[^a-z0-9]+", "-", t.lower()).strip("-")
        if len(s) >= 4:
            out.append(s)
    # the shortest root covers the longer ones as a prefix ('navi' finds 'navi-upi-…')
    out = sorted(set(out), key=len)
    return [s for i, s in enumerate(out) if not any(s.startswith(o) for o in out[:i])][:4]


def collections(limit: int) -> list[str]:
    r = try_fetch(f"{INDEX}/collinfo.json")
    if not (r and r.status == 200):
        return []
    try:
        return [c["id"] for c in json.loads(r.content)][:limit]
    except (ValueError, KeyError):
        return []


def _query(collection: str, prefix: str, pace: float) -> list[dict] | None:
    """One CDX prefix lookup. None = could not be answered (rate-limited / down)."""
    key = f"cc:{collection}:{prefix}"
    cache = _redis()
    if cache is not None:
        try:
            hit = cache.get(key)
            if hit is not None:
                return json.loads(hit)
        except Exception:  # noqa: BLE001
            cache = None
    url = f"{INDEX}/{collection}-index?" + urlencode({
        "url": prefix, "matchType": "prefix", "output": "json", "limit": 300,
        "fl": "url,timestamp,status,mime,filename,offset,length", "filter": "status:200"})
    for attempt in range(3):
        time.sleep(pace * (attempt + 1))
        r = try_fetch(url)
        if r is not None and r.status == 404:  # no captures for this prefix in this crawl
            rows: list[dict] = []
            break
        if r is not None and r.status == 200:
            rows = [json.loads(x) for x in r.text.splitlines() if x.startswith("{")]
            break
    else:
        return None
    if cache is not None:
        try:
            cache.set(key, json.dumps(rows), ex=CACHE_TTL)
        except Exception:  # noqa: BLE001
            pass
    return rows


def find_pages(ctx: BrandContext, report: ScanReport) -> list[ArchivedPage]:
    s = get_settings()
    if not s.common_crawl_enabled:
        report.skipped(COMPONENT, "COMMON_CRAWL_ENABLED=false")
        return []
    cols = collections(s.common_crawl_collections)
    if not cols:
        report.unavailable(COMPONENT, "collection list could not be read")
        return []
    deadline = time.monotonic() + s.common_crawl_budget_seconds
    pages: dict[str, ArchivedPage] = {}
    asked = failed = 0
    for slug in slugs(ctx):
        for site in SLUG_SITES:
            for col in cols:
                if time.monotonic() > deadline:
                    report.ok(COMPONENT, f"time budget reached after {asked} lookups", lookups=asked)
                    return list(pages.values())
                asked += 1
                rows = _query(col, f"{site}/{slug}", s.common_crawl_pace_seconds)
                if rows is None:
                    failed += 1
                    continue
                for row in rows:
                    if "html" not in (row.get("mime") or "html"):
                        continue
                    page_url = row["url"].split("?")[0].split("#")[0]
                    if page_url not in pages or row["timestamp"] > pages[page_url].timestamp:
                        pages[page_url] = ArchivedPage(page_url, row["timestamp"], row["filename"],
                                                       int(row["offset"]), int(row["length"]), col)
    if failed and failed == asked:
        report.unavailable(COMPONENT, f"all {asked} lookups failed (index rate-limited or down)")
    else:
        if failed:
            report.failed(COMPONENT, f"{failed} of {asked} lookups failed (rate-limited)", failed=failed)
        report.ok(COMPONENT, lookups=asked, pages=len(pages))
    return list(pages.values())


def archived_html(page: ArchivedPage) -> str | None:
    """The archived page body, read from the WARC record (no request to the APK site itself)."""
    r = try_fetch(DATA + page.filename,
                  headers={"Range": f"bytes={page.offset}-{page.offset + page.length - 1}"},
                  max_bytes=page.length + 1024)
    if not (r and r.status in (200, 206) and r.content):
        return None
    try:
        record = gzip.decompress(r.content)
    except OSError:
        return None
    # WARC headers, blank line, HTTP headers, blank line, body
    parts = record.split(b"\r\n\r\n", 2)
    body = parts[2] if len(parts) == 3 else b""
    return body.decode("utf-8", "replace")
