"""Helpers shared by the app, social and document modules."""

from __future__ import annotations

import re
import time
from urllib.parse import urlsplit

from app.core import search
from app.core.fetch import try_fetch
from app.core.imaging import ImageHashes, best_match, hashes_for

MAX_ICON_BYTES = 2 * 1024 * 1024

# Image hosts that keep failing (e.g. a CDN unreachable from this network) are skipped for a while, so hundreds of
# thumbnails don't each wait ~30 s on retries and push a scan past its time limit.
_HOST_FAILS: dict[str, tuple[int, float]] = {}
_FAILS_BEFORE_SKIP = 3
_SKIP_SECONDS = 15 * 60


def _host_skipped(host: str) -> bool:
    fails, since = _HOST_FAILS.get(host, (0, 0.0))
    if fails < _FAILS_BEFORE_SKIP:
        return False
    if time.monotonic() - since > _SKIP_SECONDS:
        _HOST_FAILS.pop(host, None)  # try again
        return False
    return True


def image_match(url: str | None, officials: list[ImageHashes]) -> tuple[float, bytes | None, str | None]:
    """Fetch an image (safely) and compare it with the brand's official images. → (score, bytes, content_type)"""
    if not url or not officials:
        return 0.0, None, None
    host = (urlsplit(url).hostname or "").lower()
    if _host_skipped(host):
        return 0.0, None, None
    r = try_fetch(url, max_bytes=MAX_ICON_BYTES)
    if r is None:
        _HOST_FAILS[host] = (_HOST_FAILS.get(host, (0, 0.0))[0] + 1, time.monotonic())
        return 0.0, None, None
    _HOST_FAILS.pop(host, None)
    if r.status != 200 or not r.content:
        return 0.0, None, None
    h = hashes_for(r.content)
    if h is None:
        return 0.0, r.content, r.content_type
    return best_match(h, officials), r.content, r.content_type or "image/png"


def literal_brand_in(identifier: str, terms: list[str]) -> bool:
    """Exact brand name inside an identifier (domain label, handle, package) — D-20."""
    flat = re.sub(r"[^a-z0-9]", "", identifier.lower())
    return any(re.sub(r"[^a-z0-9]", "", t.lower()) in flat for t in terms if t.strip())


def og_image(html: str) -> str | None:
    m = re.search(r'<meta[^>]+property=["\']og:image["\'][^>]+content=["\']([^"\']+)', html, re.I) or re.search(
        r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+property=["\']og:image', html, re.I)
    return m.group(1) if m else None


def html_title(html: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    return re.sub(r"\s+", " ", m.group(1)).strip() if m else ""


def report_search_failure(report, component: str, exc: Exception, fatal: bool = False) -> None:
    """A search that could not run: 'not configured' when no provider is set up, otherwise 'unavailable' (D-31)."""
    if isinstance(exc, search.SearchNotConfigured):
        report.not_configured(component, str(exc), fatal=fatal)
    else:
        report.unavailable(component, str(exc), fatal=fatal)
