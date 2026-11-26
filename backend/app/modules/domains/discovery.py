"""Extra discovery sources for look-alike domains and brand-named websites (D-51).

Typosquat generation only finds names we can guess. These sources find names attackers actually used:

* Certificate Transparency hits are kept as the *site* (hosting platforms included) instead of being cut down to
  the registered domain — 'axisofficial.web.app' used to become 'web.app' and was thrown away.
* Brand-in-subdomain hosts on unrelated domains ('uat-axis-apple-pay.rewardkartshop.in').
* urlscan.io: hostnames containing the brand and pages titled with the brand, from public scans (URLSCAN_API_KEY).
* Phishing feeds (free, no key): PhishTank, OpenPhish, Phishing.Database, Phishing Army, Phishunt.
* Common Crawl: hostnames on free hosting platforms archived by the monthly web crawl (D-52).
* CertStream: brand-named hosts seen in newly issued certificates, collected live by the certwatch service (D-52).
* Web search dorks: brand pages on free hosting platforms (vercel.app, web.app, netlify.app...) and brand-titled
  login pages outside the official domains.

Every host still goes through the normal pipeline (DNS, WHOIS, capture, page analysis, scoring), so a name match
alone never makes a High alert: the page itself must show the brand (D-29).
"""

from __future__ import annotations

import json
import re
import threading
import time
from collections.abc import Callable
from urllib.parse import quote, urlsplit

import structlog

from app.config import get_settings
from app.core import search
from app.core.fetch import FetchError, fetch
from app.core.similarity import best_similarity, domain_label, host_labels, hosting_platform, registered_domain, site_domain
from app.modules.base import BrandContext, ScanReport

log = structlog.get_logger(__name__)

MIN_LOOKALIKE_SIMILARITY = 70
STRONG_LABEL_LEN = 6

URLSCAN = "urlscan.io search"
FEEDS = "Phishing feeds (PhishTank, OpenPhish, Phishing.Database, Phishing Army, Phishunt)"
COMMON_CRAWL = "Common Crawl hostnames"
CERTSTREAM = "CertStream (new certificates)"
# Hosting platforms whose sites are looked up in the Common Crawl index (one wildcard query each)
CC_PLATFORMS = ["vercel.app", "web.app", "firebaseapp.com", "netlify.app", "pages.dev", "github.io", "onrender.com",
                "herokuapp.com", "glitch.me", "webflow.io"]
DORKS = "Hosting-platform & login-page search"

# Words that, next to a short brand word ('axis'), make a hostname about the brand rather than a namesake
RISK_WORDS = ["bank", "banking", "netbanking", "login", "signin", "secure", "verify", "verification", "account",
              "support", "help", "helpline", "care", "customer", "online", "pay", "payment", "upi", "wallet", "card",
              "cards", "credit", "debit", "loan", "loans", "emi", "kyc", "update", "auth", "otp", "portal", "service",
              "reward", "rewards", "points", "offer", "offers", "cashback", "refund", "bonus", "official", "mobile",
              "invest", "finance", "insurance", "atm", "branch", "apply", "onboarding", "chatbot", "assist"]

# Free hosting platforms phishing kits are deployed to (searched with site: dorks)
HOSTING_PLATFORMS = ["vercel.app", "web.app", "firebaseapp.com", "netlify.app", "github.io", "pages.dev",
                     "herokuapp.com", "onrender.com", "glitch.me", "replit.app", "repl.co", "webflow.io",
                     "framer.website", "wixsite.com", "weebly.com", "blogspot.com", "000webhostapp.com",
                     "azurewebsites.net", "godaddysites.com", "square.site", "surge.sh", "fly.dev", "workers.dev"]

# Never candidates: big sites that show up in title/search results for any brand
IGNORED_SITES = {"google.com", "youtube.com", "facebook.com", "instagram.com", "linkedin.com", "twitter.com", "x.com",
                 "wikipedia.org", "reddit.com", "quora.com", "medium.com", "amazon.com", "amazon.in", "flipkart.com",
                 "play.google.com", "apple.com", "microsoft.com", "bing.com", "duckduckgo.com", "yahoo.com",
                 "moneycontrol.com", "economictimes.indiatimes.com", "indiatimes.com", "ndtv.com", "paisabazaar.com",
                 "bankbazaar.com", "policybazaar.com", "glassdoor.com", "glassdoor.co.in", "ambitionbox.com",
                 "naukri.com", "indeed.com", "justdial.com", "crunchbase.com", "zaubacorp.com", "tofler.in",
                 "urlscan.io", "github.com", "gitlab.com", "telegram.org", "t.me", "whatsapp.com"}

PHISHING_FEEDS = {
    "Phishing.Database": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/"
                         "phishing-domains-ACTIVE.txt",
    "OpenPhish": "https://openphish.com/feed.txt",
    "PhishTank": "http://data.phishtank.com/data/online-valid.csv",
    "Phishing Army": "https://phishing.army/download/phishing_army_blocklist_extended.txt",
    "Phishunt": "https://phishunt.io/feed.txt",
}
FEED_CACHE_SECONDS = 6 * 3600
_feed_cache: dict[str, tuple[float, list[str]]] = {}
_feed_lock = threading.Lock()


# Never brand labels on their own: a product term like 'banking' would match every bank's phishing domain
GENERIC_WORDS = set(RISK_WORDS) | {"bank", "banks", "banking", "finance", "financial", "india", "group", "global",
                                   "services", "service", "limited", "private", "company", "corp", "money", "capital",
                                   "securities", "the", "and", "app", "web", "net", "online", "digital"}


def _flat(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


class HostMatcher:
    """Decides whether a hostname is about the brand, and which name to monitor for it."""

    def __init__(self, ctx: BrandContext) -> None:
        self.ctx = ctx
        labels = {_flat(x) for x in ctx.labels + ctx.strong_terms} - {""} - GENERIC_WORDS
        self.strong = sorted(x for x in labels if len(x) >= STRONG_LABEL_LEN)
        self.weak = sorted(x for x in labels if 3 <= len(x) < STRONG_LABEL_LEN)
        self.official = {registered_domain(d) for d in ctx.official_domains}
        self.official_sites = {site_domain(d) for d in ctx.official_domains}

    def names_brand(self, labels: list[str], hosted: bool) -> bool:
        flat = _flat("".join(labels))
        if any(s in flat for s in self.strong):
            return True
        tokens = [t for t in re.split(r"[.\-_]", ".".join(labels)) if t]
        for w in self.weak:
            for t in tokens:
                if t == w or t.startswith(w):
                    # 'axis', 'axisloan': the brand starts the word - on a hosting platform that is enough,
                    # elsewhere another part must be a risk word ('axis-kyc', 'axisloan.in')
                    if hosted:
                        return True
                    parts = [x for x in tokens if x != t] + [t[len(w):]]
                    if any(p and (p.startswith(r) or p.endswith(r)) for p in parts for r in RISK_WORDS):
                        return True
                elif t.endswith(w):
                    # 'rewardsaxis' yes, 'praxis' / 'growthaxis' no: the word before the brand must be a risk word
                    if any(t[:-len(w)].endswith(r) for r in RISK_WORDS):
                        return True
        return False

    def candidate(self, raw: str, *, any_name: bool = False, strict: bool = False) -> str | None:
        """The name to monitor for a discovered host, or None. any_name=True keeps a host whose name does not
        mention the brand (it was found by its page content, e.g. a brand-titled page). strict=True needs the brand
        word itself in the name (no fuzzy similarity), for sources that return many unrelated names."""
        host = clean_host(raw)
        if not host:
            return None
        rd, site = registered_domain(host), site_domain(host)
        if rd in self.official or site in self.official_sites or rd in IGNORED_SITES or site in IGNORED_SITES:
            return None
        platform = hosting_platform(host)
        if platform:
            if platform in self.official:
                return None
            return site if (any_name or self.names_brand(host_labels(site), hosted=True)) else None
        label = domain_label(rd)
        fuzzy = not strict and best_similarity(label, self.ctx.labels)[0] >= MIN_LOOKALIKE_SIMILARITY
        if fuzzy or self.names_brand([label], False):
            return rd
        if self.names_brand(host_labels(host), hosted=False):
            return host  # the brand is only in the subdomain: monitor this exact host
        return rd if any_name else None


def brand_phrases(ctx: BrandContext) -> list[str]:
    """Distinctive brand names to search page titles/text for ('axis bank'), never a generic product term."""
    return [t for t in ctx.strong_terms if len(_flat(t)) >= STRONG_LABEL_LEN and _flat(t) not in GENERIC_WORDS]


def clean_host(raw: str) -> str | None:
    raw = (raw or "").strip().lower()
    if not raw:
        return None
    host = urlsplit(raw).hostname if "://" in raw else raw.split("/")[0].split(":")[0]
    host = (host or "").lstrip("*.").removeprefix("www.").strip(".")
    if not host or "." not in host or not re.fullmatch(r"[a-z0-9.-]+", host) or len(host) > 253:
        return None
    return host


def _add(out: dict[str, str], host: str | None, kind: str, cap: int) -> None:
    if host and host not in out and len(out) < cap:
        out[host] = kind


# ------------------------------------------------------------------------------------------------ urlscan.io
def urlscan_hosts(ctx: BrandContext, report: ScanReport, matcher: HostMatcher,
                  fetcher: Callable = fetch) -> dict[str, str]:
    s = get_settings()
    if not s.urlscan_api_key:
        report.not_configured(URLSCAN, "URLSCAN_API_KEY not set - public scans not searched for brand hostnames")
        return {}
    headers = {"API-Key": s.urlscan_api_key}
    date_q = ""
    if ctx.has_date_range:
        date_q = f" AND date:[{ctx.date_from or '1995-01-01'} TO {ctx.date_to or 'now'}]"
    queries: list[tuple[str, bool]] = [(f"page.domain:*{w}*", False) for w in matcher.strong + matcher.weak]
    queries += [(f'page.title:"{t}"', True) for t in brand_phrases(ctx)]
    out: dict[str, str] = {}
    failed: list[str] = []
    per_query = max(150, s.domain_discovery_max_hosts // max(1, len(queries)))
    for q, by_title in queries:
        after, start = None, len(out)
        for _ in range(max(1, s.urlscan_discovery_pages)):
            url = (f"https://urlscan.io/api/v1/search/?q={quote(q + date_q)}&size=1000"
                   + (f"&search_after={quote(after)}" if after else ""))
            try:
                r = fetcher(url, headers=headers, max_bytes=40_000_000, timeout=60)
            except FetchError as exc:
                failed.append(f"{q}: {exc}"[:160])
                break
            if r.status != 200:
                failed.append(f"{q}: HTTP {r.status}")
                break
            data = json.loads(r.content or b"{}")
            results = data.get("results", [])
            for x in results:
                page = x.get("page") or {}
                host = matcher.candidate(page.get("domain") or "", any_name=by_title)
                _add(out, host, "urlscan", min(s.domain_discovery_max_hosts, start + per_query))
            if not data.get("has_more") or not results or len(out) >= min(s.domain_discovery_max_hosts,
                                                                          start + per_query):
                break
            after = ",".join(str(v) for v in results[-1].get("sort", []))
            if not after:
                break
    if failed and not out:
        report.failed(URLSCAN, "; ".join(failed[:3]), failed=len(failed))
    else:
        report.ok(URLSCAN, queries=len(queries), hosts=len(out))
        if failed:
            report.failed(URLSCAN, "; ".join(failed[:3]), failed=len(failed))
    return out


# ------------------------------------------------------------------------------------------------ phishing feeds
def _feed(name: str, url: str, fetcher: Callable) -> list[str]:
    with _feed_lock:
        hit = _feed_cache.get(name)
        if hit and time.monotonic() - hit[0] < FEED_CACHE_SECONDS:
            return hit[1]
    r = fetcher(url, max_bytes=80_000_000, timeout=120)
    if r.status != 200:
        raise FetchError(f"{name}: HTTP {r.status}")
    lines = []
    for ln in (r.content or b"").decode("utf-8", "ignore").splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        if "," in ln or "://" in ln:  # CSV rows (PhishTank) and URL lists: keep just the URL
            m = re.search(r"https?://[^\s,\"']+", ln)
            if not m:
                continue
            ln = m.group(0)
        lines.append(ln)
    with _feed_lock:
        _feed_cache[name] = (time.monotonic(), lines)
    return lines


def feed_hosts(ctx: BrandContext, report: ScanReport, matcher: HostMatcher, fetcher: Callable = fetch) -> dict[str, str]:
    s = get_settings()
    out: dict[str, str] = {}
    failed, checked = [], 0
    needles = matcher.strong + matcher.weak
    for name, url in PHISHING_FEEDS.items():
        try:
            lines = _feed(name, url, fetcher)
        except (FetchError, ValueError) as exc:
            failed.append(f"{name}: {exc}"[:160])
            continue
        checked += 1
        for line in lines:
            low = line.lower()
            if not any(n in _flat(low) for n in needles):
                continue
            # a feed listing is itself evidence, so a distinctive brand word anywhere in the host is enough
            host = matcher.candidate(low, strict=True) or (matcher.candidate(low, any_name=True)
                                              if any(n in _flat(low) for n in matcher.strong) else None)
            _add(out, host, "phishing-feed", s.domain_discovery_max_hosts)
    if checked:
        report.ok(FEEDS, feeds=checked, hosts=len(out))
    if failed:
        report.failed(FEEDS, "; ".join(failed), failed=len(failed))
    return out


# ------------------------------------------------------------------------------------------------ web search dorks
def dork_queries(ctx: BrandContext) -> list[str]:
    name = (brand_phrases(ctx) or [ctx.name])[0]
    official = " ".join(f"-site:{d}" for d in ctx.official_domains[:4])
    groups = [HOSTING_PLATFORMS[i:i + 8] for i in range(0, len(HOSTING_PLATFORMS), 8)]
    out = [f'"{name}" (' + " OR ".join(f"site:{p}" for p in g) + ")" for g in groups]
    out += [f'intitle:"{name}" (login OR "net banking" OR kyc OR verify) {official}'.strip(),
            f'"{name}" "customer care" OR "kyc update" OR "reward points" {official}'.strip()]
    return out


def search_hosts(ctx: BrandContext, report: ScanReport, matcher: HostMatcher,
                 searcher: Callable = search.search) -> dict[str, str]:
    s = get_settings()
    if not search.configured():
        report.not_configured(DORKS, "no web search configured")
        return {}
    out: dict[str, str] = {}
    failed = []
    queries = dork_queries(ctx)
    for q in queries:
        try:
            results = searcher(q, 100)
        except search.SearchUnavailable as exc:
            failed.append(str(exc)[:160])
            continue
        for r in results:
            text = f"{r.title} {r.snippet}".lower()
            names_brand = any(t.lower() in text for t in brand_phrases(ctx))
            host = matcher.candidate(r.url, strict=True)
            if host is None and names_brand and hosting_platform(clean_host(r.url) or ""):
                host = matcher.candidate(r.url, any_name=True)  # brand page deployed on vercel.app, web.app...
            _add(out, host, "search-engine", s.domain_discovery_max_hosts)
    if len(failed) == len(queries):
        report.failed(DORKS, "; ".join(failed[:2]), failed=len(failed))
    else:
        report.ok(DORKS, queries=len(queries) - len(failed), hosts=len(out))
    return out


# ------------------------------------------------------------------------------------------------ Common Crawl
def _redis():
    try:
        import redis

        return redis.Redis.from_url(get_settings().redis_url, socket_timeout=3)
    except Exception:  # noqa: BLE001
        return None


def _cc_get(url: str, fetcher: Callable) -> tuple[int | None, str]:
    """One index request with back-off: the public index often answers 502/503/504 under load."""
    last = ""
    for attempt in range(3):
        try:
            r = fetcher(url, max_bytes=30_000_000, timeout=90)
            if r.status in (200, 404):  # 404 = no captures matched on this page
                return r.status, (r.content or b"").decode("utf-8", "ignore")
            last = f"HTTP {r.status}"
        except FetchError as exc:
            last = str(exc)[:120]
        time.sleep(5 * (attempt + 1))
    return None, last


def commoncrawl_hosts(ctx: BrandContext, report: ScanReport, matcher: HostMatcher,
                      fetcher: Callable = fetch) -> dict[str, str]:
    """Brand-named sites on hosting platforms from the newest Common Crawl index (e.g. axis-bank-xyz.vercel.app).
    These share one wildcard certificate, so CT never lists them. Each index page's result is cached for 30 days
    (a published crawl never changes), so every scan continues with pages not read yet."""
    from urllib.parse import urlencode

    from app.modules.apk import commoncrawl as cc

    s = get_settings()
    if not s.common_crawl_enabled:
        report.not_configured(COMMON_CRAWL, "COMMON_CRAWL_ENABLED=false")
        return {}
    needles = matcher.strong + matcher.weak
    if not needles:
        return {}
    cols = cc.collections(1)
    if not cols:
        report.failed(COMMON_CRAWL, "Common Crawl index unavailable (collinfo.json)")
        return {}
    col = cols[0]
    api = f"https://index.commoncrawl.org/{col}-index?"
    regex = ".*(" + "|".join(re.escape(n) for n in needles) + ").*"
    cache = _redis()
    deadline = time.monotonic() + s.common_crawl_domain_budget_seconds
    out: dict[str, str] = {}
    failed: list[str] = []
    read = cached = 0
    pending_pages = 0
    for plat in CC_PLATFORMS:
        base = {"url": f"*.{plat}", "output": "json", "fl": "url", "filter": f"~url:{regex}"}
        meta_key = f"ccdom:{col}:{plat}:pages"
        pages = None
        try:
            pages = int(cache.get(meta_key)) if cache is not None and cache.get(meta_key) else None
        except Exception:  # noqa: BLE001
            pages = None
        if pages is None:
            if time.monotonic() > deadline:
                break
            status, body = _cc_get(api + urlencode({"url": f"*.{plat}", "showNumPages": "true", "output": "json"}),
                                   fetcher)
            try:
                pages = int(json.loads(body).get("pages", 0)) if status == 200 else None
            except (ValueError, AttributeError):
                pages = None
            if pages is None:
                failed.append(f"{plat}: {body[:80] if status is None else 'page count unreadable'}")
                continue
            if cache is not None:
                try:
                    cache.setex(meta_key, 30 * 24 * 3600, pages)
                except Exception:  # noqa: BLE001
                    pass
        for page in range(min(pages, s.common_crawl_domain_max_pages)):
            key = f"ccdom:{col}:{plat}:{page}:{regex}"
            hit = None
            if cache is not None:
                try:
                    hit = cache.get(key)
                except Exception:  # noqa: BLE001
                    hit = None
            if hit is not None:
                urls = json.loads(hit)
                cached += 1
            else:
                if time.monotonic() > deadline:
                    pending_pages += 1
                    continue
                status, body = _cc_get(api + urlencode({**base, "page": page}), fetcher)
                if status is None:
                    failed.append(f"{plat} page {page}: {body[:80]}")
                    pending_pages += 1
                    if len(failed) >= 6:
                        break
                    continue
                urls = []
                for ln in body.splitlines() if status == 200 else []:
                    try:
                        urls.append(json.loads(ln).get("url", ""))
                    except ValueError:
                        continue
                urls = sorted({clean_host(u) or "" for u in urls} - {""})
                read += 1
                if cache is not None:
                    try:
                        cache.setex(key, 30 * 24 * 3600, json.dumps(urls))
                    except Exception:  # noqa: BLE001
                        pass
            for u in urls:
                _add(out, matcher.candidate(u, strict=True), "commoncrawl", s.domain_discovery_max_hosts)
        if len(failed) >= 6:
            break
    if read or cached:
        report.ok(COMMON_CRAWL, f"index {col}", pages_read=read, pages_cached=cached, hosts=len(out))
    if failed:
        report.failed(COMMON_CRAWL, "index busy/unavailable: " + "; ".join(failed[:3]), failed=len(failed))
    elif pending_pages:
        report.ok(COMMON_CRAWL, pages_left_for_next_scan=pending_pages)
    return out


# ------------------------------------------------------------------------------------------------ CertStream
def certstream_key(brand_id) -> str:
    return f"certstream:brand:{brand_id}"


CERTSTREAM_HEARTBEAT = "certstream:heartbeat"


def certstream_hosts(ctx: BrandContext, report: ScanReport, matcher: HostMatcher) -> dict[str, str]:
    """Brand-named hosts the certwatch service saw in newly issued certificates (live stream, kept 90 days)."""
    from datetime import datetime, time as dtime, UTC

    s = get_settings()
    if not s.certstream_url:
        report.not_configured(CERTSTREAM, "CERTSTREAM_URL not set")
        return {}
    cache = _redis()
    if cache is None:
        report.failed(CERTSTREAM, "Redis unavailable")
        return {}
    lo, hi = "-inf", "+inf"
    if ctx.date_from:
        lo = datetime.combine(ctx.date_from, dtime.min, UTC).timestamp()
    if ctx.date_to:
        hi = datetime.combine(ctx.date_to, dtime.max, UTC).timestamp()
    try:
        alive = cache.get(CERTSTREAM_HEARTBEAT)
        hosts = [h.decode() if isinstance(h, bytes) else h
                 for h in cache.zrangebyscore(certstream_key(ctx.id), lo, hi)]
    except Exception as exc:  # noqa: BLE001
        report.failed(CERTSTREAM, f"Redis error: {exc}"[:160])
        return {}
    if not alive and not hosts:
        report.not_configured(CERTSTREAM, "certwatch service not running - start it with: docker compose "
                                          "--profile app --profile certstream up -d")
        return {}
    out: dict[str, str] = {}
    for h in hosts:
        _add(out, matcher.candidate(h), "certstream", get_settings().domain_discovery_max_hosts)
    report.ok(CERTSTREAM, hosts=len(out))
    if not alive:
        report.failed(CERTSTREAM, "certwatch service stopped - showing hosts collected while it ran")
    return out
