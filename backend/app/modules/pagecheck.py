"""Analyse a captured web page: phishing keywords, favicon match, official-logo match, and (D-29) whether the
page shows the brand at all — brand name/terms, references to official sites — or is a parked/for-sale page.

Shared by the domain pipeline (PHI-06/07, RSK-05/06) and the logo module (LOGO-02…05).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from app.config import get_settings
from app.core.browser import PageCapture
from app.core.imaging import best_match, favicon_hash, hashes_for
from app.modules.base import BrandContext

# PHI-07: "login, secure, account, verify, payment, etc."
PHISHING_KEYWORDS = ["login", "log in", "sign in", "signin", "secure", "account", "verify", "verification",
                     "payment", "password", "otp", "one time password", "card number", "cvv", "pin",
                     "netbanking", "net banking", "kyc", "update your", "suspended", "unlock", "billing",
                     "wallet", "credentials", "authenticate"]

# D-29: domain marketplaces and parking services; a page served from these is not the brand's look-alike site
PARKING_HOSTS = ("hugedomains.com", "sedo.com", "sedoparking.com", "afternic.com", "dan.com", "bodis.com",
                 "parkingcrew.net", "above.com", "undeveloped.com", "domainmarket.com", "buydomains.com",
                 "parklogic.com", "smartname.com", "domainnamesales.com", "atom.com", "spaceship.com")
PARKING_PHRASES = ("domain is for sale", "domain may be for sale", "buy this domain", "domain for sale",
                   "this domain has been registered", "parked free", "domain is parked", "parked domain",
                   "make an offer on this domain", "inquire about this domain", "this web page is parked")
PARKING_PATHS = ("/lander",)  # Sedo / Bodis / GoDaddy parking landers


@dataclass
class PageFacts:
    keywords_found: list[str] = field(default_factory=list)
    has_password_field: bool = False
    favicon_mmh3: int | None = None
    favicon_match: bool = False
    favicon_match_score: float = 0.0
    logo_score: float = 0.0
    logo_image_url: str | None = None
    logo_image: bytes | None = None
    brand_terms_found: list[str] = field(default_factory=list)
    official_refs: list[str] = field(default_factory=list)
    parked: bool = False

    @property
    def login_payment(self) -> bool:
        return bool(self.keywords_found) or self.has_password_field

    @property
    def brand_evidence(self) -> bool:
        """Text or links on the page tie it to the brand (logo/favicon are judged by the caller's threshold)."""
        return bool(self.brand_terms_found or self.official_refs or self.favicon_match)


def find_keywords(*texts: str) -> list[str]:
    hay = " ".join(t.lower() for t in texts if t)
    return [k for k in PHISHING_KEYWORDS if re.search(rf"(?<![a-z]){re.escape(k)}(?![a-z])", hay)]


def _host(url: str | None) -> str:
    try:
        return (urlsplit(url or "").hostname or "").lower().removeprefix("www.")
    except ValueError:
        return ""


def _domain_re(domain: str) -> str:
    # the domain or a subdomain of it, not a longer look-alike (mykcpl.com.evil, xmykcpl.com)
    return rf"(?<![a-z0-9-]){re.escape(domain)}(?![a-z0-9-]|\.[a-z0-9])"


def is_parked(cap: PageCapture) -> bool:
    host, path = _host(cap.final_url), urlsplit(cap.final_url or "").path.lower()
    if any(host == h or host.endswith("." + h) for h in PARKING_HOSTS):
        return True
    if any(path == p or path.startswith(p + "/") for p in PARKING_PATHS):
        return True
    hay = f"{cap.title} {cap.text[:20_000]}".lower()
    return any(p in hay for p in PARKING_PHRASES)


def brand_on_page(cap: PageCapture, ctx: BrandContext) -> tuple[list[str], list[str]]:
    """(brand terms in the page text, official domains referenced) — the page's own domain is ignored."""
    hay = f"{cap.title}\n{cap.text[:50_000]}".lower()
    for own in {_host(cap.url), _host(cap.final_url)} - {""}:
        hay = re.sub(_domain_re(own), " ", hay)
    rel = ctx.relevance(hay)
    terms = rel.strong_hits + (rel.weak_hits if rel.relevant and rel.weak_hits else [])
    refs_hay = f"{hay}\n{(cap.html or '')[:200_000].lower()}"
    refs = [d for d in dict.fromkeys(ctx.official_domains + ctx.email_domains)
            if d and re.search(_domain_re(d), refs_hay)]
    return list(dict.fromkeys(terms)), refs


def analyse(cap: PageCapture, ctx: BrandContext) -> PageFacts:
    s = get_settings()
    facts = PageFacts(keywords_found=find_keywords(cap.title, cap.text[:50_000]),
                      has_password_field=cap.has_password_field)
    facts.brand_terms_found, facts.official_refs = brand_on_page(cap, ctx)
    facts.parked = is_parked(cap)
    if cap.favicon:
        facts.favicon_mmh3 = favicon_hash(cap.favicon)
        if facts.favicon_mmh3 in ctx.favicon_mmh3:
            facts.favicon_match, facts.favicon_match_score = True, 100.0
        else:
            h = hashes_for(cap.favicon)
            if h and ctx.all_brand_image_hashes:
                facts.favicon_match_score = best_match(h, ctx.all_brand_image_hashes)
                facts.favicon_match = facts.favicon_match_score >= s.logo_match_threshold
    for img in cap.images:
        h = hashes_for(img.data)
        if h is None or not ctx.logo_hashes:
            continue
        sc = best_match(h, ctx.logo_hashes)
        if sc > facts.logo_score:
            facts.logo_score, facts.logo_image_url, facts.logo_image = sc, img.url, img.data
    return facts
