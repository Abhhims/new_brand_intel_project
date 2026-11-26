"""Social media impersonation (§3.4, SOC-01…12, D-10).

Sources:
  * Telegram (live): official API via Telethon — public usernames/channels matching brand terms.
  * Instagram, TikTok, Facebook, X, LinkedIn via Apify actors when APIFY_TOKEN is set (D-43): real profiles with
    bio, followers and avatar.
  * X, Facebook, Instagram, LinkedIn (live): web search restricted to each site; public profile pages
    are read only when reachable without logging in.
  * Demo brands: fixtures/sources/social.json.
Detection: username + display-name similarity, profile image vs logo, brand in bio, support/contact
terminology, and the handle not being one of the brand's official handles.
"""

from __future__ import annotations

import html
import re
from collections.abc import Iterator
from dataclasses import dataclass
from urllib.parse import urlsplit

import structlog
from sqlalchemy.orm import Session

from app.config import get_settings
from app.core import search
from app.core.allowlist import social_handle
from app.core.browser import capture
from app.core.evidence import EvidenceItem
from app.core.fetch import try_fetch
from app.core.scoring import Signals
from app.core.similarity import best_similarity, brand_terms_in_text
from app.db.models import ModuleName
from app.modules.base import BrandContext, Detection, ScanReport
from app.modules.common import image_match, literal_brand_in, report_search_failure

log = structlog.get_logger(__name__)

PLATFORMS = ["X", "Facebook", "Instagram", "LinkedIn", "Telegram", "TikTok"]  # SOC-01…05; TikTok via Apify (D-43)
SUPPORT_TERMS = ["support", "customer care", "customer service", "helpdesk", "help desk", "helpline", "official",
                 "contact us", "dm us", "dm for", "24/7", "care", "assist", "complaint", "refund", "kyc",
                 "verify", "verification", "hiring", "recruit"]
RELEVANCE_HANDLE = 80   # handle vs a long (8+ letter) brand label
RELEVANCE_STRICT = 85   # handle vs a 6-7 letter label, only with brand context

SITE_QUERIES = {
    "X": ["site:x.com", "site:twitter.com"],
    "Facebook": ["site:facebook.com"],
    "Instagram": ["site:instagram.com"],
    "LinkedIn": ["site:linkedin.com/in", "site:linkedin.com/company"],
}
RESERVED_PATHS = {"home", "search", "explore", "hashtag", "i", "intent", "share", "login", "p", "reel", "stories",
                  "pages", "groups", "watch", "events", "posts", "status", "jobs", "pulse", "feed", "school"}


@dataclass
class Profile:
    platform: str
    username: str
    display_name: str
    bio: str = ""
    followers: int | None = None
    avatar_url: str | None = None
    profile_url: str | None = None
    discovery: str = "simulated"


TELEGRAM_API = "Telegram API"


class LiveSocialSource:
    def profiles(self, ctx: BrandContext, report: ScanReport) -> list[Profile]:
        found = self._telegram(ctx, report) + apify_profiles(ctx, report) + self._search(ctx, report)
        unique: dict[str, Profile] = {}
        for p in found:  # a profile read through an API wins over the same handle from web search
            unique.setdefault(f"{p.platform}:{p.username.lstrip('@').lower()}", p)
        return list(unique.values())

    def _search(self, ctx: BrandContext, report: ScanReport) -> list[Profile]:
        out: list[Profile] = []
        component = search.component_name()
        for platform, sites in SITE_QUERIES.items():
            query = f'({" OR ".join(sites)}) ({" OR ".join(chr(34) + t + chr(34) for t in ctx.terms[:3])})'
            try:
                results = search.search(query, count=20)
                report.ok(component, queries=1)
            except search.SearchUnavailable as exc:
                report_search_failure(report, component, exc)
                continue
            for r in results:
                handle = _handle_from_url(platform, r.url)
                if handle:
                    name = re.split(r"\s[|(•\-–]\s?|\s\(@", r.title)[0].strip() or handle
                    out.append(Profile(platform=platform, username=handle, display_name=name, bio=r.snippet,
                                       profile_url=r.url, discovery="web search"))
        return out

    def _telegram(self, ctx: BrandContext, report: ScanReport) -> list[Profile]:
        s = get_settings()
        if not (s.telegram_api_id and s.telegram_api_hash and s.telegram_session):
            # D-31: say so — the public-page check below is a narrower source, not the Telegram search API
            report.not_configured(TELEGRAM_API, "TELEGRAM_API_ID / TELEGRAM_API_HASH / TELEGRAM_SESSION not set")
            if s.telegram_public_fallback:
                return telegram_public(ctx, report)
            return []
        try:
            from telethon.sessions import StringSession
            from telethon.sync import TelegramClient
            from telethon.tl.functions.contacts import SearchRequest
        except ImportError as exc:
            report.failed(TELEGRAM_API, f"Telegram client unavailable: {exc}")
            return []
        out: list[Profile] = []
        try:
            with TelegramClient(StringSession(s.telegram_session), s.telegram_api_id, s.telegram_api_hash) as client:
                for term in ctx.terms[:3]:
                    res = client(SearchRequest(q=term, limit=50))
                    for chat in list(res.chats) + list(res.users):
                        username = getattr(chat, "username", None)
                        if not username:
                            continue
                        title = getattr(chat, "title", None) or " ".join(
                            x for x in (getattr(chat, "first_name", None), getattr(chat, "last_name", None)) if x)
                        out.append(Profile(platform="Telegram", username=username, display_name=title or username,
                                           followers=getattr(chat, "participants_count", None),
                                           profile_url=f"https://t.me/{username}", discovery="Telegram API"))
        except Exception as exc:  # noqa: BLE001
            report.failed(TELEGRAM_API, f"search failed: {type(exc).__name__}: {exc}")
            return out
        report.ok(TELEGRAM_API, found=len(out))
        return out


# Usernames impersonators typically register around a brand name (checked on public t.me pages)
TELEGRAM_AFFIXES = ["", "official", "_official", "support", "_support", "help", "_help", "care", "_care",
                    "customercare", "_customer_care", "helpdesk", "_helpdesk", "india", "_india", "app", "_app"]
MAX_TELEGRAM_CHECKS = 120


class TelegramPageUnavailable(Exception):
    """t.me could not be read (blocked, rate-limited, unreachable) — unknown, not 'no such account' (D-31)."""


def _telegram_page(username: str) -> Profile | None:
    """Public preview page https://t.me/<username>: exists only when it has a page title."""
    r = try_fetch(f"https://t.me/{username}")
    if not r or r.status != 200:
        raise TelegramPageUnavailable(f"t.me/{username}: {'no response' if not r else f'HTTP {r.status}'}")
    page = r.text
    title = re.search(r'tgme_page_title"[^>]*>\s*<span[^>]*>([^<]*)', page)
    if not title:
        return None  # Telegram serves a generic page for usernames that do not exist
    desc = re.search(r'tgme_page_description"[^>]*>(.*?)</div>', page, re.S)
    extra = re.search(r'tgme_page_extra">\s*([^<]*)', page)
    photo = re.search(r'tgme_page_photo_image"[^>]*src="([^"]+)"', page)
    followers = None
    if extra:
        digits = re.sub(r"[^0-9]", "", extra.group(1).split("subscriber")[0].split("member")[0])
        followers = int(digits) if digits else None
    return Profile(platform="Telegram", username=username, display_name=html.unescape(title.group(1).strip()),
                   bio=html.unescape(re.sub(r"<[^>]+>", " ", desc.group(1))).strip() if desc else "",
                   followers=followers, avatar_url=photo.group(1) if photo else None,
                   profile_url=f"https://t.me/{username}", discovery="Telegram public page")


def telegram_public(ctx: BrandContext, report: ScanReport | None = None) -> list[Profile]:
    """No Telegram API credentials: check likely impersonator usernames on public t.me pages (D-23)."""
    stems = list(dict.fromkeys(re.sub(r"[^a-z0-9_]", "", x.lower().replace(" ", "")) for x in ctx.labels))
    names: list[str] = []
    for stem in [x for x in stems if len(x) >= 4]:
        for affix in TELEGRAM_AFFIXES:
            name = f"{stem}{affix}"
            if 5 <= len(name) <= 32 and name not in ctx.official_handles:
                names.append(name)
    out, failed, last_error = [], 0, ""
    checked = list(dict.fromkeys(names))[:MAX_TELEGRAM_CHECKS]
    for name in checked:
        try:
            p = _telegram_page(name)
        except TelegramPageUnavailable as exc:
            failed, last_error = failed + 1, str(exc)
            continue
        if p:
            out.append(p)
    if report is not None:
        if failed:
            report.failed("Telegram public pages", f"{failed} of {len(checked)} pages could not be read "
                                                   f"(e.g. {last_error})", failed=failed)
        if failed < len(checked):
            report.ok("Telegram public pages", checked=len(checked) - failed, found=len(out))
    return out


def apify_profiles(ctx: BrandContext, report: ScanReport) -> list[Profile]:
    """D-43: Instagram and TikTok account search, plus the authors of the posts and ads the Apify content searches
    found (the same searches as the social media module, so those runs come from its cache)."""
    from app.modules.social_media import apify_sources as ap

    items = ap.instagram_profiles(ctx, report) + ap.tiktok_profiles(ctx, report)
    items += ap.content_items(ctx, report)
    out: list[Profile] = []
    for i in items:
        url = i.url if i.content_type == "account" else i.author_url
        handle = i.author_handle or (social_handle(url) if url else None) or i.author_id
        if not handle or not url:
            continue
        author = i.raw.get("author") or {}
        out.append(Profile(platform="Facebook" if i.platform == "Meta Ads" else i.platform, username=handle,
                           display_name=i.author or handle, bio=author.get("bio") or "",
                           followers=_int(author.get("followers")), avatar_url=author.get("avatar"),
                           profile_url=url, discovery=i.discovery))
    return out


def _int(value) -> int | None:
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _handle_from_url(platform: str, url: str) -> str | None:
    parts = [p for p in urlsplit(url).path.split("/") if p]
    if not parts:
        return None
    if platform == "LinkedIn":
        return parts[1] if len(parts) > 1 and parts[0] in ("in", "company") else None
    if platform == "Facebook" and parts[0] == "people" and len(parts) > 1:
        return parts[1]
    head = parts[0].lstrip("@")
    return None if head.lower() in RESERVED_PATHS or head.endswith(".php") else head


class SocialModule:
    name = ModuleName.social

    def __init__(self, source=None, capture_fn=capture) -> None:
        self._source = source
        self._capture = capture_fn
        self.stats: dict = {}
        self.report = ScanReport()

    def run(self, ctx: BrandContext, db: Session) -> Iterator[Detection]:
        source = self._source or LiveSocialSource()
        profiles = source.profiles(ctx, self.report)
        if not any(c["status"] == "ok" for c in self.report.as_list()):
            # every source was missing, blocked or down: nothing was checked, so this is not "no impersonation"
            self.report.failed("Social sources", "no source could be checked (Telegram and web search)", fatal=True)
        self.stats.update(profiles_checked=len(profiles), flagged=0,
                          by_platform={p: sum(1 for x in profiles if x.platform == p) for p in PLATFORMS})
        for p in profiles:
            try:
                finding = self.analyse(ctx, p)
            except Exception as exc:  # noqa: BLE001
                self.report.failed("Profile analysis", f"{p.platform}/{p.username}: {type(exc).__name__}: {exc}",
                                   failed=1)
                continue
            if finding:
                self.stats["flagged"] += 1
                yield finding

    def analyse(self, ctx: BrandContext, p: Profile) -> Detection | None:
        s = get_settings()
        handle = p.username.lstrip("@")
        if handle.lower() in ctx.official_handles:
            return None  # the brand's own account

        handle_words = re.sub(r"[_.\-]+", " ", handle)
        rel = ctx.relevance(f"{handle_words} {p.display_name} {p.bio}", name=p.display_name or handle)
        long_labels = [x for x in ctx.strong_labels if len(x) >= 8]
        medium_labels = [x for x in ctx.strong_labels if len(x) < 8]
        sim_long = best_similarity(handle, long_labels)[0] if long_labels else 0.0
        sim_medium = best_similarity(handle, medium_labels)[0] if medium_labels else 0.0
        user_sim = max(sim_long, sim_medium)
        name_sim = rel.similarity
        bio = p.bio or ""
        bio_brand = bool(brand_terms_in_text(bio, ctx.strong_terms)
                         or (brand_terms_in_text(bio, ctx.weak_terms) and brand_terms_in_text(bio, ctx.context_words)))
        support = [t for t in SUPPORT_TERMS if re.search(rf"(?<![a-z]){re.escape(t)}(?![a-z])",
                                                         f"{p.display_name} {bio} {handle}".lower())]
        similarity = max(user_sim, name_sim)
        # D-25: look-alike of a long name stands alone; short names/abbreviations need brand context
        relevant = (rel.relevant or sim_long >= RELEVANCE_HANDLE
                    or (sim_medium >= RELEVANCE_STRICT and bool(rel.context_hits or rel.weak_hits)))
        if not relevant:
            return None
        exact = literal_brand_in(handle, ctx.strong_terms) or bool(
            rel.context_hits and literal_brand_in(handle, ctx.weak_terms))

        logo_score, avatar, avatar_type = image_match(p.avatar_url, ctx.all_brand_image_hashes)
        logo_match = logo_score >= s.logo_match_threshold
        evidence = [EvidenceItem("metadata", meta=p.__dict__.copy())]
        if avatar:
            evidence.append(EvidenceItem("image", data=avatar, content_type=avatar_type,
                                         meta={"url": p.avatar_url, "logo_match_score": logo_score}))
        if p.profile_url:
            try:
                cap = self._capture(p.profile_url, full_page=False)
                if cap.screenshot:
                    evidence.append(EvidenceItem("screenshot", data=cap.screenshot, content_type="image/png",
                                                 meta={"url": cap.final_url, "title": cap.title}))
            except Exception as exc:  # noqa: BLE001 - many profiles need a login; metadata is still evidence
                log.info("profile_capture_failed", url=p.profile_url, error=str(exc)[:200])

        signals = Signals(brand_exact_in_domain=exact, typo_similarity=similarity,
                          social_image_match=logo_match)
        details = {
            "Platform": p.platform,
            "Username": f"@{handle}",
            "Display Name": p.display_name,
            "Similarity Score": round(similarity),
            "Logo Match": logo_match,
            "Followers": p.followers,
            "Profile URL": p.profile_url,
            "Bio": p.bio,
            "Bio Mentions Brand": bool(bio_brand),
            "Support Terms": support,
            "Logo Match Score": round(logo_score) if logo_score else None,
            "Discovery Source": p.discovery,
            "Username Similarity": round(user_sim),
            "Display Name Similarity": round(name_sim),
        }
        return Detection(entity_key=f"{p.platform.lower()}:{handle.lower()}",
                       title=f"Possible impersonation on {p.platform}: @{handle}", signals=signals, details=details,
                       similarity=similarity, source_url=p.profile_url, evidence=evidence,
                       # D-33: a bare search hit is a Candidate; a fetched profile or matching avatar is a Finding
                       analysed=p.discovery != "web search" or logo_match)
