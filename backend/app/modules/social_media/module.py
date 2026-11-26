"""Social media brand-misuse monitor (spec docs/superpowers/specs/2026-10-09-social-media-monitor-design.md).

Finds posts, videos, ads and channels that use the brand name or logo on YouTube, Facebook, Instagram, X, Threads,
Meta ads, Pinterest, TikTok, LinkedIn and Telegram; keeps a screenshot, thumbnail and the link as evidence; flags
fake contact details (WhatsApp / phone / UPI / Telegram) and scam wording.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterator
from urllib.parse import urlsplit

import structlog
from sqlalchemy.orm import Session

from app.config import get_settings
from app.core.allowlist import social_handle
from app.core.browser import capture
from app.core.evidence import EvidenceItem
from app.core.scoring import Signals
from app.db.models import ModuleName
from app.modules.base import BrandContext, Detection, ScanReport
from app.modules.common import image_match, literal_brand_in
from app.modules.social_media import sources
from app.modules.social_media.analysis import (
    SCORED_CONTACTS,
    abuse_phrases,
    contact_details,
    drop_official,
    fake_support_claim,
    normalize,
    scam_phrases,
    strong_phrases,
    wrong_details_phrases,
)
from app.modules.social_media.sources import SocialItem

log = structlog.get_logger(__name__)

CAPTURE = "Browser capture (social media)"
TYPE_LABEL = {"video": "video", "post": "post", "ad": "ad", "channel": "channel", "account": "account"}


def social_signals(*, brand_in_content: bool, typo_similarity: float | None, logo_match: bool,
                   scored_contacts: dict, phrases: list[str], title: str, paid_ad: bool) -> Signals:
    """What was observed, as scoring signals (also used to re-score stored findings)."""
    return Signals(brand_in_content=brand_in_content, typo_similarity=typo_similarity,
                   social_image_match=logo_match, scam_contact_details=bool(scored_contacts),
                   fake_support_claim=fake_support_claim(scam_phrases(title), phrases),
                   scam_language=bool(wrong_details_phrases(phrases)),
                   brand_abuse=bool(abuse_phrases(phrases)), paid_ad=paid_ad)


def headline_for(platform: str, content_type: str, s: Signals) -> str:
    why = [label for flag, label in [
        (s.scam_contact_details, "fake contact details"), (s.fake_support_claim, "fake customer care"),
        (s.scam_language, "scam wording"), (s.brand_abuse, "brand abuse"), (s.social_image_match, "official logo"),
    ] if flag]
    label = TYPE_LABEL.get(content_type, content_type)
    return f"Brand used in {platform} {label}" + (f" ({', '.join(why)})" if why else "")


class SocialMediaModule:
    name = ModuleName.social_media

    def __init__(self, source: Callable[[BrandContext, ScanReport], list[SocialItem]] | None = None,
                 capture_fn=capture) -> None:
        self._source = source or sources.all_items
        self._capture = capture_fn
        self.stats: dict = {}
        self.report = ScanReport()

    def run(self, ctx: BrandContext, db: Session) -> Iterator[Detection]:
        s = get_settings()
        items = self._source(ctx, self.report)
        if ctx.has_date_range:  # D-50: content published outside the chosen range is left out (unknown dates kept)
            before = len(items)
            items = [i for i in items if i.content_type in ("channel", "account") or ctx.in_date_range(i.published)]
            self.stats["outside_date_range"] = before - len(items)
        if not any(c["status"] == "ok" for c in self.report.as_list()):
            # every source was missing, blocked or down: nothing was checked, so this is not "no misuse"
            self.report.failed("Social media sources", "no source could be checked (add API keys or a search key)",
                               fatal=True)
        self.stats.update(items_checked=len(items), flagged=0, captured=0,
                          by_platform={})
        captures_left = s.social_media_max_items
        deadline = time.monotonic() + s.social_media_analysis_minutes * 60
        for n, item in enumerate(items):
            if time.monotonic() > deadline:
                # finish and save what was found rather than being killed by the worker time limit
                self.report.failed("Content analysis", f"time budget of {s.social_media_analysis_minutes} min "
                                   f"reached: {len(items) - n} of {len(items)} items not analysed", failed=len(items) - n)
                break
            try:
                det = self.analyse(ctx, item, capture_ok=captures_left > 0)
            except Exception as exc:  # noqa: BLE001
                self.report.failed("Content analysis", f"{item.url}: {type(exc).__name__}: {exc}", failed=1)
                continue
            if det is None:
                continue
            if det.details.get("Screenshot"):
                captures_left -= 1
                self.stats["captured"] += 1
            self.stats["flagged"] += 1
            bp = self.stats["by_platform"]
            bp[item.platform] = bp.get(item.platform, 0) + 1
            yield det

    # ------------------------------------------------------------------ one item
    def _official(self, ctx: BrandContext, item: SocialItem) -> bool:
        host = (urlsplit(item.url).hostname or "").lower()
        if any(host == d or host.endswith("." + d) for d in ctx.official_domains):
            return True
        names = {social_handle(x).lower() for x in (item.author_handle, item.author_id, item.author_url) if x}
        if item.content_type in ("channel", "account"):
            names.add(social_handle(item.url).lower())
        return bool(names & set(ctx.official_handles))

    def analyse(self, ctx: BrandContext, item: SocialItem, capture_ok: bool = True) -> Detection | None:
        s = get_settings()
        if self._official(ctx, item):
            return None
        text = normalize(" ".join(x for x in (item.title, item.text, item.author or "", item.author_handle or "") if x))
        rel = ctx.relevance(text, name=normalize(item.author or item.title))
        logo_score, thumb, thumb_type = image_match(item.thumbnail_url, ctx.all_brand_image_hashes)
        logo_match = logo_score >= s.logo_match_threshold
        contacts = drop_official(contact_details(text), ctx.official_domains, ctx.official_handles)
        phrases = scam_phrases(text)
        scored_contacts = {k: v for k, v in contacts.items() if k in SCORED_CONTACTS}
        strong = strong_phrases(phrases)
        # A short brand name ('Navi') alone is ambiguous (D-25), but together with scam wording in the same
        # title/description it is the classic fraud pattern — keep it. A phone number alone is not brand context:
        # "Navi Mumbai" shops and "Navi Pillay" news publish numbers too (D-45).
        scam_context = bool(rel.weak_hits) and bool(strong or (scored_contacts and phrases))
        if not (rel.relevant or logo_match or scam_context):
            return None
        brand_named = bool(rel.strong_hits) or literal_brand_in(f"{item.author or ''} {item.title}", ctx.strong_terms)

        evidence = [EvidenceItem("metadata", meta={
            "platform": item.platform, "type": item.content_type, "url": item.url, "title": item.title,
            "text": item.text[:4000], "author": item.author, "author_handle": item.author_handle,
            "author_url": item.author_url, "published": item.published, "metrics": item.metrics,
            "discovery": item.discovery, **({"tags": item.raw["tags"]} if item.raw.get("tags") else {})})]
        if thumb:
            evidence.append(EvidenceItem("image", data=thumb, content_type=thumb_type,
                                         meta={"url": item.thumbnail_url, "role": "thumbnail",
                                               "logo_match_score": logo_score}))
        shot = False
        if capture_ok:
            try:
                cap = self._capture(item.url, full_page=False)
                if cap.screenshot:
                    shot = True
                    evidence.append(EvidenceItem("screenshot", data=cap.screenshot, content_type="image/png",
                                                 meta={"url": item.url, "final_url": cap.final_url,
                                                       "title": cap.title, "status": cap.status}))
                    self.report.ok(CAPTURE, captured=1)
                else:
                    self.report.failed(CAPTURE, f"{item.url}: {cap.error or 'no screenshot'}"[:200], failed=1)
            except Exception as exc:  # noqa: BLE001 - recorded; the item is still reported with its link
                self.report.failed(CAPTURE, f"{item.url}: {type(exc).__name__}: {str(exc)[:120]}", failed=1)
                log.info("social_capture_failed", url=item.url, error=str(exc)[:200])

        # name similarity only counts for accounts/channels (impersonation), not for a post that mentions the brand
        is_account = item.content_type in ("channel", "account")
        signals = social_signals(brand_in_content=brand_named or rel.relevant,
                                 typo_similarity=(rel.similarity or None) if is_account else None,
                                 logo_match=logo_match, scored_contacts=scored_contacts, phrases=phrases,
                                 title=f"{item.title} {item.author or ''}", paid_ad=item.content_type == "ad")
        headline = headline_for(item.platform, item.content_type, signals)
        label = TYPE_LABEL.get(item.content_type, item.content_type)
        details = {
            "Platform": item.platform,
            "Content Type": label.title(),
            "Title": item.title[:300],
            "Author": item.author,
            "Author URL": item.author_url,
            "URL": item.url,
            "Published": item.published,
            "Views": item.metrics.get("Views"),
            "Likes": item.metrics.get("Likes"),
            "Comments": item.metrics.get("Comments"),
            **{k: v for k, v in item.metrics.items() if k not in ("Views", "Likes", "Comments") and v is not None},
            "Brand Terms": rel.terms_used,
            "Logo Match": logo_match,
            "Logo Match Score": round(logo_score) if logo_score else None,
            "Scam Contacts": [f"{k}: {v}" for k, vs in scored_contacts.items() for v in vs],
            "Other Links": [f"{k}: {v}" for k, vs in contacts.items() if k not in SCORED_CONTACTS for v in vs],
            "Scam Phrases": phrases,
            "Text Excerpt": item.text[:500],
            "Thumbnail URL": item.thumbnail_url,
            "Screenshot": shot,
            "Discovery Source": item.discovery,
            "Found By Search": item.query,
        }
        return Detection(
            entity_key=item.key, title=f"{headline}: {item.title or item.author or item.url}"[:500], signals=signals,
            details=details, similarity=rel.similarity or None, source_url=item.url, evidence=evidence,
            module=ModuleName.social_media,
            analysed=item.structured or shot or bool(thumb),  # D-33: an uncaptured search hit stays a Candidate
            state={"logo_match": logo_match},
        )
