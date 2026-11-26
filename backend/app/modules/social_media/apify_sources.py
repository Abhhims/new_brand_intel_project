"""Social media content and profiles from Apify actors (D-43): Instagram, TikTok, Facebook posts, Meta ads, X, LinkedIn.

Runs next to the official APIs and web search, never instead of them. YouTube is not here: its official API is better.
Each platform reports its own scan component ("Apify Instagram", …): "not configured" without APIFY_TOKEN, "skipped"
when left out of APIFY_PLATFORMS, "failed"/"unavailable" when the actor or Apify could not be run.
Searches are the brand terms (recent content) plus the first APIFY_SCAM_QUERIES scam searches (a longer window).
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from urllib.parse import quote

import structlog

from app.config import get_settings
from app.core import apify
from app.core.allowlist import social_handle
from app.modules.base import BrandContext, ScanReport
from app.modules.social_media.sources import SocialItem, scam_base

log = structlog.get_logger(__name__)

COMPONENT = {"instagram": "Apify Instagram", "tiktok": "Apify TikTok", "facebook": "Apify Facebook posts",
             "meta_ads": "Apify Meta ads", "x": "Apify X", "linkedin": "Apify LinkedIn"}
PROFILE_COMPONENT = {"instagram": "Apify Instagram profiles", "tiktok": "Apify TikTok profiles"}
PROFILES_PER_TERM = 10


# ------------------------------------------------------------------------------------------------ helpers
def _queries(ctx: BrandContext) -> tuple[list[str], list[str]]:
    s = get_settings()
    brand = list(dict.fromkeys(ctx.terms[:2] or [ctx.name]))
    scam = [q.replace("{brand}", scam_base(ctx)) for q in s.social_media_scam_queries[:max(0, s.apify_scam_queries)]]
    return brand, list(dict.fromkeys(scam))


def _day(days: int) -> str:
    return (datetime.now(UTC) - timedelta(days=days)).strftime("%Y-%m-%d")


def _iso(value) -> str | None:
    """Epoch seconds/milliseconds, ISO strings and X's 'Fri Nov 24 17:49:36 +0000 2023' → ISO 8601."""
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        secs = value / 1000 if value > 10**11 else value
        return datetime.fromtimestamp(secs, UTC).isoformat()
    text = str(value)
    try:
        return datetime.strptime(text, "%a %b %d %H:%M:%S %z %Y").isoformat()
    except ValueError:
        return text


def _first(*values):
    return next((v for v in values if v not in (None, "", [], {})), None)


def _enabled(platform: str, report: ScanReport, component: str) -> bool:
    s = get_settings()
    if not s.apify_token:
        report.not_configured(component, "APIFY_TOKEN not set")
        return False
    if platform not in s.apify_platforms:
        report.skipped(component, f"'{platform}' not in APIFY_PLATFORMS")
        return False
    return True


Run = tuple[dict, int, str]  # actor input, max items, the searches it covers (shown as "Found By Search")


def _run(platform: str, component: str, report: ScanReport, runs: list[Run],
         parse: Callable[[dict], SocialItem | None], actor: str | None = None) -> list[SocialItem]:
    actor = actor or getattr(get_settings(), f"apify_actor_{platform}")
    try:
        results = apify.run_many(actor, [(i, n) for i, n, _ in runs])
    except apify.ApifyError as exc:
        unreachable = "unreachable" in str(exc)
        (report.unavailable if unreachable else report.failed)(component, f"{actor}: {exc}"[:300])
        return []
    out: list[SocialItem] = []
    for (_, _, label), res in zip(runs, results, strict=True):
        if res.error:
            report.failed(component, f"{actor} '{label}': {res.error}"[:300])
        for raw in res.items:
            try:
                item = parse(raw)
            except Exception as exc:  # noqa: BLE001 - one odd record must not lose the rest
                log.info("apify_item_unreadable", actor=actor, error=str(exc)[:200])
                continue
            if item:
                item.query = item.query or label
                out.append(item)
    if any(r.ok for r in results):
        report.ok(component, items=len(out), runs=sum(1 for r in results if not r.cached),
                  cached=sum(1 for r in results if r.cached))
    return out


def _author(avatar=None, followers=None, bio=None, verified=None) -> dict:
    return {"author": {"avatar": avatar, "followers": followers, "bio": bio or "", "verified": verified}}


# ------------------------------------------------------------------------------------------------ Instagram

def _instagram_post(p: dict) -> SocialItem | None:
    url = p.get("url") or (f"https://www.instagram.com/p/{p['shortCode']}/" if p.get("shortCode") else None)
    if not url:
        return None
    owner = p.get("ownerUsername")
    caption = p.get("caption") or ""
    video = p.get("type") == "Video" or p.get("productType") == "clips"
    return SocialItem(
        platform="Instagram", content_type="video" if video else "post", url=url,
        item_id=p.get("shortCode") or p.get("id"), title=caption[:120], text=caption,
        author=p.get("ownerFullName") or owner, author_handle=owner, author_id=p.get("ownerId"),
        author_url=f"https://www.instagram.com/{owner}/" if owner else None, published=_iso(p.get("timestamp")),
        thumbnail_url=p.get("displayUrl"),
        metrics={"Views": _first(p.get("videoViewCount"), p.get("videoPlayCount")),
                 "Likes": p.get("likesCount") if (p.get("likesCount") or 0) >= 0 else None,  # -1 = likes hidden
                 "Comments": p.get("commentsCount")},
        discovery="Apify (Instagram)", structured=True, raw={"tags": (p.get("hashtags") or [])[:30]})


def instagram(ctx: BrandContext, report: ScanReport) -> list[SocialItem]:
    name = COMPONENT["instagram"]
    if not _enabled("instagram", report, name):
        return []
    s = get_settings()
    n = s.apify_items_per_query
    # Keyword search (phrases like '<brand> customer care number'), not hashtags: the main scraper's search goes
    # through Google and found nothing in the live test (2026-10-14); the hashtag scraper's keyword mode did
    queries = list(dict.fromkeys(sum(_queries(ctx), [])))
    runs: list[Run] = [({"hashtags": queries, "keywordSearch": True, "resultsType": "posts", "resultsLimit": n},
                        n * len(queries), ", ".join(queries))] if queries else []
    return _run("instagram", name, report, runs, _instagram_post, actor=s.apify_actor_instagram_posts)


def _instagram_profile(p: dict) -> SocialItem | None:
    username = p.get("username")
    if not username:
        return None
    url = p.get("url") or f"https://www.instagram.com/{username}/"
    return SocialItem(
        platform="Instagram", content_type="account", url=url, item_id=username, title=p.get("fullName") or username,
        text=" ".join(x for x in (p.get("biography"), p.get("externalUrl")) if x), author=p.get("fullName") or username,
        author_handle=username, author_url=url, author_id=p.get("id"),
        thumbnail_url=p.get("profilePicUrlHD") or p.get("profilePicUrl"),
        metrics={"Followers": p.get("followersCount"), "Posts": p.get("postsCount"), "Verified": p.get("verified")},
        discovery="Apify (Instagram)", structured=True,
        raw=_author(p.get("profilePicUrlHD") or p.get("profilePicUrl"), p.get("followersCount"),
                    p.get("biography"), p.get("verified")))


def instagram_profiles(ctx: BrandContext, report: ScanReport) -> list[SocialItem]:
    name = PROFILE_COMPONENT["instagram"]
    if not _enabled("instagram", report, name):
        return []
    brand, _ = _queries(ctx)
    runs: list[Run] = [({"search": ", ".join(brand), "searchType": "user", "searchLimit": PROFILES_PER_TERM,
                         "resultsType": "details", "resultsLimit": 1},
                        PROFILES_PER_TERM * len(brand), ", ".join(brand))]
    return _run("instagram", name, report, runs, _instagram_profile)


# ------------------------------------------------------------------------------------------------ TikTok
def _tiktok_video(v: dict) -> SocialItem | None:
    url = v.get("webVideoUrl") or v.get("submittedVideoUrl")
    if not url:
        return None
    a = v.get("authorMeta") or {}
    handle = a.get("name")
    return SocialItem(
        platform="TikTok", content_type="video", url=url, item_id=v.get("id"), title=(v.get("text") or "")[:120],
        text=v.get("text") or "", author=a.get("nickName") or handle, author_handle=handle, author_id=a.get("id"),
        author_url=a.get("profileUrl") or (f"https://www.tiktok.com/@{handle}" if handle else None),
        published=_iso(v.get("createTimeISO") or v.get("createTime")),
        thumbnail_url=(v.get("videoMeta") or {}).get("coverUrl"),
        metrics={"Views": v.get("playCount"), "Likes": v.get("diggCount"), "Comments": v.get("commentCount"),
                 "Shares": v.get("shareCount")},
        discovery="Apify (TikTok)", structured=True, query=v.get("searchQuery"),
        raw=_author(a.get("avatar"), a.get("fans"), a.get("signature"), a.get("verified")))


def tiktok(ctx: BrandContext, report: ScanReport) -> list[SocialItem]:
    name = COMPONENT["tiktok"]
    if not _enabled("tiktok", report, name):
        return []
    n = get_settings().apify_items_per_query
    queries = list(dict.fromkeys(sum(_queries(ctx), [])))
    runs: list[Run] = [({"searchQueries": queries, "searchSection": "/video", "resultsPerPage": n},
                        n * len(queries), ", ".join(queries))]
    return _run("tiktok", name, report, runs, _tiktok_video)


def _tiktok_profile(raw: dict) -> SocialItem | None:
    a = raw.get("authorMeta") or raw
    handle = a.get("name") or a.get("uniqueId") or a.get("username")
    if not handle:
        return None
    url = a.get("profileUrl") or f"https://www.tiktok.com/@{handle}"
    nick = a.get("nickName") or a.get("nickname") or handle
    return SocialItem(
        platform="TikTok", content_type="account", url=url, item_id=handle, title=nick,
        text=" ".join(x for x in (a.get("signature"), a.get("bioLink")) if isinstance(x, str) and x),
        author=nick, author_handle=handle, author_url=url, author_id=a.get("id"), thumbnail_url=a.get("avatar"),
        metrics={"Followers": a.get("fans"), "Videos": a.get("video"), "Verified": a.get("verified")},
        discovery="Apify (TikTok)", structured=True,
        raw=_author(a.get("avatar"), a.get("fans"), a.get("signature"), a.get("verified")))


def tiktok_profiles(ctx: BrandContext, report: ScanReport) -> list[SocialItem]:
    name = PROFILE_COMPONENT["tiktok"]
    if not _enabled("tiktok", report, name):
        return []
    brand, _ = _queries(ctx)
    runs: list[Run] = [({"searchQueries": brand, "searchSection": "/user", "maxProfilesPerQuery": PROFILES_PER_TERM,
                         "resultsPerPage": PROFILES_PER_TERM}, PROFILES_PER_TERM * len(brand), ", ".join(brand))]
    items = _run("tiktok", name, report, runs, _tiktok_profile)
    return list({i.key: i for i in items}.values())


# ------------------------------------------------------------------------------------------------ Facebook posts
def _fb_thumbnail(attachments: list) -> str | None:
    for a in attachments or []:
        if not isinstance(a, dict):
            continue
        img = _first(a.get("thumbnail"), (a.get("image") or {}).get("uri") if isinstance(a.get("image"), dict) else
                     a.get("image"), (a.get("photo_image") or {}).get("uri"),
                     a.get("url") if a.get("type") == "photo" else None)  # scraper_one: {"type": "photo", "url": …}
        if img:
            return img
    return None


def _facebook_post(p: dict) -> SocialItem | None:
    url = p.get("url")
    if not url:
        return None
    a = p.get("author") or {}
    text = p.get("postText") or ""
    shared = p.get("sharedPost") or {}
    if shared.get("postText"):
        text = f"{text}\n{shared['postText']}".strip()
    attachments = p.get("attachments") or []
    video = any(isinstance(x, dict) and "video" in str(x.get("type", "")).lower() for x in attachments) \
        or "/videos/" in url or "/reel/" in url
    profile = a.get("profileUrl")
    handle = social_handle(profile) if profile else None
    if handle in ("profile.php", "people", ""):
        handle = None
    return SocialItem(
        platform="Facebook", content_type="video" if video else "post", url=url, item_id=p.get("postId"),
        title=text[:120], text=text, author=a.get("name"), author_handle=handle or a.get("id"), author_id=a.get("id"),
        author_url=profile, published=_iso(p.get("timestamp")), thumbnail_url=_fb_thumbnail(attachments),
        metrics={"Likes": p.get("reactionsCount"), "Comments": p.get("commentsCount"), "Shares": p.get("sharesCount")},
        discovery="Apify (Facebook)", structured=True, raw=_author(a.get("profilePicture")))


def facebook(ctx: BrandContext, report: ScanReport) -> list[SocialItem]:
    name = COMPONENT["facebook"]
    if not _enabled("facebook", report, name):
        return []
    s = get_settings()
    n = s.apify_items_per_query
    brand, scam = _queries(ctx)
    runs: list[Run] = [({"query": q, "resultsCount": n, "searchType": "latest",
                         "startDate": _day(s.social_media_lookback_days)}, n, q) for q in brand]
    runs += [({"query": q, "resultsCount": n, "searchType": "top"}, n, q) for q in scam]
    return _run("facebook", name, report, runs, _facebook_post)


# ------------------------------------------------------------------------------------------------ Meta ads
def _meta_ad(ad: dict) -> SocialItem | None:
    ad_id = _first(ad.get("adArchiveID"), ad.get("adArchiveId"), ad.get("adId"))
    if not ad_id:
        return None
    snap = ad.get("snapshot") or {}
    cards = [c for c in snap.get("cards") or [] if isinstance(c, dict)]
    body = (snap.get("body") or {}).get("text") if isinstance(snap.get("body"), dict) else snap.get("body")
    texts = [body, snap.get("title"), snap.get("caption"), snap.get("linkDescription"), snap.get("linkUrl"),
             *[x for c in cards for x in (c.get("body"), c.get("title"), c.get("linkUrl"))]]
    text = " ".join(dict.fromkeys(str(t) for t in texts if t))
    images = [i for i in snap.get("images") or [] if isinstance(i, dict)]
    videos = [v for v in snap.get("videos") or [] if isinstance(v, dict)]
    thumb = _first(*(i.get("originalImageUrl") or i.get("resizedImageUrl") for i in images),
                   *(v.get("videoPreviewImageUrl") for v in videos),
                   *(c.get("originalImageUrl") or c.get("resizedImageUrl") or c.get("videoPreviewImageUrl")
                     for c in cards))
    page = _first(ad.get("pageName"), snap.get("pageName"))
    page_id = _first(ad.get("pageID"), ad.get("pageId"), snap.get("pageId"))
    platforms = ", ".join(str(p).title() for p in ad.get("publisherPlatform") or [])
    return SocialItem(
        platform="Meta Ads", content_type="ad", url=f"https://www.facebook.com/ads/library/?id={ad_id}",
        item_id=str(ad_id), title=_first(snap.get("title"), (body or "")[:120], f"Ad by {page}"), text=text,
        author=page, author_id=str(page_id) if page_id else None,
        author_url=_first(snap.get("pageProfileUri"), f"https://www.facebook.com/{page_id}" if page_id else None),
        published=_iso(_first(ad.get("startDateFormatted"), ad.get("startDate"))), thumbnail_url=thumb,
        metrics={"Shown On": platforms or None, "Active": ad.get("isActive"),
                 "Stopped": _iso(_first(ad.get("endDateFormatted"), ad.get("endDate"))) if not ad.get("isActive")
                 else None},
        discovery="Apify (Meta Ad Library)", structured=True,
        raw=_author(snap.get("pageProfilePictureUrl"), snap.get("pageLikeCount")))


def meta_ads(ctx: BrandContext, report: ScanReport) -> list[SocialItem]:
    name = COMPONENT["meta_ads"]
    if not _enabled("meta_ads", report, name):
        return []
    s = get_settings()
    n = s.apify_items_per_query
    brand, _ = _queries(ctx)
    urls = [{"url": "https://www.facebook.com/ads/library/?active_status=all&ad_type=all"
                    f"&country={c}&q={quote(t)}&search_type=keyword_unordered&media_type=all"}
            for t in brand for c in (s.meta_ad_countries or ["IN"])]
    runs: list[Run] = [({"startUrls": urls, "resultsLimit": n, "onlyAdsNewerThan": _day(s.social_media_lookback_days)},
                        n * len(urls), ", ".join(brand))]
    return _run("meta_ads", name, report, runs, _meta_ad)


# ------------------------------------------------------------------------------------------------ X
def _tweet(t: dict) -> SocialItem | None:
    tid = t.get("id")
    if not tid or t.get("type") not in (None, "tweet"):
        return None
    a = t.get("author") or {}
    handle = a.get("userName")
    media = ((t.get("extendedEntities") or {}).get("media") or []) if isinstance(t.get("extendedEntities"), dict) \
        else []
    m = media[0] if media and isinstance(media[0], dict) else {}
    return SocialItem(
        platform="X", content_type="video" if m.get("type") in ("video", "animated_gif") else "post",
        url=t.get("url") or f"https://x.com/{handle or 'i'}/status/{tid}", item_id=str(tid),
        title=(t.get("text") or "")[:120], text=t.get("text") or "", author=a.get("name"), author_handle=handle,
        author_id=a.get("id"), author_url=f"https://x.com/{handle}" if handle else None,
        published=_iso(t.get("createdAt")), thumbnail_url=m.get("media_url_https"),
        metrics={"Likes": t.get("likeCount"), "Reposts": t.get("retweetCount"), "Comments": t.get("replyCount"),
                 "Views": t.get("viewCount")},
        discovery="Apify (X)", structured=True, query=t.get("searchTerm"),
        raw=_author(a.get("profilePicture"), a.get("followers"), a.get("description"),
                    a.get("isVerified") or a.get("isBlueVerified")))


def x_posts(ctx: BrandContext, report: ScanReport) -> list[SocialItem]:
    name = COMPONENT["x"]
    if not _enabled("x", report, name):
        return []
    s = get_settings()
    n = s.apify_items_per_query
    brand, scam = _queries(ctx)
    runs: list[Run] = []
    for queries, days in ((brand, s.social_media_lookback_days), (scam, s.social_media_scam_lookback_days)):
        terms = [f'"{q}" -filter:retweets' for q in queries]
        if terms:
            runs.append(({"searchTerms": terms, "maxItems": n * len(terms), "sort": "Latest", "start": _day(days),
                          "includeSearchTerms": True}, n * len(terms), ", ".join(queries)))
    return _run("x", name, report, runs, _tweet)


# ------------------------------------------------------------------------------------------------ LinkedIn
def _linkedin_post(p: dict) -> SocialItem | None:
    url = p.get("linkedinUrl") or (p.get("socialContent") or {}).get("shareUrl")
    if not url or p.get("type") not in (None, "post"):
        return None
    a = p.get("author") or {}
    handle = a.get("publicIdentifier") or a.get("universalName")
    eng = p.get("engagement") or {}
    images = [i for i in p.get("postImages") or [] if isinstance(i, dict)]
    avatar = (a.get("avatar") or {}).get("url") if isinstance(a.get("avatar"), dict) else a.get("avatar")
    text = p.get("content") or ""
    return SocialItem(
        platform="LinkedIn", content_type="post", url=url, item_id=p.get("id"), title=text[:120], text=text,
        author=a.get("name"), author_handle=handle, author_url=a.get("linkedinUrl"),
        published=_iso((p.get("postedAt") or {}).get("date") or (p.get("postedAt") or {}).get("timestamp")),
        thumbnail_url=images[0].get("url") if images else None,
        metrics={"Likes": eng.get("likes"), "Comments": eng.get("comments"), "Shares": eng.get("shares")},
        discovery="Apify (LinkedIn)", structured=True, raw=_author(avatar, None, a.get("info")))


def linkedin(ctx: BrandContext, report: ScanReport) -> list[SocialItem]:
    name = COMPONENT["linkedin"]
    if not _enabled("linkedin", report, name):
        return []
    s = get_settings()
    n = s.apify_items_per_query
    brand, scam = _queries(ctx)
    recent = "week" if s.social_media_lookback_days <= 7 else "month" if s.social_media_lookback_days <= 31 else "year"
    runs: list[Run] = [({"searchQueries": q, "maxPosts": n, "postedLimit": limit, "sortBy": "date"}, n * len(q),
                        ", ".join(q)) for q, limit in ((brand, recent), (scam, "year")) if q]
    return _run("linkedin", name, report, runs, _linkedin_post)


# ------------------------------------------------------------------------------------------------ entry points
CONTENT_SOURCES = (instagram, tiktok, facebook, meta_ads, x_posts, linkedin)


def content_items(ctx: BrandContext, report: ScanReport,
                  sources: tuple[Callable[[BrandContext, ScanReport], list[SocialItem]], ...] = CONTENT_SOURCES
                  ) -> list[SocialItem]:
    items: list[SocialItem] = []
    for source in sources:
        try:
            items += source(ctx, report)
        except Exception as exc:  # noqa: BLE001 - one broken actor must not stop the others
            report.failed(f"Apify {source.__name__}", f"{type(exc).__name__}: {exc}"[:300])
            log.exception("apify_source_failed", source=source.__name__)
    return items
