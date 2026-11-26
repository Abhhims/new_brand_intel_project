"""Where social media content comes from: official APIs when a key is configured, site-restricted web search always.

Every source reports its own scan component (D-31): "not configured" without a key, "unavailable"/"failed" when the
service could not be reached — never an empty "nothing found". Keys are sent in headers, never in logged URLs.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode

import structlog

from app.config import get_settings
from app.core import search
from app.core.fetch import FetchError, fetch
from app.modules.base import BrandContext, ScanReport
from app.modules.common import report_search_failure
from app.modules.social_media.analysis import content_type_of, platform_of

log = structlog.get_logger(__name__)

YOUTUBE = "YouTube API"
META_ADS = "Meta Ad Library"
FB_PAGES = "Facebook Pages API"
FB_MAX_PAGES = 15          # pages whose details and recent posts are read per brand
FB_POSTS_PER_PAGE = 10
THREADS = "Threads API"
X_API = "X API"
TELEGRAM = "Telegram post search"
GRAPH_VERSION = "v23.0"


@dataclass
class SocialItem:
    platform: str
    content_type: str              # video | post | ad | channel | account
    url: str
    item_id: str | None = None
    title: str = ""
    text: str = ""
    author: str | None = None
    author_handle: str | None = None
    author_url: str | None = None
    author_id: str | None = None
    published: str | None = None
    thumbnail_url: str | None = None
    metrics: dict = field(default_factory=dict)
    discovery: str = "web search"
    structured: bool = False       # came from an official API with full fields
    raw: dict = field(default_factory=dict)
    query: str | None = None       # the search that found it

    @property
    def key(self) -> str:
        ident = (self.item_id or re.sub(r"[?#].*$", "", self.url).rstrip("/")).lower()
        return f"{self.platform.lower()}:{self.content_type}:{ident}"[:1000]


def _since(days: int) -> datetime:
    return datetime.now(UTC) - timedelta(days=days)


def _get_json(url: str, headers: dict[str, str]) -> tuple[int, dict]:
    r = fetch(url, headers={"Accept": "application/json", **headers})
    try:
        data = json.loads(r.content or b"{}")
    except ValueError:
        data = {}
    return r.status, data


def _api_error(data: dict) -> str:
    err = data.get("error") if isinstance(data, dict) else None
    if isinstance(err, dict):
        return str(err.get("message") or err.get("status") or err)[:200]
    return str(data.get("title") or data.get("detail") or data)[:200] if isinstance(data, dict) else str(data)[:200]


# ---------------------------------------------------------------------------------------------------- YouTube
def youtube(ctx: BrandContext, report: ScanReport) -> list[SocialItem]:
    s = get_settings()
    if not s.youtube_api_key:
        report.not_configured(YOUTUBE, "YOUTUBE_API_KEY not set")
        return []
    headers = {"X-goog-api-key": s.youtube_api_key}
    base = "https://www.googleapis.com/youtube/v3/"
    after = _since(s.social_media_lookback_days).strftime("%Y-%m-%dT%H:%M:%SZ")
    scam_after = _since(s.social_media_scam_lookback_days).strftime("%Y-%m-%dT%H:%M:%SZ")
    before = None
    if ctx.date_from:  # the scan's own date range (D-50) replaces the default look-back window
        after = scam_after = f"{ctx.date_from:%Y-%m-%d}T00:00:00Z"
    if ctx.date_to:
        before = f"{ctx.date_to:%Y-%m-%d}T23:59:59Z"
    video_ids: list[str] = []
    found_by: dict[str, str] = {}
    channel_ids: list[str] = []
    # 1) newest videos naming the brand; 2) scam-shaped searches ("<brand> customer care number"…), most relevant
    #    first and over a longer window — fraud videos are rarely the newest and often months old
    searches = [(t, "date", after) for t in ctx.terms[:2]]
    searches += [(q.replace("{brand}", scam_base(ctx)), "relevance", scam_after) for q in s.social_media_scam_queries]
    try:
        for q, order, since in searches:
            status, data = _get_json(base + "search?" + urlencode({
                "part": "snippet", "q": q, "type": "video", "order": order, "publishedAfter": since,
                **({"publishedBefore": before} if before else {}), "maxResults": 50, "regionCode": "IN"}), headers)
            if status != 200:
                report.failed(YOUTUBE, f"video search '{q}' HTTP {status}: {_api_error(data)}")
                if status in (401, 403):
                    return []  # bad key or quota exhausted: the remaining searches fail the same way
                continue
            for i in data.get("items", []):
                vid = i.get("id", {}).get("videoId")
                if vid:
                    video_ids.append(vid)
                    found_by.setdefault(vid, q)
        status, data = _get_json(base + "search?" + urlencode({
            "part": "snippet", "q": ctx.name, "type": "channel", "maxResults": 15}), headers)
        if status == 200:
            channel_ids = [i["id"]["channelId"] for i in data.get("items", []) if i.get("id", {}).get("channelId")]
        else:
            report.failed(YOUTUBE, f"channel search HTTP {status}: {_api_error(data)}")
        out: list[SocialItem] = []
        video_ids = list(dict.fromkeys(video_ids))
        for chunk in (video_ids[i:i + 50] for i in range(0, len(video_ids), 50)):
            status, data = _get_json(base + "videos?" + urlencode({"part": "snippet,statistics",
                                                                    "id": ",".join(chunk)}), headers)
            if status != 200:
                report.failed(YOUTUBE, f"video details HTTP {status}: {_api_error(data)}")
                continue
            for v in data.get("items", []):
                sn, st = v.get("snippet", {}), v.get("statistics", {})
                thumbs = sn.get("thumbnails", {})
                out.append(SocialItem(
                    platform="YouTube", content_type="video", url=f"https://www.youtube.com/watch?v={v['id']}",
                    item_id=v["id"], title=sn.get("title", ""), text=sn.get("description", ""),
                    author=sn.get("channelTitle"), author_id=sn.get("channelId"),
                    author_url=f"https://www.youtube.com/channel/{sn.get('channelId')}",
                    published=sn.get("publishedAt"),
                    thumbnail_url=(thumbs.get("high") or thumbs.get("medium") or thumbs.get("default") or {}).get("url"),
                    metrics={"Views": st.get("viewCount"), "Likes": st.get("likeCount"),
                             "Comments": st.get("commentCount")},
                    discovery="YouTube Data API", structured=True, raw={"tags": sn.get("tags", [])[:30]},
                    query=found_by.get(v["id"])))
        # Video results only carry a channel id: look up each uploader's @handle so the brand's official channels
        # (allowlisted by handle or id) are recognised and skipped
        uploaders = list(dict.fromkeys(i.author_id for i in out if i.author_id))[:50]
        if uploaders:
            status, data = _get_json(base + "channels?" + urlencode({"part": "snippet", "id": ",".join(uploaders)}),
                                     headers)
            handles = {c["id"]: (c.get("snippet", {}).get("customUrl") or "").lstrip("@") or None
                       for c in data.get("items", [])} if status == 200 else {}
            for i in out:
                i.author_handle = handles.get(i.author_id) or i.author_handle
                if i.author_handle:
                    i.author_url = f"https://www.youtube.com/@{i.author_handle}"
        if channel_ids:
            status, data = _get_json(base + "channels?" + urlencode({"part": "snippet,statistics",
                                                                      "id": ",".join(channel_ids)}), headers)
            if status == 200:
                for c in data.get("items", []):
                    sn, st = c.get("snippet", {}), c.get("statistics", {})
                    handle = (sn.get("customUrl") or "").lstrip("@") or None
                    out.append(SocialItem(
                        platform="YouTube", content_type="channel",
                        url=f"https://www.youtube.com/{'@' + handle if handle else 'channel/' + c['id']}",
                        item_id=c["id"], title=sn.get("title", ""), text=sn.get("description", ""),
                        author=sn.get("title"), author_handle=handle, author_id=c["id"],
                        published=sn.get("publishedAt"),
                        thumbnail_url=(sn.get("thumbnails", {}).get("high") or sn.get("thumbnails", {}).get("default")
                                       or {}).get("url"),
                        metrics={"Subscribers": st.get("subscriberCount"), "Videos": st.get("videoCount"),
                                 "Views": st.get("viewCount")},
                        discovery="YouTube Data API", structured=True))
            else:
                report.failed(YOUTUBE, f"channel details HTTP {status}: {_api_error(data)}")
    except FetchError as exc:
        report.unavailable(YOUTUBE, f"YouTube API unreachable: {exc}")
        return []
    report.ok(YOUTUBE, videos=len(video_ids), channels=len(channel_ids))
    return out


def scam_base(ctx: BrandContext) -> str:
    """The name scammers use: the shortest distinctive brand term (e.g. 'Navi' rather than 'Navi Private Limited')."""
    return min(ctx.terms[:3] or [ctx.name], key=len)


# ---------------------------------------------------------------------------------------------------- Meta ads
def meta_ads(ctx: BrandContext, report: ScanReport) -> list[SocialItem]:
    s = get_settings()
    token = s.meta_ad_library_token or s.meta_graph_token  # one identity-verified user token can serve both
    if not token:
        report.not_configured(META_ADS, "META_AD_LIBRARY_TOKEN (or META_GRAPH_TOKEN) not set")
        return []
    out: list[SocialItem] = []
    fields = ("id,page_id,page_name,ad_creative_bodies,ad_creative_link_titles,ad_creative_link_captions,"
              "ad_creative_link_descriptions,ad_delivery_start_time,ad_delivery_stop_time,publisher_platforms")
    try:
        for term in ctx.terms[:2]:
            url = f"https://graph.facebook.com/{GRAPH_VERSION}/ads_archive?" + urlencode({
                "search_terms": term, "ad_type": "ALL", "ad_active_status": "ALL",
                "ad_reached_countries": json.dumps(s.meta_ad_countries), "fields": fields, "limit": 50,
                "ad_delivery_date_min": _since(s.social_media_lookback_days).strftime("%Y-%m-%d")})
            status, data = _get_json(url, {"Authorization": f"Bearer {token}"})
            if status != 200:
                report.failed(META_ADS, f"HTTP {status}: {_api_error(data)}")
                return out
            for ad in data.get("data", []):
                bodies = " ".join(ad.get("ad_creative_bodies") or [])
                titles = " ".join(ad.get("ad_creative_link_titles") or [])
                platforms = ", ".join(p.title() for p in ad.get("publisher_platforms") or [])
                out.append(SocialItem(
                    platform="Meta Ads", content_type="ad",
                    url=f"https://www.facebook.com/ads/library/?id={ad['id']}", item_id=ad["id"],
                    title=titles or (bodies[:120] if bodies else f"Ad by {ad.get('page_name')}"),
                    text=" ".join([bodies, " ".join(ad.get("ad_creative_link_captions") or []),
                                   " ".join(ad.get("ad_creative_link_descriptions") or [])]),
                    author=ad.get("page_name"), author_id=ad.get("page_id"),
                    author_url=f"https://www.facebook.com/{ad.get('page_id')}" if ad.get("page_id") else None,
                    published=ad.get("ad_delivery_start_time"),
                    metrics={"Shown On": platforms or None, "Stopped": ad.get("ad_delivery_stop_time")},
                    discovery="Meta Ad Library API", structured=True))
    except FetchError as exc:
        report.unavailable(META_ADS, f"Meta Ad Library unreachable: {exc}")
        return out
    report.ok(META_ADS, ads=len(out))
    return out


# ---------------------------------------------------------------------------------------------------- Facebook
def _graph_token() -> str | None:
    s = get_settings()
    if s.meta_graph_token:
        return s.meta_graph_token
    if s.meta_app_id and s.meta_app_secret:
        return f"{s.meta_app_id}|{s.meta_app_secret}"  # app access token
    return None


def facebook_pages(ctx: BrandContext, report: ScanReport) -> list[SocialItem]:
    """Pages Search API: Facebook Pages named like the brand, their details (phone, website, about) and recent
    public posts. Needs the app's 'Page Public Content Access' feature; Meta's error is reported as-is if not."""
    token = _graph_token()
    if not token:
        report.not_configured(FB_PAGES, "META_APP_ID / META_APP_SECRET not set")
        return []
    headers = {"Authorization": f"Bearer {token}"}
    graph = f"https://graph.facebook.com/{GRAPH_VERSION}/"
    since = _since(get_settings().social_media_lookback_days)
    out: list[SocialItem] = []
    try:
        page_ids: list[str] = []
        for term in list(dict.fromkeys([ctx.name, *ctx.terms[:2]])):
            status, data = _get_json(graph + "pages/search?" + urlencode({
                "q": term, "fields": "id,name,link,verification_status", "limit": 25}), headers)
            if status != 200:
                report.failed(FB_PAGES, f"page search HTTP {status}: {_api_error(data)}")
                return out
            page_ids += [p["id"] for p in data.get("data", []) if p.get("id")]
        page_ids = list(dict.fromkeys(page_ids))[:FB_MAX_PAGES]
        fields = ("id,name,username,link,about,description,category,fan_count,followers_count,website,phone,emails,"
                  "verification_status,picture.type(large){url}")
        for pid in page_ids:
            status, p = _get_json(graph + pid + "?" + urlencode({"fields": fields}), headers)
            if status != 200:
                report.failed(FB_PAGES, f"page {pid} HTTP {status}: {_api_error(p)}")
                continue
            handle = p.get("username") or pid
            contact = " ".join(x for x in [p.get("phone") or "", " ".join(p.get("emails") or []),
                                           p.get("website") or ""] if x)
            out.append(SocialItem(
                platform="Facebook", content_type="account", url=p.get("link") or f"https://www.facebook.com/{pid}",
                item_id=pid, title=p.get("name", ""),
                text=" ".join(x for x in [p.get("about"), p.get("description"), p.get("category"), contact] if x),
                author=p.get("name"), author_handle=handle, author_id=pid,
                author_url=p.get("link") or f"https://www.facebook.com/{pid}",
                thumbnail_url=((p.get("picture") or {}).get("data") or {}).get("url"),
                metrics={"Followers": p.get("followers_count") or p.get("fan_count"),
                         "Verified": p.get("verification_status"), "Category": p.get("category"),
                         "Listed Phone": p.get("phone"), "Website": p.get("website")},
                discovery="Facebook Pages API", structured=True))
            status, posts = _get_json(graph + pid + "/posts?" + urlencode({
                "fields": "id,message,permalink_url,created_time,full_picture", "limit": FB_POSTS_PER_PAGE,
                "since": int(since.timestamp())}), headers)
            if status != 200:
                report.failed(FB_PAGES, f"posts of {pid} HTTP {status}: {_api_error(posts)}")
                continue
            for post in posts.get("data", []):
                if not post.get("message") or not post.get("permalink_url"):
                    continue
                out.append(SocialItem(
                    platform="Facebook", content_type="post", url=post["permalink_url"], item_id=post["id"],
                    title=post["message"][:120], text=post["message"], author=p.get("name"), author_handle=handle,
                    author_id=pid, author_url=p.get("link"), published=post.get("created_time"),
                    thumbnail_url=post.get("full_picture"), discovery="Facebook Pages API", structured=True))
    except FetchError as exc:
        report.unavailable(FB_PAGES, f"Facebook Graph API unreachable: {exc}")
        return out
    report.ok(FB_PAGES, pages=sum(1 for i in out if i.content_type == "account"),
              posts=sum(1 for i in out if i.content_type == "post"))
    return out


# ---------------------------------------------------------------------------------------------------- Threads
def threads(ctx: BrandContext, report: ScanReport) -> list[SocialItem]:
    s = get_settings()
    if not s.threads_access_token:
        report.not_configured(THREADS, "THREADS_ACCESS_TOKEN not set")
        return []
    out: list[SocialItem] = []
    try:
        for term in ctx.terms[:2]:
            url = "https://graph.threads.net/v1.0/keyword_search?" + urlencode({
                "q": term, "search_type": "RECENT",
                "fields": "id,text,media_type,permalink,timestamp,username,thumbnail_url,media_url"})
            status, data = _get_json(url, {"Authorization": f"Bearer {s.threads_access_token}"})
            if status != 200:
                report.failed(THREADS, f"HTTP {status}: {_api_error(data)}")
                return out
            for p in data.get("data", []):
                if not p.get("permalink"):
                    continue
                out.append(SocialItem(
                    platform="Threads", content_type="video" if p.get("media_type") == "VIDEO" else "post",
                    url=p["permalink"], item_id=p.get("id"), title=(p.get("text") or "")[:120], text=p.get("text") or "",
                    author=p.get("username"), author_handle=p.get("username"),
                    author_url=f"https://www.threads.net/@{p.get('username')}" if p.get("username") else None,
                    published=p.get("timestamp"), thumbnail_url=p.get("thumbnail_url") or p.get("media_url"),
                    discovery="Threads API", structured=True))
    except FetchError as exc:
        report.unavailable(THREADS, f"Threads API unreachable: {exc}")
        return out
    report.ok(THREADS, posts=len(out))
    return out


# ---------------------------------------------------------------------------------------------------- X
def x_posts(ctx: BrandContext, report: ScanReport) -> list[SocialItem]:
    s = get_settings()
    if not s.x_bearer_token:
        report.not_configured(X_API, "X_BEARER_TOKEN not set")
        return []
    query = "(" + " OR ".join(f'"{t}"' for t in ctx.terms[:3]) + ") -is:retweet"
    url = "https://api.x.com/2/tweets/search/recent?" + urlencode({
        "query": query[:512], "max_results": 25, "tweet.fields": "created_at,public_metrics,author_id",
        "expansions": "author_id,attachments.media_keys", "user.fields": "username,name,profile_image_url",
        "media.fields": "preview_image_url,url,type"})
    try:
        status, data = _get_json(url, {"Authorization": f"Bearer {s.x_bearer_token}"})
    except FetchError as exc:
        report.unavailable(X_API, f"X API unreachable: {exc}")
        return []
    if status != 200:
        report.failed(X_API, f"HTTP {status}: {_api_error(data)}")
        return []
    users = {u["id"]: u for u in data.get("includes", {}).get("users", [])}
    media = {m["media_key"]: m for m in data.get("includes", {}).get("media", [])}
    out = []
    for t in data.get("data", []):
        u = users.get(t.get("author_id"), {})
        keys = (t.get("attachments") or {}).get("media_keys") or []
        m = media.get(keys[0], {}) if keys else {}
        pm = t.get("public_metrics") or {}
        username = u.get("username") or "i"
        out.append(SocialItem(
            platform="X", content_type="video" if m.get("type") == "video" else "post",
            url=f"https://x.com/{username}/status/{t['id']}", item_id=t["id"], title=t.get("text", "")[:120],
            text=t.get("text", ""), author=u.get("name"), author_handle=u.get("username"),
            author_url=f"https://x.com/{username}", published=t.get("created_at"),
            thumbnail_url=m.get("preview_image_url") or m.get("url"),
            metrics={"Likes": pm.get("like_count"), "Reposts": pm.get("retweet_count"),
                     "Comments": pm.get("reply_count"), "Views": pm.get("impression_count")},
            discovery="X API", structured=True))
    report.ok(X_API, posts=len(out))
    return out


# ---------------------------------------------------------------------------------------------------- Telegram
def telegram_posts(ctx: BrandContext, report: ScanReport) -> list[SocialItem]:
    s = get_settings()
    if not (s.telegram_api_id and s.telegram_api_hash and s.telegram_session):
        report.not_configured(TELEGRAM, "TELEGRAM_API_ID / TELEGRAM_API_HASH / TELEGRAM_SESSION not set")
        return []
    out: list[SocialItem] = []
    try:
        from telethon.sessions import StringSession
        from telethon.sync import TelegramClient
        from telethon.tl.functions.messages import SearchGlobalRequest
        from telethon.tl.types import InputMessagesFilterEmpty, InputPeerEmpty

        with TelegramClient(StringSession(s.telegram_session), s.telegram_api_id, s.telegram_api_hash) as client:
            for term in ctx.terms[:2]:
                res = client(SearchGlobalRequest(q=term, filter=InputMessagesFilterEmpty(), min_date=None,
                                                 max_date=None, offset_rate=0, offset_peer=InputPeerEmpty(),
                                                 offset_id=0, limit=50, broadcasts_only=True))
                chats = {c.id: c for c in res.chats}
                for msg in res.messages:
                    chat = chats.get(getattr(getattr(msg, "peer_id", None), "channel_id", None))
                    username = getattr(chat, "username", None)
                    if not username or not getattr(msg, "message", None):
                        continue
                    out.append(SocialItem(
                        platform="Telegram", content_type="post", url=f"https://t.me/{username}/{msg.id}",
                        item_id=f"{username}/{msg.id}", title=msg.message[:120], text=msg.message,
                        author=getattr(chat, "title", username), author_handle=username,
                        author_url=f"https://t.me/{username}",
                        published=msg.date.isoformat() if getattr(msg, "date", None) else None,
                        metrics={"Views": getattr(msg, "views", None)}, discovery="Telegram API", structured=True))
    except Exception as exc:  # noqa: BLE001
        report.failed(TELEGRAM, f"search failed: {type(exc).__name__}: {exc}")
        return out
    report.ok(TELEGRAM, posts=len(out))
    return out


# ---------------------------------------------------------------------------------------------------- web search
# Platforms without a usable official search API are found through site-restricted web search.
SITE_GROUPS = [
    ["instagram.com", "facebook.com", "threads.net"],
    ["tiktok.com", "pinterest.com", "linkedin.com/posts"],
]
SCAM_QUERY = '(whatsapp OR "customer care" OR helpline OR "kyc" OR refund)'
# Accounts on these platforms are already monitored by the impersonation module (`social`): only content here
ACCOUNTS_ELSEWHERE = {"X", "Facebook", "Instagram", "LinkedIn", "Telegram"}


def web_search(ctx: BrandContext, report: ScanReport) -> list[SocialItem]:
    s = get_settings()
    terms = "(" + " OR ".join(f'"{t}"' for t in ctx.terms[:3]) + ")"
    groups = list(SITE_GROUPS)
    if not s.youtube_api_key:
        groups.append(["youtube.com"])
    if not s.x_bearer_token:
        groups.append(["x.com", "twitter.com"])
    queries = [f"({' OR '.join('site:' + d for d in g)}) {terms}" for g in groups]
    queries.append(f"(site:facebook.com OR site:instagram.com OR site:youtube.com) {terms} {SCAM_QUERY}")
    component = search.component_name()
    out: dict[str, SocialItem] = {}
    for q in queries:
        try:
            results = search.search(q, count=20)
            report.ok(component, queries=1)
        except search.SearchUnavailable as exc:
            searched = any(c["name"] == component and c["counts"].get("queries") for c in report.as_list())
            report_search_failure(report, component, exc)
            if not searched:
                break  # provider down / not configured: the remaining queries would fail the same way
            continue
        for r in results:
            platform = platform_of(r.url)
            if not platform:
                continue
            ctype = content_type_of(platform, r.url)
            if ctype == "account" and platform in ACCOUNTS_ELSEWHERE:
                continue
            item = SocialItem(platform=platform, content_type=ctype, url=r.url, title=r.title, text=r.snippet,
                              discovery=f"web search ({search.provider_name()})")
            out.setdefault(item.key, item)
    return list(out.values())


def url_key(url: str) -> str:
    """The same post seen through different sources: no scheme, www./m., query or trailing slash; twitter → x."""
    u = re.sub(r"^https?://(www\.|m\.|mobile\.)?", "", url.lower())
    path, _, query = re.sub(r"#.*$", "", u).partition("?")
    path = path.rstrip("/")
    # pages identified by their query (permalink.php?story_fbid=…, ads/library/?id=…) keep it
    u = f"{path}?{query}" if query and (path.endswith(".php") or path.endswith("/ads/library")) else path
    if path.endswith("/watch"):  # youtube.com/watch?v=ID: the video id is the identity, other params are noise
        v = re.search(r"(?:^|&)v=([\w-]+)", query)
        u = f"{path}?v={v.group(1)}" if v else path
    return re.sub(r"^twitter\.com/", "x.com/", u)


def all_items(ctx: BrandContext, report: ScanReport) -> list[SocialItem]:
    from app.modules.social_media import apify_sources

    items: list[SocialItem] = []
    for source in (youtube, meta_ads, facebook_pages, threads, x_posts, telegram_posts):
        try:
            items += source(ctx, report)
        except Exception as exc:  # noqa: BLE001 - one broken source must not stop the others
            report.failed(f"Social source {source.__name__}", f"{type(exc).__name__}: {exc}")
            log.exception("social_source_failed", source=source.__name__)
    items += apify_sources.content_items(ctx, report)  # D-43: next to the official APIs, before web search
    try:
        items += web_search(ctx, report)
    except Exception as exc:  # noqa: BLE001
        report.failed("Social source web_search", f"{type(exc).__name__}: {exc}")
        log.exception("social_source_failed", source="web_search")
    unique: dict[str, SocialItem] = {}
    seen_urls: set[str] = set()
    for it in items:
        # API and Apify items come first and win over the same post found again (e.g. by web search)
        if it.key in unique or url_key(it.url) in seen_urls:
            continue
        unique[it.key] = it
        seen_urls.add(url_key(it.url))
    return list(unique.values())
