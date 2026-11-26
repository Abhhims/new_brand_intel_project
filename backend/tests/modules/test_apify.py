"""Apify sources (D-43): the client, each platform's parser, honest status, de-duplication, impersonation profiles."""

import json

import pytest

from app.config import get_settings
from app.core import apify
from app.core.fetch import FetchResult
from app.modules.base import ScanReport
from app.modules.social import module as social
from app.modules.social_media import apify_sources as ap
from app.modules.social_media import sources
from app.modules.social_media.sources import SocialItem
from tests.modules.test_social_media import _ctx, _run

TWEET = {"type": "tweet", "id": "1799", "url": "https://x.com/zentrova_care/status/1799",
         "text": "Zentrova Bank customer care number 9876543210 call now", "likeCount": 4, "retweetCount": 1,
         "replyCount": 0, "viewCount": 120, "createdAt": "Fri Oct 10 17:49:36 +0000 2026",
         "author": {"userName": "zentrova_care", "name": "Zentrova Bank Care", "followers": 31,
                    "profilePicture": None, "description": "Official Zentrova support 24/7"}}


@pytest.fixture
def token(monkeypatch):
    monkeypatch.setattr(get_settings(), "apify_token", "apify_api_SECRET")
    monkeypatch.setattr(get_settings(), "apify_platforms", ["instagram", "tiktok", "facebook", "meta_ads", "x",
                                                            "linkedin"])


def _fake_runs(monkeypatch, items_by_actor: dict[str, list[dict]], calls: list | None = None):
    def run_many(actor, runs):
        if calls is not None:
            calls.append((actor, runs))
        return [apify.RunResult(items=items_by_actor.get(actor, [])) for _ in runs]
    monkeypatch.setattr(apify, "run_many", run_many)


@pytest.mark.req("SMM-05", "SMM-07")
def test_not_configured_and_skipped(monkeypatch):
    monkeypatch.setattr(get_settings(), "apify_token", None)
    report = ScanReport()
    assert ap.content_items(_ctx(), report) == []
    statuses = {c["name"]: c["status"] for c in report.as_list()}
    assert set(statuses) == set(ap.COMPONENT.values()) and set(statuses.values()) == {"not_configured"}

    monkeypatch.setattr(get_settings(), "apify_token", "t")
    monkeypatch.setattr(get_settings(), "apify_platforms", ["x"])
    _fake_runs(monkeypatch, {})
    report = ScanReport()
    ap.content_items(_ctx(), report)
    statuses = {c["name"]: c["status"] for c in report.as_list()}
    assert statuses["Apify X"] == "ok" and statuses["Apify Instagram"] == "skipped"


@pytest.mark.req("SMM-02", "SMM-05")
def test_client_runs_actor_with_token_in_header(monkeypatch, token):
    monkeypatch.setattr(apify, "_redis", lambda: None)
    calls = []

    def fake_fetch(url, *, method="GET", headers=None, content=None, timeout=None, **_):
        calls.append((method, url, headers, content))
        if "/runs?" in url:
            body = {"data": {"id": "run1", "status": "RUNNING", "defaultDatasetId": "ds1"}}
        elif "actor-runs/run1" in url:
            body = {"data": {"id": "run1", "status": "SUCCEEDED", "defaultDatasetId": "ds1"}}
        else:
            body = [TWEET, {"noResults": True}, {"error": "blocked", "url": "x"}]
        return FetchResult(url=url, final_url=url, status=201 if method == "POST" else 200, headers={},
                           content=json.dumps(body).encode(), peer_ip=None)

    monkeypatch.setattr(apify, "fetch", fake_fetch)
    [res] = apify.run_many("apidojo/tweet-scraper", [({"searchTerms": ["zentrova"]}, 20)])
    assert res.ok and [i["id"] for i in res.items] == ["1799"]  # placeholder and error items dropped
    start = calls[0]
    assert start[0] == "POST" and "acts/apidojo~tweet-scraper/runs?maxItems=20" in start[1]
    assert json.loads(start[3]) == {"searchTerms": ["zentrova"]}
    assert all(h["Authorization"] == "Bearer apify_api_SECRET" for _, _, h, _ in calls)
    assert all("SECRET" not in u for _, u, _, _ in calls)

    # bad token: nothing could start, the error is raised and reported as failed, not "nothing found"
    monkeypatch.setattr(apify, "fetch", lambda url, **kw: FetchResult(
        url=url, final_url=url, status=401, headers={}, peer_ip=None,
        content=json.dumps({"error": {"message": "User was not found or authentication token is not valid"}}).encode()))
    report = ScanReport()
    assert ap.x_posts(_ctx(), report) == []
    c = report.as_list()[0]
    assert c["status"] == "failed" and "token is not valid" in c["message"]


@pytest.mark.req("SMM-02", "SMM-07")
def test_parsers_for_every_platform(monkeypatch, token):
    _fake_runs(monkeypatch, {
        "apify/instagram-hashtag-scraper": [{"shortCode": "C1", "url": "https://www.instagram.com/p/C1/", "type": "Video",
                                     "caption": "Zentrova loan helpline 9876543210", "ownerUsername": "zen_help",
                                     "likesCount": 9, "videoViewCount": 500, "timestamp": "2026-10-01T10:00:00.000Z",
                                     "displayUrl": "https://cdn.example/c1.jpg"}],
        "clockworks/tiktok-scraper": [{"id": "77", "webVideoUrl": "https://www.tiktok.com/@zen/video/77",
                                       "text": "Zentrova KYC update", "playCount": 1000, "createTimeISO": "2026-10-02",
                                       "authorMeta": {"name": "zen", "nickName": "Zentrova Help", "fans": 12},
                                       "videoMeta": {"coverUrl": "https://cdn.example/77.jpg"}}],
        "scraper_one/facebook-posts-search": [{"url": "https://www.facebook.com/zencare/posts/1", "postId": "1",
                                               "postText": "Zentrova refund call 9876543210",
                                               "timestamp": 1760000000000, "reactionsCount": 3,
                                               "attachments": [{"type": "photo", "url": "https://cdn.example/f.jpg"}],
                                               "author": {"id": "55", "name": "Zentrova Care",
                                                          "profileUrl": "https://www.facebook.com/zencare"}}],
        "apify/facebook-ads-scraper": [{"adArchiveID": "999", "pageName": "Zentrova Offers", "pageID": "55",
                                        "publisherPlatform": ["FACEBOOK", "INSTAGRAM"], "isActive": True,
                                        "startDateFormatted": "2026-10-03T00:00:00.000Z",
                                        "snapshot": {"body": {"text": "Zentrova cashback, WhatsApp wa.me/919876543210"},
                                                     "images": [{"originalImageUrl": "https://cdn.example/ad.jpg"}]}}],
        "apidojo/tweet-scraper": [TWEET],
        "harvestapi/linkedin-post-search": [{"type": "post", "id": "li1", "content": "Hiring for Zentrova Bank",
                                             "linkedinUrl": "https://www.linkedin.com/posts/zen-hr_1",
                                             "author": {"name": "Zen HR", "publicIdentifier": "zen-hr",
                                                        "linkedinUrl": "https://www.linkedin.com/in/zen-hr"},
                                             "postedAt": {"date": "2026-10-04T00:00:00Z"},
                                             "engagement": {"likes": 2}}],
    })
    report = ScanReport()
    items = {i.platform: i for i in ap.content_items(_ctx(), report)}
    assert set(items) == {"Instagram", "TikTok", "Facebook", "Meta Ads", "X", "LinkedIn"}
    assert items["Instagram"].content_type == "video" and items["Instagram"].metrics["Views"] == 500
    assert items["TikTok"].author_handle == "zen" and items["TikTok"].thumbnail_url.endswith("77.jpg")
    assert items["Facebook"].thumbnail_url == "https://cdn.example/f.jpg"
    assert items["Facebook"].author_handle == "zencare" and items["Facebook"].published.startswith("2025-10-09")
    assert items["Meta Ads"].url == "https://www.facebook.com/ads/library/?id=999"
    assert items["Meta Ads"].metrics["Shown On"] == "Facebook, Instagram" and "wa.me" in items["Meta Ads"].text
    assert items["X"].item_id == "1799" and items["X"].published.startswith("2026-10-10T17:49:36")
    assert items["LinkedIn"].author_url == "https://www.linkedin.com/in/zen-hr"
    assert all(i.structured for i in items.values())
    assert {c["status"] for c in report.as_list()} == {"ok"}


@pytest.mark.req("SMM-01", "SMM-03")
def test_apify_post_becomes_a_finding(monkeypatch, token):
    item = ap._tweet(TWEET)
    dets, _ = _run([item])
    assert len(dets) == 1 and dets[0].analysed
    assert "9876543210" in " ".join(dets[0].details["Scam Contacts"])
    assert dets[0].details["Discovery Source"] == "Apify (X)"


@pytest.mark.req("SMM-02", "SMM-07")
def test_same_post_from_apify_and_web_search_is_reported_once(monkeypatch):
    for name in ("youtube", "meta_ads", "facebook_pages", "threads", "x_posts", "telegram_posts"):
        monkeypatch.setattr(sources, name, lambda ctx, rep: [])
    apify_item = SocialItem(platform="Instagram", content_type="post", url="https://www.instagram.com/p/C1/",
                            item_id="C1", structured=True)
    web_item = SocialItem(platform="Instagram", content_type="post", url="https://instagram.com/p/C1?igsh=abc")
    library = "https://www.facebook.com/ads/library/?id="
    ad = SocialItem(platform="Meta Ads", content_type="ad", url=library + "1", item_id="1")
    ad2 = SocialItem(platform="Meta Ads", content_type="ad", url=library + "2", item_id="2")
    monkeypatch.setattr(ap, "content_items", lambda ctx, rep: [apify_item, ad, ad2])
    monkeypatch.setattr(sources, "web_search", lambda ctx, rep: [web_item])
    out = sources.all_items(_ctx(), ScanReport())
    assert out == [apify_item, ad, ad2]


@pytest.mark.req("SOC-03", "SOC-06", "SMM-07")
def test_impersonation_gets_real_profiles(monkeypatch, token):
    _fake_runs(monkeypatch, {
        "apify/instagram-scraper": [{"username": "zentrova_support", "fullName": "Zentrova Bank Support",
                                     "biography": "Customer care 24/7, DM us", "followersCount": 210,
                                     "url": "https://www.instagram.com/zentrova_support"}],
        "apidojo/tweet-scraper": [TWEET],
    })
    monkeypatch.setattr(get_settings(), "apify_platforms", ["instagram", "x"])
    report = ScanReport()
    profiles = {p.platform: p for p in social.apify_profiles(_ctx(), report)}
    ig, x = profiles["Instagram"], profiles["X"]
    assert ig.username == "zentrova_support" and ig.followers == 210 and "Customer care" in ig.bio
    assert x.username == "zentrova_care" and x.followers == 31 and x.discovery == "Apify (X)"
    mod = social.SocialModule(capture_fn=lambda url, full_page=False: type("C", (), {"screenshot": None})())
    det = mod.analyse(_ctx(), ig)
    assert det is not None and det.analysed and det.details["Support Terms"]
