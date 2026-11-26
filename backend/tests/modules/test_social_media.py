"""Social media brand-misuse monitor: scam contacts, official accounts skipped, candidates vs findings, scoring."""

import pytest

from app.core.browser import PageCapture
from app.core.scoring import score
from app.db.models import AllowKind, Brand, BrandAllow, ModuleName, RiskLevel
from app.modules.base import BrandContext, ScanReport
from app.modules.social_media.analysis import contact_details, content_type_of, platform_of, scam_phrases
from app.modules.social_media.module import SocialMediaModule
from app.modules.social_media.sources import SocialItem


def _ctx() -> BrandContext:
    brand = Brand(name="Zentrova Bank", keywords=["zentrova"], product_terms=[])
    brand.assets = []
    brand.allowlist = [BrandAllow(kind=AllowKind.social_handle, value="zentrovaofficial"),
                       BrandAllow(kind=AllowKind.domain, value="zentrova.example")]
    return BrandContext.from_brand(brand)


def _cap(url, full_page=False):
    return PageCapture(url=url, final_url=url, status=200, title="t", text="", html="", screenshot=b"\x89PNG fake")


def _run(items, capture_fn=_cap):
    report = ScanReport()
    report.ok("YouTube API")
    mod = SocialMediaModule(source=lambda ctx, rep: items, capture_fn=capture_fn)
    mod.report = report
    return list(mod.run(_ctx(), db=None)), report


@pytest.mark.req("SMM-03")
def test_contact_details_and_scam_wording():
    text = "Zentrova customer care call +91 98765 43210 or wa.me/919876543210, pay to refund.desk@ybl, t.me/zentrovahelp"
    c = contact_details(text)
    assert c["phone"] == ["9876543210"] and c["whatsapp"] and c["upi"] == ["refund.desk@ybl"] and c["telegram"]
    assert "customer care" in scam_phrases(text)
    assert platform_of("https://www.instagram.com/reel/abc/") == "Instagram"
    assert content_type_of("Instagram", "https://www.instagram.com/reel/abc/") == "video"
    assert content_type_of("YouTube", "https://www.youtube.com/@zentrovafake") == "channel"


@pytest.mark.req("SMM-01", "SMM-02", "SMM-03", "SMM-06")
def test_scam_video_is_flagged_with_screenshot_and_alert_level():
    video = SocialItem(platform="YouTube", content_type="video", url="https://www.youtube.com/watch?v=abc123",
                       item_id="abc123", title="Zentrova Bank KYC update helpline",
                       text="Call Zentrova customer care on WhatsApp wa.me/919876543210", author="Bank Help 24x7",
                       author_id="UCfake", discovery="YouTube Data API", structured=True)
    dets, _ = _run([video])
    assert len(dets) == 1
    d = dets[0]
    assert d.entity_key == "youtube:video:abc123" and d.analysed
    assert d.details["Scam Contacts"] and d.details["Screenshot"] is True
    assert any(e.kind == "screenshot" for e in d.evidence)
    result = score(d.signals, ModuleName.social_media)
    assert result.level == RiskLevel.critical  # fake contact details → Critical
    assert {"brand_in_content", "scam_contact_details", "fake_support_claim"} <= set(result.fired)


@pytest.mark.req("SMM-04")
def test_official_irrelevant_and_mention_only():
    official = SocialItem(platform="YouTube", content_type="channel", url="https://www.youtube.com/@zentrovaofficial",
                          title="Zentrova Bank", author_handle="zentrovaofficial", structured=True)
    unrelated = SocialItem(platform="YouTube", content_type="video", url="https://www.youtube.com/watch?v=x1",
                           item_id="x1", title="Cooking pasta", structured=True)
    mention = SocialItem(platform="Instagram", content_type="post", url="https://www.instagram.com/p/xyz/",
                         title="Opened my Zentrova account today", text="", discovery="web search")
    dets, _ = _run([official, unrelated, mention], capture_fn=lambda url, full_page=False: PageCapture(
        url=url, final_url=url, status=None, title="", text="", html="", screenshot=None, error="timeout"))
    assert [d.entity_key for d in dets] == ["instagram:post:https://www.instagram.com/p/xyz"]
    d = dets[0]
    assert d.analysed is False  # bare search hit, no screenshot -> Candidate
    assert score(d.signals, ModuleName.social_media).level == RiskLevel.low  # mention alone does not alert


@pytest.mark.req("SMM-03")
def test_short_brand_name_with_scam_contact_is_kept():
    """'Navi' alone is ambiguous (D-25), but 'Navi customer care number 98765…' is the fraud pattern."""
    from app.modules.social_media.module import SocialMediaModule as M

    brand = Brand(name="Navi", keywords=["navi"], product_terms=["navi loan"])
    brand.assets, brand.allowlist = [], []
    ctx = BrandContext.from_brand(brand)
    scam = SocialItem(platform="YouTube", content_type="video", url="https://www.youtube.com/watch?v=n1", item_id="n1",
                      title="Navi customer care number", text="Call 9876543210 for KYC help", structured=True)
    other = SocialItem(platform="YouTube", content_type="video", url="https://www.youtube.com/watch?v=n2", item_id="n2",
                       title="Navi Pillay wins prize", text="news", structured=True)
    # D-45: a phone number is not brand context — "Navi Mumbai" shops and news publish numbers too
    shop = SocialItem(platform="YouTube", content_type="video", url="https://www.youtube.com/watch?v=n3", item_id="n3",
                      title="Gold Choker Necklace Collection | Kalash Jewellers Kamothe Navi Mumbai",
                      text="Order on WhatsApp wa.me/918889991812", structured=True)
    mod = M(source=lambda c, r: [], capture_fn=_cap)
    det = mod.analyse(ctx, scam)
    assert det is not None and score(det.signals, ModuleName.social_media).level.value == "Critical"
    assert mod.analyse(ctx, other) is None
    assert mod.analyse(ctx, shop) is None


@pytest.mark.req("SMM-05", "D-31")
def test_no_source_checked_fails_the_run():
    mod = SocialMediaModule(source=lambda ctx, rep: [], capture_fn=_cap)
    mod.report.not_configured("YouTube API", "YOUTUBE_API_KEY not set")
    list(mod.run(_ctx(), db=None))
    assert any(c["fatal"] for c in mod.report.as_list())


@pytest.mark.req("SMM-02", "SMM-05")
def test_facebook_pages_source(monkeypatch):
    from app.config import get_settings
    from app.modules.social_media import sources

    monkeypatch.setattr(get_settings(), "meta_app_id", "123")
    monkeypatch.setattr(get_settings(), "meta_app_secret", "s3cret")
    monkeypatch.setattr(get_settings(), "meta_graph_token", None)  # the app token is used when no override
    calls = []

    def fake_get(url, headers):
        calls.append((url, headers))
        if "pages/search" in url:
            return 200, {"data": [{"id": "99", "name": "Zentrova Bank Care"}]}
        if "/posts" in url:
            return 200, {"data": [{"id": "99_1", "message": "Zentrova KYC update call 9876543210",
                                   "permalink_url": "https://www.facebook.com/99/posts/1",
                                   "created_time": "2026-10-01T10:00:00+0000"}]}
        return 200, {"id": "99", "name": "Zentrova Bank Care", "phone": "+91 98765 43210",
                     "link": "https://www.facebook.com/zentrovacare", "username": "zentrovacare"}

    monkeypatch.setattr(sources, "_get_json", fake_get)
    report = ScanReport()
    items = sources.facebook_pages(_ctx(), report)
    assert {i.content_type for i in items} == {"account", "post"}
    assert all(h["Authorization"] == "Bearer 123|s3cret" for _, h in calls)  # key in header, not URL
    assert all("s3cret" not in u for u, _ in calls)
    assert report.as_list()[0]["status"] == "ok"

    # app not approved for Page Public Content Access: Meta's error is reported, nothing is invented
    monkeypatch.setattr(sources, "_get_json", lambda url, headers: (400, {"error": {
        "message": "(#10) This endpoint requires the 'Page Public Content Access' feature"}}))
    report = ScanReport()
    assert sources.facebook_pages(_ctx(), report) == []
    c = report.as_list()[0]
    assert c["status"] == "failed" and "Page Public Content Access" in c["message"]


@pytest.mark.req("SMM-03")
def test_lookalike_lettering_and_hindi_wording_are_read():
    from app.modules.social_media.analysis import abuse_phrases, normalize, support_phrases

    fancy = "ℕ𝕒𝕧𝕚 𝕒𝕡𝕡 𝕔𝕦𝕤𝕥𝕠𝕞𝕖𝕣 𝕔𝕒𝕣𝕖 𝕟𝕦𝕞𝕓𝕖𝕣 𝐍𝐚𝐯𝐢 𝐔𝐏𝐈 𝐡𝐞𝐥𝐩𝐥𝐢𝐧𝐞"
    assert normalize(fancy).startswith("Navi app customer care number")
    assert {"customer care", "care number", "helpline"} <= set(support_phrases(scam_phrases(fancy)))
    assert "customer care" in scam_phrases("#navicustomercare #viral")             # glued hashtag
    assert "toll free" in scam_phrases("Navi toll-free number")                    # hyphenated
    assert "कस्टमर केयर" in scam_phrases("Navi कस्टमर केयर नंबर")
    assert contact_details("call ९८७६५४३२१० now")["phone"] == ["9876543210"]       # Devanagari digits
    assert abuse_phrases(scam_phrases("Navi refer and earn ₹500, Navi app se paise kaise kamaye"))
    assert not scam_phrases("How to add a bank account in the Navi app")          # tutorial: informative


@pytest.mark.req("SMM-03")
def test_social_media_criticality_end_to_end():
    def item(i, title):
        return SocialItem(platform="YouTube", content_type="video", url=f"https://www.youtube.com/watch?v=v{i}",
                          item_id=f"v{i}", title=title, structured=True)

    titles = {
        "critical": "𝐙𝐞𝐧𝐭𝐫𝐨𝐯𝐚 𝐜𝐮𝐬𝐭𝐨𝐦𝐞𝐫 𝐜𝐚𝐫𝐞 𝐧𝐮𝐦𝐛𝐞𝐫 9876543210",
        "high": "𝐙𝐞𝐧𝐭𝐫𝐨𝐯𝐚 𝐜𝐮𝐬𝐭𝐨𝐦𝐞𝐫 𝐜𝐚𝐫𝐞 𝐧𝐮𝐦𝐛𝐞𝐫",  # claim, but no number in the text (D-45)
        "high ": "Zentrova KYC update pending, account blocked",
        "medium": "Zentrova refer and earn trick",
        "low": "How to open a Zentrova account",
    }
    dets, _ = _run([item(i, t) for i, t in enumerate(titles.values())])
    got = [score(d.signals, ModuleName.social_media).tier for d in dets]
    assert got == [t.strip() for t in titles]


@pytest.mark.req("SMM-03")
def test_help_video_mentioning_support_is_not_a_fake_customer_care():
    from app.modules.social_media.analysis import fake_support_claim

    desc = "Wrong transaction? Raise a ticket or contact customer support in the app."
    assert not fake_support_claim(scam_phrases("Navi wrong transaction refund kaise kare"), scam_phrases(desc))
    assert fake_support_claim([], scam_phrases("Call the Navi customer care number for a refund"))   # number claim
    assert fake_support_claim(scam_phrases("Navi helpline"), [])                                     # title claim
