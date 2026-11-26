import pytest

from app.core.scoring import SCORING_POLICY, Signals, level_for, score
from app.db.models import ModuleName, RiskLevel

pytestmark = pytest.mark.req("RSK-01", "RSK-02", "RSK-03", "RSK-04", "RSK-05", "RSK-06",
                             "RSK-07", "RSK-08", "RSK-09", "RSK-10", "OUT-02")


@pytest.mark.parametrize(
    ("signals", "points", "rule"),
    [
        (Signals(brand_exact_in_domain=True), 40, "brand_exact_in_domain"),
        (Signals(typo_similarity=81), 25, "typo_similarity_gt_80"),
        (Signals(mx_present=True), 15, "mx_present"),
        (Signals(https=True), 10, "https"),
        (Signals(login_payment_keywords=True), 20, "login_payment_keywords"),
        (Signals(official_logo=True), 30, "official_logo"),
        (Signals(social_image_match=True), 20, "social_image_match"),
        (Signals(publisher_mismatch=True), 25, "publisher_mismatch"),
        (Signals(doc_brand_keyword=True), 30, "doc_brand_keyword"),
        (Signals(doc_official_domain=True), 20, "doc_official_domain"),
        (Signals(doc_sensitive_pattern=True), 30, "doc_sensitive_pattern"),
        (Signals(doc_many_emails=True), 20, "doc_many_emails"),
    ],
)
def test_each_rule_adds_its_points(signals, points, rule):
    result = score(signals, ModuleName.typosquat)
    assert result.score == points
    assert result.fired == [rule]


def test_typo_similarity_exactly_80_does_not_score():
    # Decision D-05: "> 80%" is strict
    assert score(Signals(typo_similarity=80), ModuleName.typosquat).score == 0
    assert score(Signals(typo_similarity=80.01), ModuleName.typosquat).score == 25


def test_no_signals_scores_zero_low():
    result = score(Signals(), ModuleName.typosquat)
    assert (result.score, result.level, result.fired) == (0, RiskLevel.low, [])


def test_rules_stack():
    # D-05: exact match and typo similarity both apply
    result = score(Signals(brand_exact_in_domain=True, typo_similarity=90), ModuleName.typosquat)
    assert result.score == 65


def test_score_capped_at_100():
    everything = Signals(
        brand_exact_in_domain=True, typo_similarity=99, mx_present=True, https=True,
        login_payment_keywords=True, official_logo=True, page_live=True, brand_on_page=True,
    )
    result = score(everything, ModuleName.phishing)
    assert result.score == 100
    assert result.level == RiskLevel.critical


@pytest.mark.parametrize(
    ("value", "level"),
    [(0, RiskLevel.low), (29, RiskLevel.low), (30, RiskLevel.medium), (59, RiskLevel.medium),
     (60, RiskLevel.high), (79, RiskLevel.high), (80, RiskLevel.critical), (100, RiskLevel.critical)],
)
def test_level_boundaries(value, level):
    assert level_for(value) == level


@pytest.mark.parametrize(
    ("module", "raw_points_signals", "expected"),
    [
        # APK / rogue app / logo: Medium or High only (D-03)
        (ModuleName.apk, Signals(), RiskLevel.medium),
        (ModuleName.apk, Signals(brand_exact_in_domain=True, official_logo=True, publisher_mismatch=True),
         RiskLevel.high),
        (ModuleName.rogue_app, Signals(), RiskLevel.medium),
        (ModuleName.logo, Signals(official_logo=True, https=True, login_payment_keywords=True,
                                  mx_present=True, brand_exact_in_domain=True), RiskLevel.high),
        # Social: Low / Medium / High
        (ModuleName.social, Signals(), RiskLevel.low),
        (ModuleName.social, Signals(typo_similarity=95, social_image_match=True,
                                    publisher_mismatch=True, brand_exact_in_domain=True), RiskLevel.high),
        # Documents: Medium / High / Critical
        (ModuleName.documents, Signals(), RiskLevel.medium),
        (ModuleName.documents, Signals(doc_brand_keyword=True, doc_official_domain=True,
                                       doc_sensitive_pattern=True), RiskLevel.critical),
        # Domains: all four
        (ModuleName.typosquat, Signals(), RiskLevel.low),
    ],
)
def test_module_level_clamp(module, raw_points_signals, expected):
    assert score(raw_points_signals, module).level == expected


def test_clamped_score_stays_consistent_with_level():
    # A clamped level must not contradict the number shown to analysts
    result = score(Signals(), ModuleName.apk)
    assert level_for(result.score) == result.level
    result = score(Signals(brand_exact_in_domain=True, official_logo=True, publisher_mismatch=True,
                           https=True), ModuleName.apk)
    assert result.level == RiskLevel.high
    assert level_for(result.score) == result.level


@pytest.mark.req("FND-15")
def test_production_refuses_default_secrets():
    from app.config import Settings, check_production

    with pytest.raises(RuntimeError, match="jwt_secret"):
        check_production(Settings(env="production", jwt_secret="change-me-in-production", fetch_allow_private_hosts=[]))
    ok = Settings(env="production", jwt_secret="y" * 40, bootstrap_admin_password="Strong-Unique-Pass-1",
                  s3_secret_key="another-strong-secret", fetch_allow_private_hosts=[])
    check_production(ok)


@pytest.mark.req("D-27")
def test_production_refuses_test_website_allowlist():
    """The private-host allowlist exists only so tests can reach the local test website."""
    from app.config import Settings, check_production

    with pytest.raises(RuntimeError, match="fetch_allow_private_hosts"):
        check_production(Settings(env="production", jwt_secret="y" * 40, bootstrap_admin_password="Strong-Unique-Pass-1",
                                  s3_secret_key="another-strong-secret", fetch_allow_private_hosts=["localhost"]))


# ---------------------------------------------------------------- D-29: a live site must show brand evidence
_ALL_DOMAIN_SIGNALS = dict(brand_exact_in_domain=True, typo_similarity=95, mx_present=True, https=True,
                           login_payment_keywords=True, lookalike_can_send=True)


@pytest.mark.req("D-29")
def test_live_site_without_brand_evidence_capped():
    # D-45: a login/payment form without brand content stays Medium; any other unrelated live site is Low
    result = score(Signals(**_ALL_DOMAIN_SIGNALS, page_live=True), ModuleName.phishing)
    assert (result.score, result.level, result.raw_score, result.cap) == (59, RiskLevel.medium, 100,
                                                                          "no_brand_login_form")
    plain = dict(_ALL_DOMAIN_SIGNALS, login_payment_keywords=False)
    result = score(Signals(**plain, page_live=True), ModuleName.phishing)
    assert (result.score, result.level, result.cap) == (29, RiskLevel.low, "no_brand_evidence")


@pytest.mark.req("D-29")
def test_live_site_with_brand_evidence_can_be_critical():
    result = score(Signals(**_ALL_DOMAIN_SIGNALS, page_live=True, brand_on_page=True), ModuleName.phishing)
    assert (result.score, result.level, result.cap) == (100, RiskLevel.critical, None)


@pytest.mark.req("D-29")
def test_parked_page_capped_at_low_even_with_brand_text():
    result = score(Signals(**_ALL_DOMAIN_SIGNALS, page_live=True, brand_on_page=True, parked_page=True),
                   ModuleName.phishing)
    assert (result.score, result.level, result.cap) == (29, RiskLevel.low, "parked_page")


@pytest.mark.req("D-29")
def test_cap_boundaries_do_not_raise_low_scores():
    # 25 stays 25 under the Low cap; a 25-point parked page is not lifted to 29
    assert score(Signals(typo_similarity=95, page_live=True), ModuleName.phishing).score == 25
    assert score(Signals(typo_similarity=95, page_live=True), ModuleName.phishing).cap is None
    assert score(Signals(typo_similarity=95, parked_page=True, page_live=True), ModuleName.phishing).score == 25
    # 65 raw with a login form → capped to 59 (High → Medium)
    capped = score(Signals(typo_similarity=95, login_payment_keywords=True, https=True, lookalike_can_send=True,
                           page_live=True), ModuleName.phishing)
    assert (capped.raw_score, capped.score, capped.level) == (65, 59, RiskLevel.medium)
    # 30 raw parked → 29 (Medium → Low)
    parked = score(Signals(typo_similarity=95, https=True, page_live=True, parked_page=True), ModuleName.phishing)
    assert (parked.raw_score, parked.score, parked.level) == (35, 29, RiskLevel.low)


@pytest.mark.req("D-29")
def test_domain_without_website_is_at_most_high():
    # D-45: no page seen, so no brand content or phishing behaviour observed — the name alone is never Critical
    result = score(Signals(brand_exact_in_domain=True, typo_similarity=95, mx_present=True,
                           lookalike_can_send=True), ModuleName.mx)
    assert (result.raw_score, result.score, result.level, result.cap) == (90, 79, RiskLevel.high, "no_website")
    low = score(Signals(typo_similarity=95), ModuleName.typosquat)
    assert (low.score, low.cap) == (25, None)  # only a cap that lowered the score is reported


@pytest.mark.req("D-29")
def test_cap_reason_reported_in_alert_signals():
    d = score(Signals(**_ALL_DOMAIN_SIGNALS, page_live=True), ModuleName.phishing).as_dict()
    assert d["cap"] == "no_brand_login_form" and d["raw_score"] == 100 and d["score"] == 59
    assert d["policy"] == SCORING_POLICY  # every stored score names the rule version that produced it


# ------------------------------------------------------------------ social media criticality
SM = ModuleName.social_media
BRAND = {"brand_in_content": True}


@pytest.mark.parametrize(("extra", "level", "tier"), [
    ({"scam_contact_details": True, "fake_support_claim": True}, RiskLevel.critical, "critical"),  # fake care no.
    ({"scam_contact_details": True, "scam_language": True}, RiskLevel.critical, "critical"),  # number + KYC wording
    ({"fake_support_claim": True}, RiskLevel.high, "high"),        # "customer care number" claim, number not seen
    ({"scam_contact_details": True}, RiskLevel.medium, "medium"),  # a number next to the name, no support wording
    ({"scam_language": True}, RiskLevel.high, "high"),                         # KYC / blocked account / returns
    ({"brand_abuse": True, "social_image_match": True}, RiskLevel.high, "high"),
    ({"brand_abuse": True, "typo_similarity": 95}, RiskLevel.high, "high"),    # abuse from a look-alike channel
    ({"brand_abuse": True}, RiskLevel.medium, "medium"),                       # referral / earning bait, APK
    ({"social_image_match": True}, RiskLevel.medium, "medium"),
    ({"paid_ad": True}, RiskLevel.medium, "medium"),
    ({}, RiskLevel.low, "low"),                                                # informative mention
])
def test_social_media_tiers(extra, level, tier):
    result = score(Signals(**BRAND, **extra), SM)
    assert (result.level, result.tier) == (level, tier)


def test_social_tier_moves_score_into_its_band():
    assert score(Signals(**BRAND, fake_support_claim=True), SM).score == 60        # raw 50 → High floor
    assert score(Signals(**BRAND, scam_contact_details=True, fake_support_claim=True), SM).score == 80
    assert score(Signals(**BRAND, scam_language=True), SM).score == 60             # raw 40 → High floor
    assert score(Signals(**BRAND, brand_abuse=True), SM).score == 35               # raw 35 stays (Medium)
    assert score(Signals(**BRAND), SM).score == 20                                 # raw 20 stays (Low)
    # High band tops out at 79 even with many points
    capped = score(Signals(**BRAND, scam_language=True, social_image_match=True, brand_abuse=True,
                           typo_similarity=95), SM)
    assert (capped.raw_score, capped.score, capped.level) == (100, 79, RiskLevel.high)
    # Medium band tops out at 59
    medium = score(Signals(**BRAND, social_image_match=True, paid_ad=True, typo_similarity=95), SM)
    assert (medium.raw_score, medium.score, medium.level) == (75, 59, RiskLevel.medium)
    full = score(Signals(**BRAND, scam_contact_details=True, fake_support_claim=True, scam_language=True), SM)
    assert (full.score, full.level) == (100, RiskLevel.critical)                   # cap at 100


def test_social_tier_reported_and_only_for_social_media():
    assert score(Signals(**BRAND, brand_abuse=True), SM).as_dict()["tier"] == "medium"
    other = score(Signals(scam_contact_details=True), ModuleName.social)
    assert other.tier is None and "tier" not in other.as_dict() and other.level == RiskLevel.medium
