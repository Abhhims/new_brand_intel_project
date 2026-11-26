"""Risk scoring model (requirements §6, decisions D-02, D-03, D-05, D-06).

One pure function. Modules describe *what they observed* as Signals; this module alone decides
the points, the 0-100 score and the risk level.
"""

from dataclasses import dataclass, field

from app.db.models import ModuleName, RiskLevel

# (rule name, points) — order is the order rules are reported in
RULE_POINTS: dict[str, int] = {
    "brand_exact_in_domain": 40,   # RSK-01
    "typo_similarity_gt_80": 25,   # RSK-02 (strictly > 80, D-05)
    "mx_present": 15,              # RSK-03
    "https": 10,                   # RSK-04
    "login_payment_keywords": 20,  # RSK-05
    "official_logo": 30,           # RSK-06
    "social_image_match": 20,      # RSK-07
    "publisher_mismatch": 25,      # RSK-08
    "doc_brand_keyword": 30,       # D-06
    "doc_official_domain": 20,     # D-06
    "doc_sensitive_pattern": 30,   # D-06
    "doc_many_emails": 20,         # D-06
    # Social media content (posts, videos, ads, channels)
    "brand_in_content": 20,        # brand name used in the content, account or channel name
    "scam_contact_details": 30,    # phone / WhatsApp / Telegram / UPI contact published next to the brand
    "scam_language": 20,           # customer-care, KYC, refund, guaranteed-returns style wording
    "paid_ad": 10,                 # a paid advertisement
    "fake_support_claim": 30,      # "customer care / helpline / toll-free number" for the brand, posted by others
    "brand_abuse": 15,             # earning / referral bait, cashback lure, unofficial APK
    # Phishing email (D-28, spec 2026-10-08 §4)
    "known_malicious_url": 40,             # URL listed by >= 2 independent sources
    "single_source_url_hit": 15,           # listed by exactly one source (corroboration rule)
    "malware_attachment": 40,              # ClamAV detection or hash known to URLhaus
    "suspicious_attachment": 20,           # YARA / macro / executable / double extension
    "auth_fail_brand_from": 30,            # From is an official brand domain and DMARC fails
    "lookalike_sender": 25,                # sender / reply-to / link domain is a brand look-alike
    "brand_impersonation": 20,             # brand terms or logo, not sent by the brand
    "reply_to_mismatch": 10,
    "credential_or_payment_language": 15,
    "young_domain": 10,                    # registered < 30 days
    "bad_sender_ip": 10,                   # AbuseIPDB confidence >= 75
    "rspamd_phish": 10,
    "live_phishing_page": 20,              # linked page is Suspected Phishing (website pipeline)
    "lookalike_can_send": 10,              # look-alike domain publishes SPF (email-ready)
    # Brand domain email posture
    "posture_dmarc_missing": 40,           # no / duplicate / invalid DMARC record
    "posture_dmarc_none": 20,              # p=none
    "posture_spf_missing": 40,             # no SPF or +all
    "posture_spf_softfail": 10,            # ~all
    "posture_dkim_missing": 10,
    "posture_mta_sts_missing": 5,
}

TYPO_SIMILARITY_THRESHOLD = 80
MAX_SCORE = 100

# Version of the scoring rules; stored with every score so a result can be reproduced later (D-45)
SCORING_POLICY = "2026-10-16"

# D-29/D-45: a look-alike domain only reaches Critical when its live page shows the brand (logo, favicon, brand
# name/terms or a reference to an official site); a name match alone is never Critical. Highest score per cap:
SCORE_CAPS: dict[str, int] = {
    "parked_page": 29,          # parked / for-sale page → Low at most
    "no_brand_evidence": 29,    # live site about something else → Low at most
    "no_brand_login_form": 59,  # live site without brand content but with a login/payment form → Medium at most
    "no_website": 79,           # no website seen (mail only, or nothing) → High at most
}
CAPPED_MODULES = (ModuleName.typosquat, ModuleName.mx, ModuleName.phishing)
CAP_REASONS: dict[str, str] = {
    "parked_page": "Parked / for-sale page — capped at Low",
    "no_brand_evidence": "No brand content on the page (logo, favicon, brand name or official-site link) "
                         "— capped at Low",
    "no_brand_login_form": "Login/payment form but no brand content on the page — capped at Medium",
    "no_website": "No website seen, so no brand content or phishing behaviour observed — capped at High",
}

# Social media criticality (social_media module only). The tier decides the level; points only order items
# inside their tier.
#   critical: contact details (phone / WhatsApp / UPI) published together with a "customer care / helpline"
#             claim or scam wording — the number itself is the evidence (D-45)
#   high:     a "customer care / helpline number" claim without a number in the text (verify the video / image),
#             wrong-details scam wording (KYC update, account blocked, guaranteed returns, fees, fake agents),
#             or brand abuse that also uses the official logo or a look-alike account name
#   medium:   contact details next to the brand name without any support or scam wording, brand abuse (earning /
#             referral bait, cashback lures, unofficial APKs), logo use, paid ads, look-alike account names
#   low:      informative content (how-to videos, news, reviews)
SOCIAL_REASONS: dict[str, str] = {
    "critical": "Contact details published as the brand's customer care / helpline, or with scam wording",
    "high": "Customer-care claim without a visible number (check the video), wrong-details scam wording, "
            "or brand abuse with the official logo / look-alike name",
    "medium": "Contact details without support wording, brand abuse (earning or referral bait, cashback lure, "
              "unofficial APK), logo use or ad",
    "low": "Informative content (how-to, news, review)",
}
_TIER_LEVEL = {"critical": RiskLevel.critical, "high": RiskLevel.high, "medium": RiskLevel.medium,
               "low": RiskLevel.low}

# Lower bound of each level (RSK-09); upper bound is the next level's floor - 1
LEVEL_FLOORS: list[tuple[int, RiskLevel]] = [
    (80, RiskLevel.critical),
    (60, RiskLevel.high),
    (30, RiskLevel.medium),
    (0, RiskLevel.low),
]
LEVEL_RANGE: dict[RiskLevel, tuple[int, int]] = {
    RiskLevel.low: (0, 29),
    RiskLevel.medium: (30, 59),
    RiskLevel.high: (60, 79),
    RiskLevel.critical: (80, 100),
}

# Levels each module may report (from the Expected Output tables in §3, D-03)
MODULE_LEVELS: dict[ModuleName, tuple[RiskLevel, RiskLevel]] = {
    ModuleName.typosquat: (RiskLevel.low, RiskLevel.critical),
    ModuleName.mx: (RiskLevel.low, RiskLevel.critical),
    ModuleName.phishing: (RiskLevel.low, RiskLevel.critical),
    ModuleName.apk: (RiskLevel.medium, RiskLevel.high),
    ModuleName.rogue_app: (RiskLevel.medium, RiskLevel.high),
    ModuleName.logo: (RiskLevel.medium, RiskLevel.high),
    ModuleName.social: (RiskLevel.low, RiskLevel.high),
    ModuleName.documents: (RiskLevel.medium, RiskLevel.critical),
    ModuleName.email: (RiskLevel.low, RiskLevel.critical),
    ModuleName.email_posture: (RiskLevel.low, RiskLevel.critical),
    ModuleName.dmarc: (RiskLevel.low, RiskLevel.critical),
    ModuleName.social_media: (RiskLevel.low, RiskLevel.critical),
}

EMAIL_BOOL_RULES = (
    "known_malicious_url", "single_source_url_hit", "malware_attachment", "suspicious_attachment",
    "auth_fail_brand_from", "lookalike_sender", "brand_impersonation", "reply_to_mismatch",
    "credential_or_payment_language", "young_domain", "bad_sender_ip", "rspamd_phish", "live_phishing_page",
    "lookalike_can_send", "posture_dmarc_missing", "posture_dmarc_none", "posture_spf_missing",
    "posture_spf_softfail", "posture_dkim_missing", "posture_mta_sts_missing",
)


@dataclass(frozen=True)
class Signals:
    brand_exact_in_domain: bool = False
    typo_similarity: float | None = None
    mx_present: bool = False
    https: bool = False
    login_payment_keywords: bool = False
    official_logo: bool = False
    social_image_match: bool = False
    publisher_mismatch: bool = False
    doc_brand_keyword: bool = False
    doc_official_domain: bool = False
    doc_sensitive_pattern: bool = False
    doc_many_emails: bool = False
    brand_in_content: bool = False
    scam_contact_details: bool = False
    scam_language: bool = False
    paid_ad: bool = False
    fake_support_claim: bool = False
    brand_abuse: bool = False
    known_malicious_url: bool = False
    single_source_url_hit: bool = False
    malware_attachment: bool = False
    suspicious_attachment: bool = False
    auth_fail_brand_from: bool = False
    lookalike_sender: bool = False
    brand_impersonation: bool = False
    reply_to_mismatch: bool = False
    credential_or_payment_language: bool = False
    young_domain: bool = False
    bad_sender_ip: bool = False
    rspamd_phish: bool = False
    live_phishing_page: bool = False
    lookalike_can_send: bool = False
    posture_dmarc_missing: bool = False
    posture_dmarc_none: bool = False
    posture_spf_missing: bool = False
    posture_spf_softfail: bool = False
    posture_dkim_missing: bool = False
    posture_mta_sts_missing: bool = False
    # D-29 context for live look-alike websites (not points)
    page_live: bool = False
    brand_on_page: bool = False
    parked_page: bool = False


@dataclass(frozen=True)
class ScoreResult:
    score: int
    level: RiskLevel
    fired: list[str] = field(default_factory=list)
    raw_score: int = 0  # before module clamp, for transparency
    cap: str | None = None  # D-29 cap that lowered the score, if any
    tier: str | None = None  # social media criticality tier (social_media module only)

    def as_dict(self) -> dict:
        return {
            "score": self.score,
            "level": self.level.value,
            "raw_score": self.raw_score,
            "cap": self.cap,
            "policy": SCORING_POLICY,
            **({"tier": self.tier} if self.tier else {}),
            "rules": {name: RULE_POINTS[name] for name in self.fired},
        }


def level_for(value: int) -> RiskLevel:
    for floor, level in LEVEL_FLOORS:
        if value >= floor:
            return level
    return RiskLevel.low


def _fired_rules(s: Signals) -> list[str]:
    checks = {
        "brand_exact_in_domain": s.brand_exact_in_domain,
        "typo_similarity_gt_80": s.typo_similarity is not None and s.typo_similarity > TYPO_SIMILARITY_THRESHOLD,
        "mx_present": s.mx_present,
        "https": s.https,
        "login_payment_keywords": s.login_payment_keywords,
        "official_logo": s.official_logo,
        "social_image_match": s.social_image_match,
        "publisher_mismatch": s.publisher_mismatch,
        "doc_brand_keyword": s.doc_brand_keyword,
        "doc_official_domain": s.doc_official_domain,
        "doc_sensitive_pattern": s.doc_sensitive_pattern,
        "doc_many_emails": s.doc_many_emails,
        "brand_in_content": s.brand_in_content,
        "scam_contact_details": s.scam_contact_details,
        "scam_language": s.scam_language,
        "paid_ad": s.paid_ad,
        "fake_support_claim": s.fake_support_claim,
        "brand_abuse": s.brand_abuse,
        **{name: getattr(s, name) for name in EMAIL_BOOL_RULES},
    }
    return [name for name in RULE_POINTS if checks[name]]


def _cap_for(s: Signals, module: ModuleName) -> str | None:
    if module not in CAPPED_MODULES:
        return None
    if s.parked_page and s.page_live:
        return "parked_page"
    if s.known_malicious_url:
        return None  # D-46: >= 2 independent threat-intel listings are observed malicious behaviour
    if not s.page_live:
        return "no_website"
    if not s.brand_on_page:
        return "no_brand_login_form" if s.login_payment_keywords else "no_brand_evidence"
    return None


def score(signals: Signals, module: ModuleName) -> ScoreResult:
    fired = _fired_rules(signals)
    raw = min(MAX_SCORE, sum(RULE_POINTS[name] for name in fired))

    # Clamp into the module's allowed level range, moving the number with it so the
    # score shown never contradicts the level (D-03).
    lowest, highest = MODULE_LEVELS[module]
    value = max(raw, LEVEL_RANGE[lowest][0])
    value = min(value, LEVEL_RANGE[highest][1])

    cap = _cap_for(signals, module)
    if cap and value > SCORE_CAPS[cap]:
        value = SCORE_CAPS[cap]
    else:
        cap = None  # only report a cap that actually lowered the score

    tier = None
    if module == ModuleName.social_media:
        tier = social_tier(signals)
        low, high = LEVEL_RANGE[_TIER_LEVEL[tier]]
        value = min(max(value, low), high)
    return ScoreResult(score=value, level=level_for(value), fired=fired, raw_score=raw, cap=cap, tier=tier)


def social_tier(s: Signals) -> str:
    """Criticality tier of a social media post / video / ad / channel (see SOCIAL_REASONS)."""
    lookalike = s.typo_similarity is not None and s.typo_similarity > TYPO_SIMILARITY_THRESHOLD
    if s.scam_contact_details and (s.fake_support_claim or s.scam_language):
        return "critical"
    if s.fake_support_claim or s.scam_language or (s.brand_abuse and (s.social_image_match or lookalike)):
        return "high"
    if s.scam_contact_details or s.brand_abuse or s.social_image_match or s.paid_ad or lookalike:
        return "medium"
    return "low"


def email_risk(mx_present: bool, website_live: bool) -> RiskLevel:
    """§3.1 MX tiers, reported as a separate 'Email Risk' field (D-02, MX-04)."""
    if mx_present and website_live:
        return RiskLevel.high
    if mx_present:
        return RiskLevel.medium
    return RiskLevel.low
