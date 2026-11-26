"""D-47 / RDA-08: confidence (evidence quality) is separate from risk and explained factor by factor."""

import pytest

from app.core.confidence import assess
from app.db.models import ModuleName

pytestmark = pytest.mark.req("RDA-08", "D-47")
PH, SM = ModuleName.phishing, ModuleName.social_media


def _names(c):
    return {f.name for f in c.factors}


def test_name_only_domain_is_low_confidence_even_if_risk_is_high():
    c = assess(ModuleName.typosquat, {"brand_exact_in_domain", "typo_similarity_gt_80"}, {}, analysed=False,
               captured=False)
    assert c.level == "Low" and "name_only" in _names(c) and "candidate" in _names(c)


def test_independent_evidence_raises_confidence_once_per_kind():
    page = {"Website Live": True, "Brand Evidence On Page": True, "Threat Intel": "Listed by OpenPhish, urlscan.io"}
    c = assess(PH, {"brand_exact_in_domain", "login_payment_keywords", "official_logo", "known_malicious_url"},
               page, analysed=True, captured=True)
    assert c.level == "High" and {"content", "visual", "threat_intel", "corroborated"} <= _names(c)
    # the same kind of evidence twice is not two confirmations
    once = assess(SM, {"scam_language"}, {}, analysed=True, captured=True)
    twice = assess(SM, {"scam_language", "fake_support_claim", "brand_abuse"}, {}, analysed=True, captured=True)
    assert once.score == twice.score


def test_unknowns_and_contradictions_lower_confidence_and_say_why():
    base = assess(PH, {"brand_exact_in_domain", "login_payment_keywords"}, {"Website Live": True,
                  "Brand Evidence On Page": True}, analysed=True, captured=True)
    failed = assess(PH, {"brand_exact_in_domain", "login_payment_keywords"},
                    {"Website Live": "unknown (capture failed)", "Registrar": "lookup failed",
                     "Threat Intel": "Not checked"}, analysed=True, captured=False)
    parked = assess(PH, {"brand_exact_in_domain"}, {"Website Live": True, "Parked Page": True}, analysed=True,
                    captured=True)
    assert failed.score < base.score and {"capture_failed", "whois_failed", "intel_partial"} <= _names(failed)
    assert "parked" in _names(parked) and parked.level == "Low"
    assert all(f.why for f in failed.factors)


def test_search_snippet_is_less_certain_than_platform_data():
    api = assess(SM, {"brand_in_content", "scam_contact_details"}, {"Discovery Source": "YouTube Data API"},
                 analysed=True, captured=True)
    web = assess(SM, {"brand_in_content", "scam_contact_details"}, {"Discovery Source": "web search (Brave)"},
                 analysed=True, captured=True)
    assert web.score == api.score - 10 and "snippet_only" in _names(web)


def test_apk_signer_and_posture_facts():
    assert "signer_verified" in _names(assess(ModuleName.apk, {"publisher_mismatch"},
                                              {"Signer Matches Official": False}, analysed=True, captured=True))
    assert "signer_unknown" in _names(assess(ModuleName.apk, set(), {"Signer Matches Official": None},
                                             analysed=True, captured=True))
    posture = assess(ModuleName.email_posture, {"posture_dmarc_missing"}, {}, analysed=True, captured=False)
    assert posture.level == "High"  # read directly from DNS: a fact, not a guess


def test_confidence_is_stored_next_to_risk_not_mixed_into_it():
    from app.core.scoring import Signals, score

    s = Signals(brand_exact_in_domain=True, typo_similarity=95)
    before = score(s, ModuleName.typosquat).as_dict()
    assert "confidence" not in before  # the risk score is unchanged by confidence
    d = assess(ModuleName.typosquat, before["rules"], {}, analysed=False, captured=False).as_dict()
    assert set(d) == {"score", "level", "policy", "factors"} and d["factors"][0]["why"]
