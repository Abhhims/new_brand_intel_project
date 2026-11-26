import pytest

from app.core.scoring import MODULE_LEVELS, Signals, score
from app.db.models import ModuleName, RiskLevel

pytestmark = pytest.mark.req("EML-12")


@pytest.mark.parametrize(("signals", "points", "rule"), [
    (Signals(known_malicious_url=True), 40, "known_malicious_url"),
    (Signals(single_source_url_hit=True), 15, "single_source_url_hit"),
    (Signals(malware_attachment=True), 40, "malware_attachment"),
    (Signals(suspicious_attachment=True), 20, "suspicious_attachment"),
    (Signals(auth_fail_brand_from=True), 30, "auth_fail_brand_from"),
    (Signals(lookalike_sender=True), 25, "lookalike_sender"),
    (Signals(brand_impersonation=True), 20, "brand_impersonation"),
    (Signals(reply_to_mismatch=True), 10, "reply_to_mismatch"),
    (Signals(credential_or_payment_language=True), 15, "credential_or_payment_language"),
    (Signals(young_domain=True), 10, "young_domain"),
    (Signals(bad_sender_ip=True), 10, "bad_sender_ip"),
    (Signals(rspamd_phish=True), 10, "rspamd_phish"),
    (Signals(live_phishing_page=True), 20, "live_phishing_page"),
    (Signals(lookalike_can_send=True), 10, "lookalike_can_send"),
    (Signals(posture_dmarc_missing=True), 40, "posture_dmarc_missing"),
    (Signals(posture_dmarc_none=True), 20, "posture_dmarc_none"),
    (Signals(posture_spf_missing=True), 40, "posture_spf_missing"),
    (Signals(posture_spf_softfail=True), 10, "posture_spf_softfail"),
    (Signals(posture_dkim_missing=True), 10, "posture_dkim_missing"),
    (Signals(posture_mta_sts_missing=True), 5, "posture_mta_sts_missing"),
])
def test_email_rules(signals, points, rule):
    r = score(signals, ModuleName.email)
    assert (r.score, r.fired) == (points, [rule])


@pytest.mark.parametrize("module", ["email", "email_posture", "dmarc"])
def test_email_modules_use_all_four_levels(module):
    m = ModuleName(module)
    assert MODULE_LEVELS[m] == (RiskLevel.low, RiskLevel.critical)
    assert score(Signals(), m).level == RiskLevel.low


def test_typical_phish_is_critical():
    s = Signals(known_malicious_url=True, lookalike_sender=True, brand_impersonation=True,
                reply_to_mismatch=True, credential_or_payment_language=True)
    assert score(s, ModuleName.email).score == 100
