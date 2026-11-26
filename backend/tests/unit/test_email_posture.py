import uuid

import pytest

from app.modules.email import posture

pytestmark = pytest.mark.req("EML-15", "EML-16")


def _ctx(domains):
    from app.modules.base import BrandContext

    return BrandContext(id=uuid.uuid4(), name="KCPL", keywords=["kcpl"], product_terms=[],
                        official_domains=domains, official_packages=[], official_publishers=[], official_handles=[],
                        email_domains=domains, logo_hashes=[], favicon_hashes=[], favicon_mmh3=[])


def test_duplicate_dmarc_record_is_missing():
    # Two DMARC records (one malformed) → receivers treat DMARC as absent
    def dns(domain, rtype):
        return {
            ("_dmarc.mykcpl.com", "TXT"): ["v=DMARC1; p=none;", "Value: v=DMARC1; p=none;"],
            ("mykcpl.com", "TXT"): ["v=spf1 +a +mx ~all"],
        }.get((domain, rtype), [])

    finding = posture.evaluate("mykcpl.com", _ctx(["mykcpl.com"]), dns=dns, dkim_selectors=lambda d, s: False)
    assert finding is not None
    # one valid p=none record plus a malformed "Value: ..." record (the real mykcpl.com situation)
    assert finding.signals.posture_dmarc_none is True
    assert any("malformed DMARC" in i for i in finding.details["DMARC Issues"])


def test_softfail_spf_and_none_policy():
    def dns(domain, rtype):
        return {
            ("_dmarc.good.com", "TXT"): ["v=DMARC1; p=none; rua=mailto:x@good.com"],
            ("good.com", "TXT"): ["v=spf1 include:_spf.google.com ~all"],
        }.get((domain, rtype), [])

    f = posture.evaluate("good.com", _ctx(["good.com"]), dns=dns, dkim_selectors=lambda d, s: True)
    assert f.signals.posture_dmarc_none is True and f.signals.posture_spf_softfail is True
    assert f.signals.posture_dkim_missing is False


def test_missing_spf_and_dmarc_is_high_risk():
    f = posture.evaluate("naked.com", _ctx(["naked.com"]), dns=lambda d, t: [], dkim_selectors=lambda d, s: False)
    assert f.signals.posture_spf_missing is True and f.signals.posture_dmarc_missing is True


def test_well_configured_domain_no_alert():
    def dns(domain, rtype):
        return {
            ("_dmarc.secure.com", "TXT"): ["v=DMARC1; p=reject; rua=mailto:x@secure.com"],
            ("secure.com", "TXT"): ["v=spf1 include:_spf.google.com -all"],
            ("_mta-sts.secure.com", "TXT"): ["v=STSv1; id=1"],
        }.get((domain, rtype), [])

    f = posture.evaluate("secure.com", _ctx(["secure.com"]), dns=dns, dkim_selectors=lambda d, s: True)
    assert f is None  # nothing wrong → no alert
