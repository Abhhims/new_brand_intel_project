import pytest

from app.modules.email import auth
from app.modules.email.parser import parse

pytestmark = pytest.mark.req("EML-04", "EML-05")


def _parsed(auth_results: str, from_addr: str = "notice@zentr0va-mail.test"):
    raw = (
        f"From: <{from_addr}>\r\nTo: r@example.org\r\nSubject: t\r\n"
        f"Authentication-Results: {auth_results}\r\nMessage-ID: <a@b>\r\n\r\nbody\r\n"
    ).encode()
    return parse(raw)


def test_reads_header_verdicts():
    p = _parsed("mx.example.org; spf=fail smtp.mailfrom=zentr0va-mail.test; dkim=none; dmarc=fail header.from=zentr0va-mail.test")
    r = auth.authenticate(p, b"", lookup=lambda d: None)
    assert r["header"]["spf"] == "fail" and r["header"]["dkim"] == "none" and r["header"]["dmarc"] == "fail"
    assert r["from_domain"] == "zentr0va-mail.test"


def test_dmarc_fail_when_from_fails_all():
    p = _parsed("mx; spf=fail smtp.mailfrom=evil.test; dkim=fail")
    r = auth.authenticate(p, b"", lookup=lambda d: {"policy": "reject"})
    assert r["dmarc"]["result"] == "fail"


def test_dmarc_pass_with_aligned_spf():
    # From zentrova.com, SPF passes for the same registered domain → relaxed alignment → DMARC pass
    p = _parsed("mx; spf=pass smtp.mailfrom=mail.zentrova.com; dkim=none", from_addr="updates@zentrova.com")
    r = auth.authenticate(p, b"", lookup=lambda d: {"policy": "none"})
    assert r["dmarc"]["aligned_spf"] is True and r["dmarc"]["result"] == "pass"


def test_no_dmarc_record_is_none_result():
    p = _parsed("mx; spf=pass smtp.mailfrom=zentrova.com", from_addr="x@zentrova.com")
    r = auth.authenticate(p, b"", lookup=lambda d: None)
    assert r["dmarc"]["result"] == "none" and r["dmarc"]["policy"] is None


def test_dns_failure_is_temperror_not_exception():
    def boom(domain):
        raise RuntimeError("dns down")

    p = _parsed("mx; spf=pass smtp.mailfrom=zentrova.com", from_addr="x@zentrova.com")
    r = auth.authenticate(p, b"", lookup=boom)
    assert r["dmarc"]["result"] == "temperror"
