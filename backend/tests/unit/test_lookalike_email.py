import pytest

from app.modules.email.posture import domain_can_send

pytestmark = pytest.mark.req("EML-17")


def test_domain_with_spf_can_send():
    assert domain_can_send(["v=spf1 include:x ~all"]) is True


def test_domain_with_mx_only_can_receive_not_send():
    # no SPF record published -> not flagged as "can send as" (MX is handled by the MX rule)
    assert domain_can_send([]) is False


def test_unrelated_txt_is_not_spf():
    assert domain_can_send(["google-site-verification=abc", "something=else"]) is False
