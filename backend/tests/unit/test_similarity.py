import pytest

from app.core.similarity import (
    brand_terms_in_text,
    domain_label,
    fold_homoglyphs,
    similarity,
    to_unicode_domain,
)

pytestmark = pytest.mark.req("TYP-13", "SOC-06", "SOC-07", "APK-03", "APK-04")


def test_fold_homoglyphs_cyrillic_and_digits():
    assert "zentrova" in fold_homoglyphs("zеntrоva")  # Cyrillic е and о
    assert "zentrova" in fold_homoglyphs("zentr0va")
    assert "paypal" in fold_homoglyphs("paypa1")
    assert "modern" in fold_homoglyphs("rnodern")


def test_idn_decoded():
    assert to_unicode_domain("xn--zntrova-2fg.com") != "xn--zntrova-2fg.com"


def test_domain_label_uses_registered_domain():
    assert domain_label("login.zentrova-secure.co.in") == "zentrova-secure"
    assert domain_label("https://www.zentrova.com/path") == "zentrova"


@pytest.mark.parametrize(
    ("candidate", "minimum"),
    [("zentrova", 100), ("zentr0va", 100), ("zentorva", 80), ("zentrova-login", 100),
     ("zеntrova", 100), ("zentova", 85)],
)
def test_similar_names_score_high(candidate, minimum):
    assert similarity(candidate, "zentrova") >= minimum


def test_unrelated_names_score_low():
    assert similarity("weatherapp", "zentrova") < 50


def test_similarity_bounds():
    assert 0 <= similarity("", "zentrova") <= 100


def test_brand_terms_in_text():
    text = "Welcome to ZENTROVA Bank secure login. Contact Zentrova-Support"
    assert brand_terms_in_text(text, ["zentrova", "zentrova bank", "other"]) == ["zentrova", "zentrova bank"]
