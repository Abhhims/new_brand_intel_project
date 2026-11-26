import uuid

import pytest

from app.modules.base import BrandContext

pytestmark = pytest.mark.req("ROG-04", "APK-03", "SOC-06", "SOC-07", "DOC-04", "D-25")


def ctx(**kw) -> BrandContext:
    base = dict(id=uuid.uuid4(), name="Kodachadri Chits Private Limited",
                keywords=["KCPL", "mykcpl", "Kodachadri Chits", "chitkart", "KCPL Agent"],
                product_terms=["mykcpl", "chitkart", "KCPL Agent"],
                official_domains=["mykcpl.com", "chitkart.com"], official_packages=[], official_publishers=[],
                official_handles=[], email_domains=[], logo_hashes=[], favicon_hashes=[], favicon_mmh3=[])
    base.update(kw)
    return BrandContext(**base)


def test_term_strength():
    c = ctx()
    assert c.weak_terms == ["KCPL"]
    assert "chitkart" in c.strong_terms and "Kodachadri Chits" in c.strong_terms
    assert set(c.context_words) >= {"kodachadri", "chits", "chitkart", "mykcpl"} and "kcpl" not in c.context_words


@pytest.mark.parametrize(("name", "text"), [
    ("Kanawha County Public Library", "Kanawha County Public Library app. KCPL card holders"),
    ("KCPL Service & IOT", "Kirloskar KCPL service management"),
    ("MyKPL", "Solus UK loyalty app"),
    ("KCL - Kerala Cricket League", "Official app of the Kerala Cricket League"),
    ("RKCPL", "Veenus software ERP"),
])
def test_unrelated_acronym_collisions_are_not_relevant(name, text):
    assert ctx().relevance(f"{name} {text}", name=name).relevant is False


@pytest.mark.parametrize(("name", "text"), [
    ("KCPL Chits Helper", "Pay your KCPL chit instalments"),            # abbreviation + context word
    ("Chitkart Loans", "Instant chit loans"),                           # distinctive name
    ("Kodachadri Chit Fund App", "Kodachadri chits members"),           # distinctive phrase
    ("Chitkartt", "chit fund"),                                         # look-alike of a distinctive name
    ("MyKCPL Pay", "pay dues"),                                         # distinctive keyword
])
def test_brand_uses_are_relevant(name, text):
    assert ctx().relevance(f"{name} {text}", name=name).relevant is True


def test_zentrova_demo_brand_unchanged():
    z = ctx(name="Zentrova Bank", keywords=["zentrova", "zentrova bank"], product_terms=["zentrova pay"])
    assert z.weak_terms == [] and z.relevance("Zentrova Bank Loan Helper", name="Zentrova Bank Loan Helper").relevant
