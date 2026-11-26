"""D-29: what a live look-alike page says about the brand — brand text, official-site references, parking."""

import uuid

import pytest

from app.core.browser import PageCapture
from app.modules.base import BrandContext
from app.modules.pagecheck import analyse

pytestmark = pytest.mark.req("D-29", "PHI-08")


def ctx() -> BrandContext:
    return BrandContext(id=uuid.uuid4(), name="Kodachadri Chits Private Limited",
                        keywords=["KCPL", "mykcpl", "Kodachadri Chits", "chitkart"],
                        product_terms=["chitkart"],
                        official_domains=["mykcpl.com", "chitkart.com"], official_packages=[],
                        official_publishers=[], official_handles=[], email_domains=["kcpl.in"],
                        logo_hashes=[], favicon_hashes=[], favicon_mmh3=[])


def page(text: str = "", title: str = "", html: str = "", url: str = "https://mykcpi.com/",
         final_url: str | None = None) -> PageCapture:
    return PageCapture(url=url, final_url=final_url or url, status=200, title=title, text=text,
                       html=html or text, screenshot=None)


def test_unrelated_business_with_login_has_no_brand_evidence():
    f = analyse(page(title="Specio | Sign in", text="Sign in to your Specio lab account. Password"), ctx())
    assert f.login_payment is True
    assert f.brand_terms_found == [] and f.official_refs == []
    assert f.brand_evidence is False and f.parked is False


def test_brand_name_on_page_is_brand_evidence():
    f = analyse(page(title="Login", text="Welcome to Kodachadri Chits. Enter your password."), ctx())
    assert "Kodachadri Chits" in f.brand_terms_found
    assert f.brand_evidence is True


def test_short_abbreviation_alone_is_not_brand_evidence():
    # D-25: "KCPL" also means Kansas City Public Library
    f = analyse(page(title="KCPL", text="KCPL library card login"), ctx())
    assert f.brand_evidence is False


def test_link_to_official_site_is_brand_evidence():
    f = analyse(page(text="Customer care", html='<a href="https://www.mykcpl.com/pay">Pay</a>'), ctx())
    assert f.official_refs == ["mykcpl.com"]
    assert f.brand_evidence is True


def test_official_email_domain_is_brand_evidence():
    f = analyse(page(text="Write to support@kcpl.in"), ctx())
    assert f.official_refs == ["kcpl.in"]


def test_page_naming_its_own_lookalike_domain_is_not_brand_evidence():
    # a parked/placeholder page always prints its own domain; that is not brand content
    f = analyse(page(text="mykcpl.in — coming soon", url="https://mykcpl.in/"), ctx())
    assert f.brand_terms_found == [] and f.brand_evidence is False


@pytest.mark.parametrize(("final_url", "text"), [
    ("https://www.hugedomains.com/domain_profile.cfm?d=chitmart.com", "Get this domain"),
    ("https://sedo.com/search/details/?domain=x.com", ""),
    ("https://example.com/lander", ""),
    ("https://x.com/", "This domain is for sale! Buy this domain today."),
    ("https://x.com/", "This domain may be for sale"),
])
def test_parked_pages_detected(final_url, text):
    assert analyse(page(text=text, final_url=final_url), ctx()).parked is True


def test_ordinary_shop_mentioning_domains_is_not_parked():
    assert analyse(page(text="Register an account to buy shoes"), ctx()).parked is False
