"""RDA-01 / RDA-04 / D-32: the product contains no demo mode and no path to test data."""

import pathlib
import re

import pytest

pytestmark = pytest.mark.req("RDA-01", "RDA-04")

BACKEND = pathlib.Path(__file__).resolve().parents[2]
PATTERN = re.compile(r"demo_mode|allow_demo_mode|fixtures_dir|fixtures_base_url|from app\.modules import fixtures"
                     r"|Fixture\w*Source|FixtureInfra|tests\.fixtures|tests/fixtures")


def test_product_code_has_no_demo_or_fixture_paths():
    offenders = [str(p.relative_to(BACKEND)) for p in (BACKEND / "app").rglob("*.py")
                 if "alembic" not in p.parts and PATTERN.search(p.read_text(encoding="utf-8"))]
    offenders += [str(p.relative_to(BACKEND)) for p in (BACKEND / "scripts").rglob("*.py")
                  if PATTERN.search(p.read_text(encoding="utf-8"))]
    assert offenders == []


def test_settings_have_no_demo_switch():
    from app.config import Settings

    assert not {"allow_demo_mode", "fixtures_dir", "fixtures_base_url"} & set(Settings.model_fields)


def test_brand_schemas_reject_demo_mode():
    from pydantic import ValidationError

    from app.schemas.api import BrandIn, BrandUpdate

    with pytest.raises(ValidationError):
        BrandIn(name="Example Bank", keywords=["examplebank"], demo_mode=True)
    with pytest.raises(ValidationError):
        BrandUpdate(demo_mode=True)
