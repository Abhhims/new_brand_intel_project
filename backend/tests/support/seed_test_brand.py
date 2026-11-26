"""Create (or reset) the fictional TEST brand "Zentrova Bank" from tests/fixtures/brand/ (DEL-08, D-09, D-32).

Test use only: it runs against the test database, and scans for it use the simulated sources injected by
tests/support/fixture_sources.py. The product has no demo mode.
"""

import json
import mimetypes

from sqlalchemy import select

from app.core.assets import add_asset
from app.db.models import AllowKind, AssetKind, Brand, BrandAllow
from app.db.session import session_scope
from tests.support.fixture_sources import FIXTURES_ROOT


def seed(reset: bool = False) -> str:
    spec = json.loads((FIXTURES_ROOT / "brand" / "zentrova.json").read_text(encoding="utf-8"))
    with session_scope() as db:
        brand = db.scalar(select(Brand).where(Brand.name == spec["name"]))
        if brand and reset:
            db.delete(brand)
            db.flush()
            brand = None
        if brand:
            print(f"seed_test_brand: '{brand.name}' already exists ({brand.id})")
            return str(brand.id)
        brand = Brand(name=spec["name"], description=spec["description"], keywords=spec["keywords"],
                      product_terms=spec["product_terms"])
        brand.allowlist = [BrandAllow(kind=AllowKind(a["kind"]), value=a["value"]) for a in spec["allowlist"]]
        db.add(brand)
        db.flush()
        for asset in spec["assets"]:
            path = FIXTURES_ROOT / "brand" / asset["file"]
            add_asset(db, brand, AssetKind(asset["kind"]), path.name, path.read_bytes(),
                      mimetypes.guess_type(path.name)[0] or "image/png")
        print(f"seed_test_brand: created '{brand.name}' ({brand.id})")
        return str(brand.id)
