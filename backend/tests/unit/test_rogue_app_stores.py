"""D-41: Google Play detail pages + scam checks, Apple App Store search, both stores tracked."""

import uuid
from unittest.mock import MagicMock

import pytest

from app.core.scoring import score
from app.db.models import ModuleName, RiskLevel
from app.modules.base import BrandContext
from app.modules.rogue_app.module import RogueAppModule


def _ctx() -> BrandContext:
    return BrandContext(id=uuid.uuid4(), name="Zentrova Bank", keywords=["zentrova"], product_terms=[],
                        official_domains=["zentrova.example"], official_packages=["com.zentrova.app"],
                        official_publishers=["Zentrova Bank Ltd"], official_handles=[], email_domains=[],
                        logo_hashes=[], favicon_hashes=[], favicon_mmh3=[])


class FakePlay:
    def search(self, ctx, report):
        report.ok("Google Play search", terms=1)
        return [{"appId": "com.zentrova.app", "title": "Zentrova Bank", "developer": "Zentrova Bank Ltd"},
                {"appId": "com.zentrova.care", "title": "Zentrova Customer Care", "developer": "Help Desk",
                 "summary": "support"},
                {"appId": "com.cooking", "title": "Pasta recipes", "developer": "Chef"}]

    def details(self, app_id):
        assert app_id == "com.zentrova.care"  # only flagged apps get the extra request
        return {"developerEmail": "zentrova.help@gmail.com", "installs": "10,000+", "version": "2.1",
                "description": "Zentrova customer care helpline, call 9876543210 for KYC update",
                "developerAddress": "Unknown"}


class FakeApple:
    def search(self, ctx, report):
        report.ok("Apple App Store search", terms=1)
        return [{"store": "Apple App Store", "appId": "com.fake.zentrovapay", "title": "Zentrova Pay Wallet",
                 "developer": "Some Dev", "description": "Zentrova wallet", "url": "https://apps.apple.com/x",
                 "details_loaded": True}]


@pytest.mark.req("ROG-01", "ROG-03", "ROG-04", "ROG-02")
def test_play_details_scam_checks_and_apple_store():
    db = MagicMock()
    db.scalar.return_value = None
    db.scalars.return_value.all.return_value = []
    mod = RogueAppModule(source=FakePlay(), apple_source=FakeApple())
    dets = {d.entity_key: d for d in mod.run(_ctx(), db)}
    assert set(dets) == {"play:com.zentrova.care", "appstore:com.fake.zentrovapay"}  # official + unrelated skipped
    care = dets["play:com.zentrova.care"].details
    assert care["Developer Email"] == "zentrova.help@gmail.com" and care["Developer Uses Free E-mail"] is True
    assert care["Scam Contacts"] == ["phone: 9876543210"] and "helpline" in care["Scam Phrases"]
    assert care["Install Count"] == "10,000+" and care["Version"] == "2.1"
    r = score(dets["play:com.zentrova.care"].signals, ModuleName.rogue_app)
    assert r.level == RiskLevel.high and {"scam_contact_details", "scam_language"} <= set(r.fired)
    assert dets["appstore:com.fake.zentrovapay"].details["Store"] == "Apple App Store"
    assert mod.stats["apple_apps"] == 1 and mod.stats["details_read"] == 1
