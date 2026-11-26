import pytest

from app.core.allowlist import normalize

pytestmark = pytest.mark.req("FND-06")


@pytest.mark.parametrize(
    ("kind", "raw", "expected"),
    [
        ("social_handle", "https://www.instagram.com/kodachadrichits/", "instagram.com/kodachadrichits"),
        ("social_handle", "https://www.instagram.com/chit_kart/", "instagram.com/chit_kart"),
        ("social_handle", "https://www.linkedin.com/company/chitkart/?original_referer=", "linkedin.com/chitkart"),
        ("social_handle", "https://www.linkedin.com/company/kodachadrichits/", "linkedin.com/kodachadrichits"),
        ("social_handle", "https://www.youtube.com/@kodachadrichitsofficial", "youtube.com/kodachadrichitsofficial"),
        ("social_handle", "https://www.facebook.com/kodachadrichitsofficial/", "facebook.com/kodachadrichitsofficial"),
        ("social_handle", "https://x.com/ZentrovaBank", "x.com/zentrovabank"),
        ("social_handle", "https://twitter.com/ZentrovaBank", "x.com/zentrovabank"),
        ("social_handle", "https://t.me/zentrova_news", "t.me/zentrova_news"),
        ("social_handle", "instagram.com/zentrova/", "instagram.com/zentrova"),
        ("social_handle", "@ZentrovaBank", "zentrovabank"),
        ("social_handle", "zentrova_official", "zentrova_official"),
        ("domain", "https://www.MyKCPL.com/login", "mykcpl.com"),
        ("domain", "chitkart.com", "chitkart.com"),
        ("email_domain", "support@mykcpl.com", "mykcpl.com"),
        ("package", "https://play.google.com/store/apps/details?id=com.bharatchits.androidapp&hl=en", "com.bharatchits.androidapp"),
        ("package", "com.Zentrova.Mobile", "com.zentrova.mobile"),
        ("publisher", " Kodachadri Fintech Pvt Ltd ", "Kodachadri Fintech Pvt Ltd"),
    ],
)
def test_normalize(kind, raw, expected):
    assert normalize(kind, raw) == expected


@pytest.mark.req("D-26")
@pytest.mark.parametrize("raw", [
    "89:D3:8A:FD:9B:E5:0A:DF:18:33:62:8E:82:5A:05:86:9C:CD:B2:D8:52:54:CD:F0:72:09:CA:E1:4B:11:5E:FC",
    "SHA-256: 89d38afd9be50adf1833628e825a05869ccdb2d85254cdf07209cae14b115efc",
    "89d38afd 9be50adf 1833628e 825a0586 9ccdb2d8 5254cdf0 7209cae1 4b115efc",
])
def test_signing_cert_fingerprint_formats(raw):
    assert normalize("signing_cert", raw) == "89D38AFD9BE50ADF1833628E825A05869CCDB2D85254CDF07209CAE14B115EFC"


@pytest.mark.req("D-45")
def test_findings_for_allowlisted_assets_are_closed_exactly():
    """navi.com was found before it was added as official: the open finding is closed; look-alikes stay open."""
    import uuid

    from app.core.findings import close_authorized
    from app.db.models import AllowKind, BrandAllow, Finding, FindingDecision, ModuleName

    brand_id = uuid.uuid4()
    allow = [BrandAllow(brand_id=brand_id, kind=AllowKind.domain, value="navi.com")]

    def finding(key):
        return Finding(id=uuid.uuid4(), brand_id=brand_id, module=ModuleName.phishing, entity_key=key,
                       decision=FindingDecision.new, details={})
    own, sub, lookalike = finding("navi.com"), finding("pay.navi.com"), finding("banknavi.com")

    class FakeDB:
        def __init__(self):
            self.calls, self.added = 0, []

        def scalars(self, _stmt):
            self.calls += 1
            return allow if self.calls == 1 else [own, sub, lookalike]

        def add(self, obj):
            self.added.append(obj)

        def flush(self):
            pass

    db = FakeDB()
    assert close_authorized(db, brand_id, (ModuleName.phishing,)) == 2
    assert own.decision == sub.decision == FindingDecision.legitimate and "allowlist" in own.decision_note
    assert lookalike.decision == FindingDecision.new
    assert len(db.added) == 2  # one timeline event per closed finding


@pytest.mark.req("D-45", "D-26")
def test_fake_apks_are_never_closed_by_package_name():
    """A repackaged APK keeps the official package name; only the signer tells it apart."""
    import uuid

    from app.core.findings import close_authorized
    from app.db.models import ModuleName

    class NoDB:
        def scalars(self, _stmt):
            raise AssertionError("must not query: APK findings are never auto-closed")

    assert close_authorized(NoDB(), uuid.uuid4(), (ModuleName.apk,)) == 0


def test_same_handle_on_two_sites_stays_two_entries():
    from app.core.allowlist import social_handle
    x, fb = normalize("social_handle", "https://x.com/axisbank"), normalize("social_handle", "https://www.facebook.com/axisbank")
    assert x != fb
    assert social_handle(x) == social_handle(fb) == "axisbank"  # scans still match on the plain handle
