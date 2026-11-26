"""Acceptance tests (requirements §9) — every detection module run against its fixture.

The demo brand "Zentrova Bank" is seeded and *all* modules are scanned once per test session through
the real scan engine (fixtures website + simulated sources, real DB, real evidence storage, real
headless browser). Each test then proves one acceptance criterion: an alert exists, with evidence
and a timestamp (skill: module-fixtures).
"""

import uuid

import pytest
from sqlalchemy import select

from app.db.models import AppListing, DomainCheck, EvidenceKind, Finding, FindingDecision, ModuleName, RiskLevel, ScanRun
from app.db.session import session_scope
from app.modules.registry import OUTPUT_FIELDS

pytestmark = pytest.mark.usefixtures("database")


@pytest.fixture(scope="session")
def scanned(database):
    """Seed the test brand and run every detection module once through the real scan engine, with the simulated
    sources injected (the product has no demo mode, D-32). Returns {runner: stats}."""
    from app.config import get_settings
    from app.workers import scan
    from tests.conftest import _truncate
    from tests.support.fixture_sources import fixture_runner

    settings = get_settings()
    old = settings.fetch_allow_private_hosts
    old_runner = scan.get_runner
    settings.fetch_allow_private_hosts = ["localhost", "127.0.0.1"]
    scan.get_runner = fixture_runner
    try:
        _truncate()
        from tests.support.seed_test_brand import seed

        brand_id = uuid.UUID(seed())
        # email_posture checks real DNS of real domains; social_media uses live APIs — both have their own tests
        runners = [r for r in scan.runners_for(None) if r not in ("email_posture", "social_media")]
        with session_scope() as db:
            runs = [(r.id, r.stats["runner"]) for r in scan.create_scan_runs(db, brand_id, runners, "manual")]
        stats = {runner: scan.execute_scan(run_id) for run_id, runner in runs}
    finally:
        settings.fetch_allow_private_hosts = old
        scan.get_runner = old_runner
    return {"brand_id": brand_id, "stats": stats, "runs": [r for r, _ in runs]}


def _alert(db, module=None, key=None) -> Finding:
    stmt = select(Finding)
    if module:
        stmt = stmt.where(Finding.module == module)
    if key:
        stmt = stmt.where(Finding.entity_key == key)
    alert = db.scalar(stmt)
    assert alert is not None, f"no alert for module={module} key={key}"
    return alert


def _assert_alert_contract(alert: Finding):
    """module-fixtures contract: an alert with evidence and a timestamp."""
    assert alert.first_seen is not None and alert.last_seen is not None
    assert alert.evidence, "alert has no evidence"
    assert alert.decision == FindingDecision.new
    assert alert.details.get("Risk Level") == alert.risk_level.value


@pytest.mark.req("AC-01", "TYP-01", "TYP-02", "TYP-03", "TYP-04", "TYP-05", "TYP-06", "TYP-07", "TYP-08", "TYP-12",
                 "OBJ-01")
def test_ac01_typosquat_variants_detected(scanned, db):
    """AC-01: generated variants for the configured brand are detected."""
    stats = scanned["stats"]["domains"]
    patterns = stats["variants_by_pattern"]
    for p in ["Character omission", "Character substitution", "Transposition", "Homoglyph", "Added prefix/suffix",
              "Character insertion", "TLD variation"]:
        assert patterns.get(p, 0) > 0, f"no variants generated for {p}"
    assert stats["variants_generated"] > 1000
    alert = _alert(db, key="zentorva.in")  # transposition variant, registered
    _assert_alert_contract(alert)
    assert alert.module == ModuleName.typosquat
    assert alert.details["Fuzzer"] == "Transposition"
    assert 0 <= alert.details["Similarity Score"] <= 100


@pytest.mark.req("TYP-09", "TYP-10", "TYP-11", "TYP-13", "D-11")
def test_newly_registered_domain_from_certificate_transparency(scanned, db):
    """A domain not produced by the fuzzers is found through Certificate Transparency and WHOIS is stored."""
    alert = _alert(db, key="secure-zentrova-banking.in")
    assert alert.details["Discovery Source"] in ("Certificate Transparency",) or alert.details["Fuzzer"]
    check = db.scalar(select(DomainCheck).where(DomainCheck.domain == "secure-zentrova-banking.in"))
    assert check.whois.get("registrar") and check.a_records


@pytest.mark.req("AC-02", "MX-01", "MX-02", "MX-03", "MX-04")
def test_ac02_mx_records_resolved_and_stored(scanned, db):
    """AC-02: MX records are resolved and stored; email-enabled domains are flagged."""
    check = db.scalar(select(DomainCheck).where(DomainCheck.domain == "zentr0va.com"))
    assert check.mx_records == ["10 mail.zentr0va.com"]
    alert = _alert(db, key="zentr0va.com")
    _assert_alert_contract(alert)
    assert alert.module == ModuleName.mx
    assert alert.details["MX Enabled"] is True and alert.details["Email Risk"] == "Medium"
    assert _alert(db, key="zentrova-login.com").details["Email Risk"] == "High"  # MX + live site
    assert _alert(db, key="zentorva.in").details["Email Risk"] == "Low"


@pytest.mark.req("AC-03", "PHI-01", "PHI-02", "PHI-03", "PHI-04", "PHI-05", "PHI-06", "PHI-07", "PHI-08", "PHI-09",
                 "OBJ-02", "FND-11", "FND-12")
def test_ac03_live_phishing_domain_screenshot_and_score(scanned, db):
    """AC-03: a live suspicious domain gets a screenshot and a risk score."""
    alert = _alert(db, key="zentrova-login.com")
    _assert_alert_contract(alert)
    kinds = {e.kind for e in alert.evidence}
    assert {EvidenceKind.screenshot, EvidenceKind.favicon, EvidenceKind.ssl, EvidenceKind.html} <= kinds
    shot = next(e for e in alert.evidence if e.kind == EvidenceKind.screenshot)
    assert shot.storage_key and shot.size > 10_000 and len(shot.sha256) == 64
    d = alert.details
    assert d["Website Live"] is True and d["SSL Present"] is True and d["Page Title"]
    assert d["Favicon Match"] is True and "login" in " ".join(d["Keywords Found"])
    assert alert.suspected_phishing is True
    assert alert.module == ModuleName.phishing and alert.risk_level == RiskLevel.critical


@pytest.mark.req("PHI-08", "D-04")
def test_unrelated_live_site_is_not_suspected_phishing(scanned, db):
    """Negative: a live page without phishing signals is not marked Suspected Phishing."""
    alert = _alert(db, key="zentrova.org")
    assert alert.details["Website Live"] is True
    assert alert.suspected_phishing is False


@pytest.mark.req("D-29", "RSK-09")
def test_unrelated_live_site_capped_at_low(scanned, db):
    """D-29/D-45: a live look-alike whose page shows nothing of the brand (and asks for no login) is Low."""
    alert = _alert(db, key="zentrova.org")
    assert alert.details["Brand Evidence On Page"] is False
    assert alert.risk_level == RiskLevel.low and alert.signals["raw_score"] == 65  # exact + similarity
    assert alert.details["Score Cap"].startswith("No brand content on the page")


@pytest.mark.req("D-29", "RSK-09")
def test_parked_lookalike_scores_low(scanned, db):
    """D-29: a parked / for-sale page with MX, HTTPS and a 'login' link scores Low and is not phishing."""
    alert = _alert(db, key="zentrova.net")
    assert alert.details["Parked Page"] is True
    assert alert.risk_level == RiskLevel.low and alert.signals["cap"] == "parked_page"
    assert alert.details["Score Cap"].startswith("Parked")
    assert alert.suspected_phishing is False


@pytest.mark.req("D-29")
def test_branded_phishing_page_reports_brand_evidence(scanned, db):
    alert = _alert(db, key="zentrova-login.com")
    assert alert.details["Brand Evidence On Page"] is True and alert.signals["cap"] is None
    assert alert.details["Score Cap"] is None
    assert "Brand Evidence On Page" in OUTPUT_FIELDS[ModuleName.phishing]


@pytest.mark.req("AC-04", "APK-01", "APK-02", "APK-03", "APK-04", "APK-05", "APK-06", "APK-07", "APK-08", "APK-09",
                 "OBJ-03")
def test_ac04_simulated_fake_apk_detected(scanned, db):
    """AC-04: at least one simulated fake APK entry is detected, with metadata and SHA256."""
    alert = db.scalar(select(Finding).where(Finding.module == ModuleName.apk,
                                            Finding.entity_key.like("%:com.zentrova.mobilebanking.secure")))
    assert alert is not None, "fake APK not detected"
    _assert_alert_contract(alert)
    d = alert.details
    assert d["Package Name"] == "com.zentrova.mobilebanking.secure"
    assert d["Logo Match"] is True and d["Suspicious Developer"] is True
    assert len(d["SHA256"]) == 64 and d["Version"] == "5.2" and d["Developer"] == "ZB Apps Studio"
    assert alert.risk_level in (RiskLevel.medium, RiskLevel.high)
    assert any(e.kind == EvidenceKind.file for e in alert.evidence)
    assert d["Signer Matches Official"] is False and "ZB Apps Studio" in d["Signed By"]
    keys = [a.entity_key for a in db.scalars(select(Finding).where(Finding.module == ModuleName.apk))]
    assert "apkmirror-sim:com.zentrova.mobile" not in keys, "genuine app (official signature) must not alert"
    assert not any("zentasks" in k for k in keys), "unrelated app must not alert"


@pytest.mark.req("APK-02", "APK-06", "APK-07", "D-26")
def test_repackaged_official_app_detected_by_signature(scanned, db):
    """Same package name and developer label as the official app, but signed with a different key."""
    alert = _alert(db, module=ModuleName.apk, key="modapk-sim:com.zentrova.mobile")
    _assert_alert_contract(alert)
    d = alert.details
    assert d["Official Package"] is True and d["Signer Matches Official"] is False
    assert "re-signed" in alert.title
    assert "publisher_mismatch" in alert.signals["rules"] and "brand_exact_in_domain" in alert.signals["rules"]
    assert alert.risk_level == RiskLevel.high


@pytest.mark.req("AC-05", "ROG-01", "ROG-03", "ROG-04", "ROG-05", "ROG-06")
def test_ac05_unauthorized_play_listing_by_keyword(scanned, db):
    """AC-05: an unauthorized Google Play listing is detected by keyword; status is tracked."""
    alert = _alert(db, key="play:com.quickloan.zentrovahelper")
    _assert_alert_contract(alert)
    d = alert.details
    assert d["Store"] == "Google Play" and d["Publisher"] == "QuickLoan Apps"
    assert d["Official Publisher Match"] is False and d["Install Count"] == "10,000+" and d["App Status"] == "New"
    assert db.scalar(select(Finding).where(Finding.entity_key == "play:com.zentrova.mobile")) is None
    listing = db.scalar(select(AppListing).where(AppListing.package == "com.quickloan.zentrovahelper"))
    assert listing.state == "new"


@pytest.mark.req("ROG-05")
def test_rogue_app_removed_is_tracked(scanned):
    """ROG-05: an app that disappears from the store is marked Removed on its alert."""
    from app.db.models import Brand
    from app.modules.base import BrandContext
    from app.modules.rogue_app.module import RogueAppModule
    from tests.support.fixture_sources import FixturePlaySource

    class WithoutHelper(FixturePlaySource):
        def search(self, ctx, report=None):
            return [r for r in super().search(ctx, report) if r["appId"] != "com.quickloan.zentrovahelper"]

    with session_scope() as db:
        brand = db.get(Brand, scanned["brand_id"])
        ctx = BrandContext.from_brand(brand)
        mod = RogueAppModule(source=WithoutHelper())
        list(mod.run(ctx, db))
        assert mod.stats["apps_removed"] == 1
    with session_scope() as db:
        alert = db.scalar(select(Finding).where(Finding.entity_key == "play:com.quickloan.zentrovahelper"))
        assert alert.details["App Status"] == "Removed"


@pytest.mark.req("AC-06", "SOC-01", "SOC-02", "SOC-03", "SOC-04", "SOC-05", "SOC-06", "SOC-07", "SOC-08", "SOC-09",
                 "SOC-10", "SOC-11", "SOC-12", "OBJ-04")
def test_ac06_simulated_fake_social_account(scanned, db):
    """AC-06: a simulated fake social account is detected on every Phase-1 platform."""
    alert = _alert(db, key="x:zentrova_support")
    _assert_alert_contract(alert)
    d = alert.details
    assert d["Logo Match"] is True and d["Bio Mentions Brand"] is True and "support" in d["Support Terms"]
    assert d["Followers"] == 1284 and d["Username"] == "@zentrova_support"
    assert any(e.kind == EvidenceKind.screenshot for e in alert.evidence)
    platforms = {a.details["Platform"] for a in db.scalars(select(Finding).where(Finding.module == ModuleName.social))}
    assert platforms >= {"X", "Facebook", "Instagram", "LinkedIn", "Telegram"}
    assert db.scalar(select(Finding).where(Finding.entity_key == "x:zentrovabank")) is None, "official handle"


@pytest.mark.req("AC-07", "DOC-01", "DOC-02", "DOC-03", "DOC-04", "DOC-05", "DOC-06", "DOC-07", "DOC-08", "OBJ-05")
def test_ac07_indexed_document_with_brand_keyword(scanned, db):
    """AC-07: an indexed document containing the brand keyword is detected and classified."""
    salary = _alert(db, module=ModuleName.documents, key="http://localhost:8088/docs/Zentrova_Internal_Salary_Review_2026.pdf")
    _assert_alert_contract(salary)
    d = salary.details
    assert d["File Type"] == "PDF" and "zentrova" in d["Brand Match"]
    assert d["Exposure Confidence"] == "High" and {"confidential", "salary"} <= set(d["Sensitive Patterns"])
    assert d["Emails Found"] >= 5 and "zentrova.com" in d["Domains Found"]
    assert salary.risk_level == RiskLevel.critical
    xlsx = _alert(db, key="http://localhost:8088/docs/zentrova_customer_list_internal.xlsx")
    assert xlsx.details["File Type"] == "XLSX" and xlsx.details["Discovery Source"] == "Public Share Link"
    brochure = _alert(db, key="http://localhost:8088/docs/zentrova_home_loans_brochure.docx")
    assert brochure.risk_level == RiskLevel.medium and brochure.details["Exposure Confidence"] == "Medium"


@pytest.mark.req("AC-08", "LOGO-01", "LOGO-02", "LOGO-03", "LOGO-04", "LOGO-05", "LOGO-06", "OBJ-06")
def test_ac08_official_logo_on_test_website(scanned, db):
    """AC-08: the official logo is detected on a test website, with screenshot evidence."""
    alert = _alert(db, module=ModuleName.logo, key="http://localhost:8088/partner/")
    _assert_alert_contract(alert)
    assert alert.details["Logo Match Score"] >= 85
    assert any(e.kind == EvidenceKind.screenshot for e in alert.evidence)
    assert alert.risk_level in (RiskLevel.medium, RiskLevel.high)
    assert db.scalar(select(Finding).where(Finding.module == ModuleName.logo,
                                         Finding.entity_key == "http://localhost:8088/innocent/")) is None


@pytest.mark.req("AC-09", "DSH-21", "OBJ-07")
def test_ac09_alerts_exist_for_all_modules(scanned, db):
    """AC-09 (data side): alerts exist for every module type; the UI test proves they display."""
    from app.modules.registry import PHASE1_MODULES

    modules = set(db.scalars(select(Finding.module).distinct()))
    assert modules >= set(PHASE1_MODULES)


@pytest.mark.req("FND-07", "FND-13", "RDA-17")
def test_scan_runs_recorded(scanned, db):
    """Every scan is recorded with status, statistics and per-component results."""
    runs = db.scalars(select(ScanRun).where(ScanRun.id.in_(scanned["runs"]))).all()
    assert len(runs) == 6
    assert all(r.started_at and r.finished_at for r in runs)
    assert all(r.stats.get("findings", 0) > 0 for r in runs)  # every detection runner found something
    for r in runs:
        assert r.components, f"{r.stats['runner']} recorded no components"
        assert all(c["status"] in ("ok", "skipped", "not_configured", "unavailable", "failed") for c in r.components)
    by_runner = {r.stats["runner"]: r for r in runs}
    assert by_runner["domains"].status.value == "completed"
    assert {c["name"] for c in by_runner["domains"].components} >= {
        "Variant generation", "DNS resolution", "WHOIS/RDAP", "Website probe & browser capture"}


@pytest.mark.req("D-19", "D-21")
def test_rescan_updates_instead_of_duplicating(scanned):
    """A second scan updates existing alerts and does not duplicate evidence."""
    from app.config import get_settings
    from app.workers.scan import create_scan_runs, execute_scan

    with session_scope() as db:
        before = {a.entity_key: len(a.evidence) for a in db.scalars(select(Finding).where(Finding.module == ModuleName.apk))}
        run = create_scan_runs(db, scanned["brand_id"], ["apk"], "manual")[0]
        run_id = run.id
    from app.workers import scan
    from tests.support.fixture_sources import fixture_runner

    s = get_settings()
    old, s.fetch_allow_private_hosts = s.fetch_allow_private_hosts, ["localhost", "127.0.0.1"]
    old_runner, scan.get_runner = scan.get_runner, fixture_runner
    try:
        stats = execute_scan(run_id)
    finally:
        s.fetch_allow_private_hosts = old
        scan.get_runner = old_runner
    assert stats["created"] == 0 and stats["updated"] >= 1
    with session_scope() as db:
        after = {a.entity_key: len(a.evidence) for a in db.scalars(select(Finding).where(Finding.module == ModuleName.apk))}
    assert after == before
