"""End-to-end UI test in a real browser against the running stack (AC-09, AC-10, DSH-*).

Runs only when E2E_WEB_URL is set, e.g. after `docker compose --profile app up -d` and a demo scan:
    E2E_WEB_URL=http://localhost:3000 E2E_API_URL=http://localhost:8010 REQ_RESULTS_APPEND=1 \
        python -m uv run pytest tests/e2e
Screenshots are saved to docs/demo/screenshots/ for the demo guide.
"""

import os
import re
from pathlib import Path

import httpx
import pytest

WEB = os.environ.get("E2E_WEB_URL")
API = os.environ.get("E2E_API_URL", "http://localhost:8010")
EMAIL = os.environ.get("E2E_EMAIL", "")
PASSWORD = os.environ.get("E2E_PASSWORD", "")
ALLOW_WRITE = os.environ.get("E2E_ALLOW_WRITE") == "1"
SHOTS = Path(__file__).resolve().parents[3] / "docs" / "demo" / "screenshots"

pytestmark = pytest.mark.skipif(not (WEB and EMAIL and PASSWORD),
                                reason="E2E_WEB_URL / E2E_EMAIL / E2E_PASSWORD not set (needs the running stack)")

MODULE_LABELS = {
    "typosquat": "Typosquat", "mx": "MX", "phishing": "Phishing", "apk": "APK", "rogue_app": "Rogue",
    "social": "Social", "documents": "Document", "logo": "Logo",
}


@pytest.fixture(scope="module")
def token():
    r = httpx.post(f"{API}/api/v1/auth/login", json={"email": EMAIL, "password": PASSWORD}, timeout=20)
    r.raise_for_status()
    return r.json()["access_token"]


@pytest.fixture(scope="module")
def browser_page():
    from playwright.sync_api import sync_playwright

    SHOTS.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch()
        context = browser.new_context(viewport={"width": 1440, "height": 900})
        page = context.new_page()
        page.goto(f"{WEB}/login")
        page.get_by_label("Email").fill(EMAIL)
        page.get_by_label("Password").fill(PASSWORD)
        page.get_by_role("button", name="Sign in").click()
        page.wait_for_url(re.compile(rf"^{re.escape(WEB)}/?(\?.*)?$"), timeout=20_000)
        yield page
        browser.close()


@pytest.mark.req("AC-09", "DSH-01", "DSH-02", "DSH-03", "DSH-04", "DSH-05", "DSH-06", "DSH-17", "FND-03")
def test_executive_dashboard_renders(browser_page):
    """AC-09: after login the executive dashboard shows the KPI tiles and charts."""
    page = browser_page
    for text in ["New phishing domains", "New impersonation accounts", "New rogue apps",
                 "Sensitive document exposures"]:
        page.get_by_text(text, exact=False).first.wait_for(timeout=20_000)
    page.wait_for_timeout(1500)  # chart animation
    page.screenshot(path=str(SHOTS / "01-dashboard.png"), full_page=True)


@pytest.mark.req("AC-09", "DSH-07", "DSH-09", "DSH-12", "DSH-21")
def test_alert_queue_shows_every_module(browser_page, token):
    """AC-09: the alert queue displays the alerts of every module that has any (real data)."""
    page = browser_page
    headers = {"Authorization": f"Bearer {token}"}
    shown = 0
    for module in MODULE_LABELS:
        total = httpx.get(f"{API}/api/v1/alerts", params={"module": module, "page_size": 1}, headers=headers).json()["total"]
        if not total:
            continue  # this module has found nothing for the monitored brands (yet)
        page.goto(f"{WEB}/alerts?module={module}")
        page.locator("tbody tr").first.wait_for(timeout=20_000)
        assert page.locator("tbody tr").count() >= 1, f"no rows shown for {module} although the API has {total}"
        shown += 1
    assert shown >= 1, "no alerts at all — run a scan first"
    page.goto(f"{WEB}/alerts")
    page.locator("tbody tr").first.wait_for(timeout=20_000)
    page.wait_for_timeout(800)
    page.screenshot(path=str(SHOTS / "02-alert-queue.png"), full_page=True)


@pytest.mark.req("AC-10", "DSH-08", "DSH-10")
def test_analyst_changes_status_in_ui(browser_page, token):
    """AC-10: an analyst changes an alert's status from the alert page; history records it."""
    if not ALLOW_WRITE:
        pytest.skip("read-only run (set E2E_ALLOW_WRITE=1 to test a real status change)")
    page = browser_page
    headers = {"Authorization": f"Bearer {token}"}
    alerts = httpx.get(f"{API}/api/v1/alerts", params={"module": "phishing", "status": "New",
                                                       "sort": "risk"}, headers=headers).json()["items"]
    if not alerts:
        pytest.skip("no New phishing alert left to review")
    alert_id = alerts[0]["id"]
    page.goto(f"{WEB}/alerts/{alert_id}")
    page.get_by_text("Why this score", exact=False).first.wait_for(timeout=20_000)
    page.wait_for_timeout(1000)
    page.screenshot(path=str(SHOTS / "03-alert-detail.png"), full_page=True)
    page.get_by_label("New status").click()
    page.get_by_role("option", name="Under Review").click()
    page.locator("#status-note").fill("E2E: checking hosting provider")
    page.get_by_role("button", name="Mark as Under Review").click()
    page.get_by_text("Status changed to Under Review").wait_for(timeout=20_000)
    detail = httpx.get(f"{API}/api/v1/alerts/{alert_id}", headers=headers).json()
    assert detail["status"] == "Under Review"
    assert any(e["note"] == "E2E: checking hosting provider" for e in detail["events"])
    # put it back so the demo data stays fresh
    httpx.post(f"{API}/api/v1/alerts/{alert_id}/status", json={"status": "New", "note": "E2E reset"}, headers=headers)


@pytest.mark.req("DSH-20")
def test_phone_layout(browser_page):
    """DSH-20: the queue and dashboard are usable at phone width."""
    page = browser_page
    page.set_viewport_size({"width": 390, "height": 844})
    page.goto(f"{WEB}/alerts")
    page.locator("tbody tr").first.wait_for(timeout=20_000)
    page.screenshot(path=str(SHOTS / "04-alerts-phone.png"), full_page=False)
    width = page.evaluate("document.documentElement.scrollWidth")
    assert width <= 400, f"page scrolls horizontally on a phone ({width}px)"
    page.set_viewport_size({"width": 1440, "height": 900})


@pytest.mark.req("RDA-19", "RDA-02")
def test_dashboard_shows_error_when_api_fails(browser_page):
    """RDA-19: if the stats API fails the dashboard says so — it never shows zeros or loads forever."""
    page = browser_page
    page.route("**/api/v1/stats/executive*", lambda route: route.fulfill(status=500, body='{"detail":"boom"}',
                                                                          content_type="application/json"))
    try:
        page.goto(f"{WEB}/")
        page.get_by_text("Couldn't load the dashboard").wait_for(timeout=60_000)
        page.get_by_role("button", name="Retry").wait_for()
        assert page.get_by_text("New phishing domains").count() == 0
    finally:
        page.unroute("**/api/v1/stats/executive*")


@pytest.mark.req("RDA-02")
def test_dashboard_states_scan_coverage(browser_page, token):
    """RDA-02: the dashboard says when nothing has been scanned, or when scan parts could not run."""
    page = browser_page
    stats = httpx.get(f"{API}/api/v1/stats/executive", headers={"Authorization": f"Bearer {token}"}, timeout=20).json()
    page.goto(f"{WEB}/")
    page.get_by_text("New phishing domains").first.wait_for(timeout=20_000)
    if stats["last_completed_scan_at"] is None:
        page.get_by_text("No scans have run yet").wait_for()
    elif stats["open_alerts"] == 0:
        page.get_by_text("No threats detected.").wait_for()
    if stats["last_completed_scan_at"] and stats["components_unavailable"]:
        page.get_by_text("could not run in the latest scans").first.wait_for()


@pytest.mark.req("RDA-17", "RDA-03")
def test_scans_page_lists_components(browser_page, token):
    """RDA-17: a finished scan shows which parts ran and which could not run."""
    page = browser_page
    scans = httpx.get(f"{API}/api/v1/scans", headers={"Authorization": f"Bearer {token}"}, timeout=20).json()
    index = next((i for i, s in enumerate(scans) if s["components"]), None)
    if index is None:
        pytest.skip("no scan with component results yet — run a scan first")
    page.goto(f"{WEB}/scans")
    page.get_by_role("button", name="Show scan details").nth(index).click()
    page.get_by_role("list", name="Scan components").first.wait_for(timeout=20_000)
    page.screenshot(path=str(SHOTS / "06-scan-components.png"), full_page=True)


@pytest.mark.req("RDA-03")
def test_integrations_page(browser_page):
    """RDA-03: every integration is listed with whether it is configured."""
    page = browser_page
    page.goto(f"{WEB}/integrations")
    for name in ("urlscan.io", "Certificate Transparency (crt.sh)", "Telegram search API (Telethon)"):
        page.get_by_text(name, exact=False).first.wait_for(timeout=20_000)
    page.screenshot(path=str(SHOTS / "07-integrations.png"), full_page=True)
