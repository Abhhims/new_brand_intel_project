import pytest

from app.db.models import ScanStatus
from app.modules.base import ScanReport, derive_run_status

pytestmark = pytest.mark.req("RDA-17", "RDA-21", "RDA-03")


def test_all_ok_is_completed():
    r = ScanReport()
    r.ok("DNS resolution", resolved=10)
    assert derive_run_status(r.as_list(), crashed=False) == ScanStatus.completed


def test_no_components_is_completed():
    assert derive_run_status([], crashed=False) == ScanStatus.completed


def test_not_configured_is_partially_completed():
    r = ScanReport()
    r.ok("Telegram public pages")
    r.not_configured("Telegram API", "no credentials")
    assert derive_run_status(r.as_list(), False) == ScanStatus.partially_completed


def test_unavailable_is_partially_completed():
    r = ScanReport()
    r.unavailable("Web search", "rate limited")
    assert derive_run_status(r.as_list(), False) == ScanStatus.partially_completed


def test_skipped_alone_is_completed():
    r = ScanReport()
    r.skipped("Removal check", "a store search failed")
    assert derive_run_status(r.as_list(), False) == ScanStatus.completed


def test_failure_beats_reduced_coverage():
    r = ScanReport()
    r.unavailable("Web search", "rate limited")
    r.failed("Listing pages", "3 of 9 failed")
    assert derive_run_status(r.as_list(), False) == ScanStatus.completed_with_errors


def test_fatal_component_fails_run():
    r = ScanReport()
    r.failed("Web search", "all queries failed", fatal=True)
    assert derive_run_status(r.as_list(), False) == ScanStatus.failed


def test_fatal_unavailable_fails_run():
    r = ScanReport()
    r.unavailable("Web search", "rate limited", fatal=True)
    assert derive_run_status(r.as_list(), False) == ScanStatus.failed


def test_crash_fails_run():
    assert derive_run_status([], crashed=True) == ScanStatus.failed


def test_repeated_component_keeps_worst_status_and_sums_counts():
    r = ScanReport()
    r.ok("DNS resolution", resolved=5)
    r.failed("DNS resolution", "timeout", unresolved=2)
    r.ok("DNS resolution", resolved=1)
    (c,) = r.as_list()
    assert c["status"] == "failed" and c["counts"] == {"resolved": 6, "unresolved": 2}


def test_components_keep_insertion_order():
    r = ScanReport()
    r.ok("B")
    r.ok("A")
    assert [c["name"] for c in r.as_list()] == ["B", "A"]


def test_errors_lists_failed_and_unavailable_messages():
    r = ScanReport()
    r.failed("A", "boom")
    r.unavailable("B", "down")
    r.not_configured("C", "no key")
    assert r.errors == ["A: boom", "B: down"]
