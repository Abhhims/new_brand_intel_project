"""D-42: Common Crawl as an APK source — brand slugs, paced prefix lookups, archived page read from the WARC."""

import gzip
import uuid

import pytest

from app.config import get_settings
from app.core.fetch import FetchResult
from app.modules.apk import commoncrawl
from app.modules.base import BrandContext, ScanReport


def _ctx() -> BrandContext:
    return BrandContext(id=uuid.uuid4(), name="Navi", keywords=["Navi UPI", "Navi", "navi loan"],
                        product_terms=["navi payments"], official_domains=[], official_packages=[],
                        official_publishers=[], official_handles=[], email_domains=[], logo_hashes=[],
                        favicon_hashes=[], favicon_mmh3=[])


@pytest.mark.req("APK-01")
def test_slugs_keep_shortest_roots():
    assert commoncrawl.slugs(_ctx()) == ["navi"]  # 'navi' already covers navi-upi, navi-loan… as a prefix


@pytest.mark.req("APK-01", "D-31")
def test_find_pages_paced_and_reports(monkeypatch):
    monkeypatch.setattr(get_settings(), "common_crawl_enabled", True)
    monkeypatch.setattr(commoncrawl, "collections", lambda n: ["CC-1"])
    asked = []

    def fake_query(col, prefix, pace):
        asked.append(prefix)
        if prefix.startswith("apkpure.com/"):
            return [{"url": "https://apkpure.com/navi-loan-fast/com.fake.naviloan", "timestamp": "20260901000000",
                     "mime": "text/html", "filename": "crawl/x.warc.gz", "offset": "10", "length": "20"}]
        return None if prefix.startswith("apkfab.com/") else []

    monkeypatch.setattr(commoncrawl, "_query", fake_query)
    report = ScanReport()
    pages = commoncrawl.find_pages(_ctx(), report)
    assert [p.url for p in pages] == ["https://apkpure.com/navi-loan-fast/com.fake.naviloan"]
    assert set(asked) == {f"{s}/navi" for s in commoncrawl.SLUG_SITES}
    comp = {c["name"]: c for c in report.as_list()}["Common Crawl index"]
    assert comp["status"] == "failed" and "1 of 6 lookups failed" in comp["message"]  # rate-limited lookup shown


@pytest.mark.req("APK-01")
def test_archived_html_is_read_from_the_warc_record(monkeypatch):
    body = b"<html><title>Navi Loan Fast APK</title></html>"
    record = (b"WARC/1.0\r\nWARC-Type: response\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + body)
    gz = gzip.compress(record)
    calls = {}

    def fake_fetch(url, **kw):
        calls.update(url=url, headers=kw.get("headers"))
        return FetchResult(url=url, final_url=url, status=206, headers={}, content=gz, peer_ip=None)

    monkeypatch.setattr(commoncrawl, "try_fetch", fake_fetch)
    page = commoncrawl.ArchivedPage("https://apkpure.com/x", "20260901", "crawl/x.warc.gz", 100, len(gz), "CC-1")
    assert commoncrawl.archived_html(page) == body.decode()
    assert calls["url"] == commoncrawl.DATA + "crawl/x.warc.gz"  # read from Common Crawl, not the APK site
    assert calls["headers"]["Range"] == f"bytes=100-{100 + len(gz) - 1}"
