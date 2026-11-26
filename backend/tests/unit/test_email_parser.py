from pathlib import Path

import pytest

from app.modules.email.parser import MAX_ATTACHMENTS, parse
from app.modules.email.urls import extract_urls, unwrap

pytestmark = pytest.mark.req("EML-01", "EML-02", "EML-03")

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "emails"


def load(name: str) -> bytes:
    return (FIX / name).read_bytes()


def test_headers_and_sender():
    p = parse(load("lookalike.eml"), "lookalike.eml")
    assert p.from_addr == "notice@zentr0va-mail.com" and p.from_name == "Zentrova Test Sender"
    assert p.reply_to == "other-desk@example.org" and p.return_path == "bounce@zentr0va-mail.com"
    assert p.subject == "TEST: Zentrova notice"  # encoded-word decoded
    assert p.message_id == "<fixture-lookalike-001@zentr0va-mail.com>"
    assert p.sender_ip == "45.33.22.11"  # first public IP, private hop skipped
    assert "dmarc=fail" in p.auth_results_header


def test_links_extracted_unwrapped_and_deobfuscated():
    p = parse(load("lookalike.eml"))
    urls = {u.url: u for u in p.urls}
    mismatch = urls["https://zentr0va-mail.com/form?id=1"]
    assert mismatch.text == "https://www.zentrova.com/account" and mismatch.text_mismatch is True
    assert "https://wrapped.zentr0va-mail.com/p" in urls  # Safe Links unwrapped
    assert "https://zentr0va-mail.com/form" in urls  # hxxps / [.] de-obfuscated
    assert any(i.url.startswith("https://images.") for i in p.images_remote)


def test_attachments_hashed_and_archive_listed():
    p = parse(load("lookalike.eml"))
    names = {a.name: a for a in p.attachments}
    assert set(names) >= {"statement.zip", "notice.pdf"}
    zipped = names["statement.zip"]
    assert len(zipped.sha256) == 64 and zipped.size > 0
    assert "statement.pdf.exe" in zipped.archive_members


def test_forwarded_original_is_analysed():
    p = parse(load("forwarded.eml"))
    assert p.is_forwarded_original is True
    assert p.from_addr == "notice@zentr0va-mail.com"  # the original, not the analyst's wrapper
    assert p.forwarded_by == "analyst@zentrova.com"


def test_malformed_mime_does_not_crash():
    p = parse(load("malformed.eml"))
    assert p.subject == "TEST malformed MIME"
    assert any(u.url == "https://example.org/x" for u in p.urls)


def test_garbage_input_is_handled():
    p = parse(b"\x00\x01 not an email at all", "x.eml")
    assert p.warnings and p.urls == []


def test_attachment_limit(monkeypatch):
    from email.message import EmailMessage

    m = EmailMessage()
    m["From"] = "a@example.org"
    m.set_content("x")
    for i in range(MAX_ATTACHMENTS + 5):
        m.add_attachment(b"x", maintype="application", subtype="octet-stream", filename=f"f{i}.bin")
    p = parse(bytes(m))
    assert len(p.attachments) == MAX_ATTACHMENTS and any("attachments" in w for w in p.warnings)


@pytest.mark.parametrize(("raw", "expected"), [
    ("https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fa.test%2Fb&data=1", "https://a.test/b"),
    ("https://www.google.com/url?q=https://a.test/c&sa=D", "https://a.test/c"),
    ("https://urldefense.proofpoint.com/v2/url?u=https-3A__a.test_d&d=x", "https://a.test/d"),
    ("hxxp://a[.]test/e", "http://a.test/e"),
    ("https://a.test/plain", "https://a.test/plain"),
])
def test_unwrap(raw, expected):
    assert unwrap(raw) == expected


def test_extract_urls_from_text_and_html():
    found = {u.url for u in extract_urls("see https://x.test/1, and www.y.test/2.", '<a href="https://z.test/3">z</a>')}
    assert found == {"https://x.test/1", "http://www.y.test/2", "https://z.test/3"}
