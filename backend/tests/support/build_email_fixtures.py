"""Build the structural test emails in backend/tests/fixtures/emails/ (automated tests only, D-27).

    python -m tests.support.build_email_fixtures

These are NOT realistic messages. They use the fictional test brand "Zentrova", reserved test domains (.test,
example.org) and documentation IP ranges, and carry an explicit TEST FIXTURE marker. They exist only to exercise the
parser and scoring paths: header fields, link extraction, attachments, forwarding and malformed MIME.
"""

import io
import zipfile
from datetime import UTC, datetime
from email.message import EmailMessage
from email.utils import format_datetime
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "fixtures" / "emails"
WHEN = format_datetime(datetime(2026, 10, 8, 9, 30, tzinfo=UTC))
MARK = "TEST FIXTURE - structural sample for automated tests, not a real message."


def _lookalike() -> EmailMessage:
    """Sender on a look-alike test domain, mismatched link, obfuscated and wrapped links, archive attachment."""
    m = EmailMessage()
    m["Return-Path"] = "<bounce@zentr0va-mail.com>"
    m["Received"] = ("from relay.zentr0va-mail.com (relay.zentr0va-mail.com [45.33.22.11]) "
                     "by mx.example.org; Wed, 08 Oct 2026 09:30:01 +0000")
    m["Received"] = "from [10.0.0.7] by relay.zentr0va-mail.com; Wed, 08 Oct 2026 09:30:00 +0000"
    m["Authentication-Results"] = ("mx.example.org; spf=fail smtp.mailfrom=zentr0va-mail.com; dkim=none; "
                                   "dmarc=fail header.from=zentr0va-mail.com")
    m["From"] = '"Zentrova Test Sender" <notice@zentr0va-mail.com>'
    m["Reply-To"] = "other-desk@example.org"
    m["To"] = "recipient@example.org"
    m["Subject"] = "=?UTF-8?B?VEVTVDogWmVudHJvdmEgbm90aWNl?="  # "TEST: Zentrova notice"
    m["Date"] = WHEN
    m["Message-ID"] = "<fixture-lookalike-001@zentr0va-mail.com>"
    m.set_content(f"{MARK}\nKeywords for the language rule: login verify payment.\n"
                  "Obfuscated link: hxxps://zentr0va-mail[.]com/form\n")
    m.add_alternative(
        f"<html><body><p>{MARK}</p>"
        '<a href="https://zentr0va-mail.com/form?id=1">https://www.zentrova.com/account</a>'
        '<a href="https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fwrapped.zentr0va-mail.com%2Fp'
        '&amp;data=x">wrapped</a>'
        '<img src="https://images.zentr0va-mail.com/logo.png"></body></html>', subtype="html")
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("statement.pdf.exe", b"MZ" + b"\0" * 64 + b"TEST FIXTURE placeholder, not an executable")
    m.add_attachment(archive.getvalue(), maintype="application", subtype="zip", filename="statement.zip")
    m.add_attachment(b"%PDF-1.4\n% TEST FIXTURE\n", maintype="application", subtype="pdf", filename="notice.pdf")
    return m


def _official() -> EmailMessage:
    """Sent by the brand's own domain with passing authentication — must not count as impersonation."""
    m = EmailMessage()
    m["Received"] = ("from mail.zentrova.com (mail.zentrova.com [198.51.100.20]) by mx.example.org; "
                     "Wed, 08 Oct 2026 10:00:00 +0000")
    m["Authentication-Results"] = ("mx.example.org; spf=pass smtp.mailfrom=zentrova.com; "
                                   "dkim=pass header.d=zentrova.com; dmarc=pass header.from=zentrova.com")
    m["From"] = '"Zentrova" <updates@zentrova.com>'
    m["To"] = "recipient@example.org"
    m["Subject"] = "TEST: Zentrova monthly statement"
    m["Date"] = WHEN
    m["Message-ID"] = "<fixture-official-001@zentrova.com>"
    m.set_content(f"{MARK}\nYour statement is ready. Login at https://www.zentrova.com/account\n")
    return m


def _forwarded() -> EmailMessage:
    """An analyst forwards the look-alike sample as an attachment (message/rfc822)."""
    m = EmailMessage()
    m["From"] = "analyst@zentrova.com"
    m["To"] = "reports@zentrova.com"
    m["Subject"] = "Fwd: TEST: Zentrova notice"
    m["Date"] = WHEN
    m["Message-ID"] = "<fixture-forward-001@zentrova.com>"
    m.set_content(f"{MARK}\nForwarding a suspicious message.\n")
    m.add_attachment(_lookalike())
    return m


MALFORMED = (
    b"From: broken@example.org\r\nTo: recipient@example.org\r\nSubject: TEST malformed MIME\r\n"
    b"Message-ID: <fixture-malformed-001@example.org>\r\n"
    b'Content-Type: multipart/mixed; boundary="never-closed"\r\n\r\n'
    b"--never-closed\r\nContent-Type: text/plain\r\n\r\n"
    b"TEST FIXTURE body without a closing boundary https://example.org/x\r\n"
)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, msg in (("lookalike.eml", _lookalike()), ("official.eml", _official()),
                      ("forwarded.eml", _forwarded())):
        (OUT / name).write_bytes(bytes(msg))
    (OUT / "malformed.eml").write_bytes(MALFORMED)
    print("written:", sorted(p.name for p in OUT.glob("*.eml")))


if __name__ == "__main__":
    main()
