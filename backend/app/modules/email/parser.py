"""Parse a raw email (.eml / .msg / forwarded original) into a ParsedEmail — best-effort, never raises."""

from __future__ import annotations

import email
import email.policy
import hashlib
import ipaddress
import re
import zipfile
from email.header import decode_header, make_header
from email.message import EmailMessage
from email.utils import parsedate_to_datetime

import structlog

from app.core.evidence import sha256
from app.modules.email.model import Attachment, ParsedEmail, UrlRef
from app.modules.email.urls import extract_images, extract_urls

log = structlog.get_logger(__name__)

MAX_ATTACHMENTS = 50
MAX_ATTACHMENT_BYTES = 30 * 1024 * 1024
_IP_RE = re.compile(r"[\[(]?((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{3,45})[\])]?")


def _decode(value: str | None) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value))).strip()
    except (ValueError, LookupError):
        return value.strip()


def _addr(value: str | None) -> tuple[str | None, str]:
    """Return (email, display-name) from a header value."""
    if not value:
        return None, ""
    decoded = _decode(value)
    m = re.search(r"<([^>]+)>", decoded)
    if m:
        name = decoded[: m.start()].strip().strip('"').strip()
        return m.group(1).strip().lower(), name
    m = re.search(r"[\w.%+\-]+@[\w.\-]+", decoded)
    return (m.group(0).lower() if m else None), (decoded if not m else "")


def _public_ip(received_headers: list[str]) -> str | None:
    """First public IP in the Received chain, read oldest→newest (sender side first for display)."""
    for header in reversed(received_headers):
        for token in _IP_RE.findall(header):
            try:
                ip = ipaddress.ip_address(token)
            except ValueError:
                continue
            mapped = ip.ipv4_mapped if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped else ip
            if not (mapped.is_private or mapped.is_loopback or mapped.is_link_local or mapped.is_reserved
                    or mapped.is_multicast or mapped.is_unspecified):
                return str(mapped)
    return None


def _to_eml(raw: bytes, filename: str) -> bytes:
    """Convert Outlook .msg to RFC822 bytes when needed."""
    if filename.lower().endswith(".msg") or raw[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        try:
            import extract_msg

            msg = extract_msg.openMsg(raw)
            eml = msg.asEmailMessage() if hasattr(msg, "asEmailMessage") else None
            if eml is not None:
                return bytes(eml)
            return msg.as_bytes() if hasattr(msg, "as_bytes") else raw
        except Exception as exc:  # noqa: BLE001
            log.info("msg_convert_failed", error=str(exc)[:200])
    return raw


def _collect_parts(msg: EmailMessage, parsed: ParsedEmail, nested: bool = False) -> EmailMessage | None:
    """Walk one message: fill text/html, attachments, and return an embedded original if present."""
    forwarded: EmailMessage | None = None
    for part in msg.walk():
        ctype = part.get_content_type()
        disp = (part.get_content_disposition() or "").lower()
        if ctype == "message/rfc822" and not nested:
            payload = part.get_payload()
            if payload:
                inner = payload[0] if isinstance(payload, list) else payload
                if isinstance(inner, EmailMessage):
                    forwarded = inner
            continue
        if part.is_multipart():
            continue
        if disp == "attachment" or (part.get_filename() and ctype not in ("text/plain", "text/html")):
            if len(parsed.attachments) >= MAX_ATTACHMENTS:
                parsed.warnings.append(f"more than {MAX_ATTACHMENTS} attachments; extra ones ignored")
                continue
            parsed.attachments.append(_attachment(part, nested))
            continue
        if ctype == "text/plain":
            parsed.text += _body(part)
        elif ctype == "text/html":
            parsed.html += _body(part)
    return forwarded


def _body(part: EmailMessage) -> str:
    try:
        payload = part.get_content()
        return payload if isinstance(payload, str) else ""
    except (LookupError, ValueError, UnicodeDecodeError):
        raw = part.get_payload(decode=True)
        return raw.decode("utf-8", "replace") if raw else ""


def _attachment(part: EmailMessage, nested: bool) -> Attachment:
    name = _decode(part.get_filename() or "") or "attachment"
    data = part.get_payload(decode=True) or b""
    if len(data) > MAX_ATTACHMENT_BYTES:
        data = data[:MAX_ATTACHMENT_BYTES]
    members: list[str] = []
    if data[:2] == b"PK":
        try:
            import io

            with zipfile.ZipFile(io.BytesIO(data)) as z:
                members = z.namelist()[:200]
        except (zipfile.BadZipFile, OSError):
            pass
    return Attachment(name=name, content_type=part.get_content_type(), data=data, sha256=sha256(data),
                      size=len(data), archive_members=members, nested=nested)


def _fill_headers(msg: EmailMessage, parsed: ParsedEmail) -> None:
    parsed.message_id = (msg.get("Message-ID") or "").strip() or None
    parsed.subject = _decode(msg.get("Subject"))
    parsed.from_addr, parsed.from_name = _addr(msg.get("From"))
    parsed.reply_to = _addr(msg.get("Reply-To"))[0]
    parsed.return_path = _addr(msg.get("Return-Path"))[0]
    parsed.to = [a for a, _ in (_addr(x) for x in (msg.get_all("To") or [])) if a]
    parsed.received = [str(h) for h in (msg.get_all("Received") or [])]
    parsed.sender_ip = _public_ip(parsed.received)
    parsed.auth_results_header = " ".join(str(h) for h in (msg.get_all("Authentication-Results") or []))
    parsed.headers = {k: _decode(v) for k, v in msg.items()}
    try:
        parsed.sent_at = parsedate_to_datetime(msg["Date"]) if msg.get("Date") else None
    except (TypeError, ValueError):
        parsed.sent_at = None


def parse(raw: bytes, filename: str = "") -> ParsedEmail:
    parsed = ParsedEmail()
    try:
        raw = _to_eml(raw, filename)
        msg = email.message_from_bytes(raw, policy=email.policy.default)
    except Exception as exc:  # noqa: BLE001
        parsed.warnings.append(f"could not parse message: {type(exc).__name__}")
        parsed.raw_sha256 = hashlib.sha256(raw).hexdigest()
        return parsed

    try:
        forwarded = _collect_parts(msg, parsed)
    except Exception as exc:  # noqa: BLE001
        parsed.warnings.append(f"partial parse: {type(exc).__name__}")
        forwarded = None

    if forwarded is not None:
        wrapper_from = _addr(msg.get("From"))[0]
        inner = ParsedEmail()
        _fill_headers(forwarded, inner)
        try:
            _collect_parts(forwarded, inner, nested=True)
        except Exception:  # noqa: BLE001
            pass
        inner.is_forwarded_original = True
        inner.forwarded_by = wrapper_from
        inner.text += parsed.text
        inner.warnings = parsed.warnings
        parsed = inner
    else:
        _fill_headers(msg, parsed)

    parsed.urls = _merge_urls(parsed)
    parsed.images_remote = extract_images(parsed.html)
    if not (parsed.from_addr or parsed.message_id or parsed.subject) and not parsed.attachments:
        parsed.warnings.append("no recognisable email headers")
    return parsed


def _merge_urls(parsed: ParsedEmail) -> list[UrlRef]:
    refs = extract_urls(parsed.text, parsed.html)
    seen = {r.url for r in refs}
    for header in ("List-Unsubscribe",):
        for raw in re.findall(r"<([^>]+)>", parsed.headers.get(header, "")):
            if raw.lower().startswith("http") and raw not in seen:
                refs.append(UrlRef(url=raw, source="header"))
                seen.add(raw)
    return refs
