"""Poll configured mailboxes: analyse reported phishing emails and ingest DMARC reports."""

from __future__ import annotations

import uuid

import structlog
from sqlalchemy import select

from app.config import get_settings
from app.db.models import Brand
from app.db.session import session_scope
from app.modules.base import BrandContext
from app.modules.email.intake.imap import ImapSource
from app.modules.email.service import process_email

log = structlog.get_logger(__name__)


def poll_reporting_mailbox() -> dict:
    """Analyse every new message in the phishing reporting mailbox (channel 'mailbox')."""
    s = get_settings()
    if not (s.imap_host and s.imap_user and s.imap_password):
        return {"status": "not_configured"}
    brand_id = _default_brand_id()
    if brand_id is None:
        return {"status": "no_active_brand"}
    source = ImapSource(s.imap_host, s.imap_user, s.imap_password, s.imap_port, s.imap_mailbox)
    processed = 0
    for _uid, raw in source.fetch_new(mark_seen=True):
        try:
            with session_scope() as db:
                process_email(db, raw, "mailbox.eml", brand_id, channel="mailbox")
            processed += 1
        except Exception as exc:  # noqa: BLE001 - one bad message must not stop the poll
            log.warning("mailbox_message_failed", error=str(exc)[:200])
    log.info("mailbox_polled", processed=processed)
    return {"status": "ok", "processed": processed}


def poll_dmarc_mailbox() -> dict:
    """Ingest DMARC aggregate reports from the DMARC mailbox (channel 'dmarc')."""
    s = get_settings()
    if not (s.dmarc_imap_host and s.dmarc_imap_user and s.dmarc_imap_password):
        return {"status": "not_configured"}
    from app.core.findings import record_detection
    from app.modules.email.dmarc import parse_report, store_and_findings

    source = ImapSource(s.dmarc_imap_host, s.dmarc_imap_user, s.dmarc_imap_password, s.dmarc_imap_port,
                        s.dmarc_imap_mailbox)
    reports = 0
    with session_scope() as db:
        brands = db.scalars(select(Brand).where(Brand.is_active.is_(True))).all()
        contexts = {d.lower(): (BrandContext.from_brand(b)) for b in brands for d in b.allowed_domains()} \
            if hasattr(Brand, "allowed_domains") else _brand_domains(brands)
    for _uid, raw in source.fetch_new(mark_seen=True):
        for blob, filename in _extract_report_attachments(raw):
            try:
                report = parse_report(blob, filename)
            except Exception as exc:  # noqa: BLE001
                log.info("dmarc_parse_failed", error=str(exc)[:150])
                continue
            ctx = contexts.get((report.domain or "").lower())
            if ctx is None:
                continue
            with session_scope() as db:
                for finding in store_and_findings(db, ctx, report, blob):
                    record_detection(db, ctx.id, finding.module, finding, channel="mailbox")
            reports += 1
    log.info("dmarc_mailbox_polled", reports=reports)
    return {"status": "ok", "reports": reports}


def _brand_domains(brands) -> dict[str, BrandContext]:
    out: dict[str, BrandContext] = {}
    for b in brands:
        ctx = BrandContext.from_brand(b)
        for d in ctx.official_domains:
            out[d.lower()] = ctx
    return out


def _extract_report_attachments(raw: bytes) -> list[tuple[bytes, str]]:
    import email
    import email.policy

    msg = email.message_from_bytes(raw, policy=email.policy.default)
    out = []
    for part in msg.walk():
        name = part.get_filename() or ""
        if name.lower().endswith((".xml", ".gz", ".zip")):
            data = part.get_payload(decode=True)
            if data:
                out.append((data, name))
    return out


def _default_brand_id() -> uuid.UUID | None:
    with session_scope() as db:
        return db.scalar(select(Brand.id).where(Brand.is_active.is_(True)).order_by(Brand.created_at))
