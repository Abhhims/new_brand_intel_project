"""Process one email end to end: parse → analyse → store raw + indicators → record the finding (alert if the rule is met)."""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime

import structlog
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.core import evidence as store
from app.core.findings import record_detection
from app.db.models import Brand, EmailIndicator, EmailMessage, Finding, ModuleName
from app.modules.base import BrandContext, Detection
from app.modules.email.analysis import analyse
from app.modules.email.parser import parse

log = structlog.get_logger(__name__)


def fingerprint(parsed, raw: bytes) -> str:
    return (parsed.message_id or "").strip() or hashlib.sha256(raw).hexdigest()


def store_raw_email(db: Session, raw: bytes, filename: str, brand_id: uuid.UUID, channel: str) -> EmailMessage:
    """Save the raw message and create (or find) its EmailMessage row as 'queued'. Fast — no analysis."""
    if db.get(Brand, brand_id) is None:
        raise ValueError("brand not found")
    parsed = parse(raw, filename)
    fp = fingerprint(parsed, raw)
    raw_sha = hashlib.sha256(raw).hexdigest()
    row = db.scalar(select(EmailMessage).where(EmailMessage.brand_id == brand_id, EmailMessage.fingerprint == fp))
    if row is None:
        key = f"emails/{brand_id}/{fp.strip('<>').replace('/', '_')[:80]}-{raw_sha[:12]}.eml"
        obj = store.put(key, raw, "message/rfc822")
        row = EmailMessage(brand_id=brand_id, fingerprint=fp, channel=channel, raw_storage_key=obj.storage_key,
                           raw_sha256=raw_sha, subject=(parsed.subject or "")[:2000], from_addr=parsed.from_addr,
                           status="queued")
        db.add(row)
    else:
        row.status = "queued"
    db.flush()
    return row


def process_email(db: Session, raw: bytes, filename: str, brand_id: uuid.UUID, channel: str) -> EmailMessage:
    """Store (if new) and analyse synchronously. Used by the Celery worker and the mailbox poller."""
    row = store_raw_email(db, raw, filename, brand_id, channel)
    return analyse_stored(db, row, raw, filename)


def analyse_stored(db: Session, row: EmailMessage, raw: bytes, filename: str = "email.eml") -> EmailMessage:
    brand = db.scalar(select(Brand).where(Brand.id == row.brand_id)
                      .options(selectinload(Brand.assets), selectinload(Brand.allowlist)))
    ctx = BrandContext.from_brand(brand)
    parsed = parse(raw, filename)
    fp = row.fingerprint
    analysis = analyse(parsed, raw, ctx)
    entity_key = f"email:{fp}"
    finding = Detection(entity_key=entity_key, title=_title(parsed, analysis), signals=analysis.signals,
                      details=analysis.details, source_url=None, evidence=analysis.evidence,
                      module=ModuleName.email)
    record, _, _ = record_detection(db, row.brand_id, ModuleName.email, finding,
                                    channel="upload" if row.channel == "upload" else "mailbox")

    # indicators (replace on re-analysis)
    db.query(EmailIndicator).filter(EmailIndicator.email_id == row.id).delete()
    for ind in analysis.indicators:
        db.add(EmailIndicator(email_id=row.id, kind=ind["kind"], value=str(ind["value"])[:2000],
                              verdicts=ind["verdicts"], malicious_sources=ind.get("malicious_sources", 0)))

    row.finding_id = record.id
    row.message_id = parsed.message_id
    row.subject = (parsed.subject or "")[:2000]
    row.from_addr = parsed.from_addr
    row.reply_to = parsed.reply_to
    row.return_path = parsed.return_path
    row.sender_ip = parsed.sender_ip
    row.sent_at = parsed.sent_at
    row.auth = {"header": analysis.details.get("SPF"), "summary": analysis.verdict_summary,
                "not_checked": analysis.not_checked}
    row.status = "analysed"
    row.analysed_at = datetime.now(UTC)
    db.flush()
    log.info("email_analysed", email_id=str(row.id), finding_id=str(record.id), level=record.risk_level.value,
             channel=row.channel)
    return row


def _title(parsed, analysis) -> str:
    sender = parsed.from_addr or "unknown sender"
    return f"{analysis.verdict_summary} email from {sender}: {(parsed.subject or '(no subject)')[:120]}"


def email_detail(db: Session, email_id: uuid.UUID) -> dict | None:
    row = db.get(EmailMessage, email_id)
    if row is None:
        return None
    finding = db.scalar(select(Finding).where(Finding.id == row.finding_id)
                        .options(selectinload(Finding.evidence), selectinload(Finding.events))) if row.finding_id else None
    indicators = db.scalars(select(EmailIndicator).where(EmailIndicator.email_id == row.id)).all()
    return {"row": row, "finding": finding, "indicators": indicators}
