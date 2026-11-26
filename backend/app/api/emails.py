"""Upload and review analysed emails (phishing-email module, D-28)."""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.security import current_user
from app.db.models import Brand, EmailMessage, User
from app.db.session import get_db
from app.modules.email.parser import parse
from app.modules.email.service import email_detail
from app.schemas.api import EmailDetailOut, EmailOut, EmailPage

router = APIRouter(prefix="/emails", tags=["phishing email"])

MAX_EMAIL_BYTES = 25 * 1024 * 1024
ALLOWED_SUFFIXES = (".eml", ".msg", ".txt")


@router.post("", response_model=EmailDetailOut, status_code=202)
def upload_email(brand_id: uuid.UUID = Form(...), file: UploadFile = File(...),
                 _: User = Depends(current_user), db: Session = Depends(get_db)):
    if db.get(Brand, brand_id) is None:
        raise HTTPException(404, "Brand not found")
    name = (file.filename or "email.eml").lower()
    data = file.file.read(MAX_EMAIL_BYTES + 1)
    if len(data) > MAX_EMAIL_BYTES:
        raise HTTPException(413, "Email is larger than 25 MB")
    if not name.endswith(ALLOWED_SUFFIXES):
        raise HTTPException(422, "Upload an .eml, .msg or .txt email file")
    # reject obvious non-emails early (an image / PDF is not a message)
    parsed = parse(data, name)
    if parsed.warnings and not (parsed.from_addr or parsed.subject or parsed.message_id):
        raise HTTPException(422, "This file does not look like an email message")
    from app.modules.email.service import store_raw_email

    try:
        row = store_raw_email(db, data, name, brand_id, channel="upload")
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from None
    db.commit()
    from app.workers.tasks import analyse_email

    try:
        analyse_email.delay(str(row.id))
    except Exception:  # noqa: BLE001 - broker down: analysis can be retried from the Scans/Emails view
        pass
    db.refresh(row)
    return _detail(db, row.id)


@router.get("", response_model=EmailPage)
def list_emails(brand_id: Annotated[list[uuid.UUID] | None, Query()] = None,
                page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=200), q: str | None = None,
                _: User = Depends(current_user), db: Session = Depends(get_db)):
    stmt = select(EmailMessage)
    if brand_id:
        stmt = stmt.where(EmailMessage.brand_id.in_(brand_id))
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(func.lower(EmailMessage.subject).like(like) | func.lower(EmailMessage.from_addr).like(like))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(stmt.order_by(EmailMessage.received_at.desc())
                      .offset((page - 1) * page_size).limit(page_size)).all()
    return EmailPage(items=[_row_out(db, r) for r in rows], total=total, page=page, page_size=page_size)


@router.get("/{email_id}", response_model=EmailDetailOut)
def get_email(email_id: uuid.UUID, _: User = Depends(current_user), db: Session = Depends(get_db)):
    return _detail(db, email_id)


def _row_out(db: Session, row: EmailMessage) -> EmailOut:
    from app.db.models import Finding

    alert = db.get(Finding, row.finding_id) if row.finding_id else None
    return EmailOut(id=row.id, brand_id=row.brand_id, subject=row.subject, from_addr=row.from_addr,
                    sender_ip=row.sender_ip, channel=row.channel, status=row.status,
                    received_at=row.received_at, risk_level=alert.risk_level.value if alert else None,
                    score=alert.score if alert else None, finding_id=row.finding_id,
                    verdict=(row.auth or {}).get("summary"))


def _detail(db: Session, email_id: uuid.UUID) -> EmailDetailOut:
    data = email_detail(db, email_id)
    if data is None:
        raise HTTPException(404, "Email not found")
    row, finding, indicators = data["row"], data["finding"], data["indicators"]
    finding_out = None
    if finding is not None:
        from app.api.findings import finding_detail, load_finding

        finding_out = finding_detail(db, load_finding(db, finding.id))
    return EmailDetailOut(
        **_row_out(db, row).model_dump(),
        indicators=[{"kind": i.kind, "value": i.value, "verdicts": i.verdicts,
                     "malicious_sources": i.malicious_sources} for i in indicators],
        not_checked=(row.auth or {}).get("not_checked", []),
        finding=finding_out,
    )
