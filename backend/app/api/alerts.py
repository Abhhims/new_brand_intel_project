"""Alert queue, detail, workflow, evidence (DSH-07…16, AC-09, AC-10, RDA-13).

Since SP2 an alert is a record raised when a finding meets the alert rule (D-34, D-36). The queue shows the latest
alert of each finding; the analyst decision lives on the finding (D-35), shown here as `status`.
"""

import uuid
from datetime import UTC, date, datetime, time, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import Select, String, cast, func, or_, select
from sqlalchemy.orm import Session, selectinload

from app.api.findings import events_out, evidence_out, load_finding, thumb
from app.core import evidence as store
from app.core.findings import InvalidTransition, set_decision
from app.core.security import current_user
from app.db.models import Alert, Brand, Evidence, Finding, FindingDecision, ModuleName, RiskLevel, User
from app.db.session import get_db
from app.schemas.api import (
    AlertDetailOut,
    AlertOut,
    AlertPage,
    AlertRecordOut,
    EventOut,
    EvidenceOut,
    ObservationOut,
    StatusChangeIn,
)

router = APIRouter(tags=["alerts"])

SORTS = {
    "newest": Alert.created_at.desc(),
    "oldest": Alert.created_at.asc(),
    "risk": Finding.score.desc(),
    "confidence": Finding.signals["confidence"]["score"].as_integer().desc().nulls_last(),
    "last_seen": Finding.last_seen.desc(),
}


class AlertFilters:
    """Shared by the alert list and the CSV/PDF exports, so exports match what the analyst sees."""

    def __init__(
        self,
        brand_id: Annotated[list[uuid.UUID] | None, Query()] = None,
        module: Annotated[list[ModuleName] | None, Query()] = None,
        risk_level: Annotated[list[RiskLevel] | None, Query()] = None,
        status: Annotated[list[FindingDecision] | None, Query()] = None,
        date_from: date | None = None,
        date_to: date | None = None,
        q: str | None = None,
        suspected_phishing: bool | None = None,
        sort: str = "newest",
        history: bool = False,
    ):
        self.brand_id, self.module, self.risk_level, self.status = brand_id, module, risk_level, status
        self.date_from, self.date_to, self.q = date_from, date_to, (q or "").strip()
        self.suspected_phishing = suspected_phishing
        self.sort = sort if sort in SORTS else "newest"
        self.history = history  # True = every alert record, False = latest alert per finding

    def select(self) -> Select:
        return self.apply(select(Alert, Finding).join(Finding, Alert.finding_id == Finding.id)
                          .join(Brand, Brand.id == Finding.brand_id))

    def apply(self, stmt: Select) -> Select:
        if not self.history:
            stmt = stmt.where(Alert.created_at == Finding.last_alert_at)
        if self.brand_id:
            stmt = stmt.where(Finding.brand_id.in_(self.brand_id))
        if self.module:
            stmt = stmt.where(Finding.module.in_(self.module))
        if self.risk_level:
            stmt = stmt.where(Finding.risk_level.in_(self.risk_level))
        if self.status:
            stmt = stmt.where(Finding.decision.in_(self.status))
        if self.date_from:
            stmt = stmt.where(Alert.created_at >= datetime.combine(self.date_from, time.min, tzinfo=UTC))
        if self.date_to:
            stmt = stmt.where(Alert.created_at < datetime.combine(self.date_to + timedelta(days=1), time.min,
                                                                  tzinfo=UTC))
        if self.suspected_phishing is not None:
            stmt = stmt.where(Finding.suspected_phishing.is_(self.suspected_phishing))
        if self.q:
            like = f"%{self.q.lower()}%"
            stmt = stmt.where(or_(func.lower(Finding.title).like(like), func.lower(Finding.entity_key).like(like),
                                  func.lower(Brand.name).like(like),
                                  func.lower(cast(Finding.details, String)).like(like)))
        return stmt


def to_out(alert: Alert, f: Finding, with_thumb: bool = True) -> AlertOut:
    out = AlertOut(
        id=alert.id, finding_id=f.id, brand_id=f.brand_id, brand_name=f.brand.name, module=f.module,
        entity_key=f.entity_key, stage=f.stage, title=f.title, similarity=f.similarity, score=f.score,
        risk_level=f.risk_level, status=f.decision, suspected_phishing=f.suspected_phishing, details=f.details,
        signals=f.signals, source_url=f.source_url, first_seen=f.first_seen, last_seen=f.last_seen,
        updated_at=f.updated_at, alerted_at=alert.created_at, trigger=alert.trigger, reason=alert.reason,
        scan_id=alert.scan_id,
    )
    if with_thumb:
        out.thumbnail_url = thumb(f)
    return out


@router.get("/alerts", response_model=AlertPage)
def list_alerts(
    filters: AlertFilters = Depends(),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    _: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    base = filters.select()
    total = db.scalar(select(func.count()).select_from(base.subquery())) or 0
    rows = db.execute(
        base.options(selectinload(Finding.brand), selectinload(Finding.evidence))
        .order_by(SORTS[filters.sort], Alert.id).offset((page - 1) * page_size).limit(page_size)
    ).all()
    return AlertPage(items=[to_out(a, f) for a, f in rows], total=total, page=page, page_size=page_size)


def _load(db: Session, alert_id: uuid.UUID) -> tuple[Alert, Finding]:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(404, "Alert not found")
    return alert, load_finding(db, alert.finding_id)


def _detail(alert: Alert, f: Finding) -> AlertDetailOut:
    return AlertDetailOut(
        **to_out(alert, f).model_dump(), evidence=evidence_out(f), events=events_out(f),
        observations=[ObservationOut.model_validate(o) for o in f.observations[:50]],
        alerts=[AlertRecordOut.model_validate(a) for a in f.alerts], decision_note=f.decision_note,
    )


@router.get("/alerts/{alert_id}", response_model=AlertDetailOut)
def get_alert(alert_id: uuid.UUID, _: User = Depends(current_user), db: Session = Depends(get_db)):
    return _detail(*_load(db, alert_id))


@router.post("/alerts/{alert_id}/status", response_model=AlertDetailOut)
def set_status(alert_id: uuid.UUID, body: StatusChangeIn, user: User = Depends(current_user),
               db: Session = Depends(get_db)):
    """Sets the decision of the alert's finding (D-35)."""
    alert, f = _load(db, alert_id)
    try:
        set_decision(db, f, body.status, user.id, body.note, body.add_to_allowlist)
    except InvalidTransition as exc:
        raise HTTPException(409, str(exc)) from None
    db.commit()
    db.expire_all()
    return _detail(*_load(db, alert_id))


@router.get("/alerts/{alert_id}/events", response_model=list[EventOut])
def alert_events(alert_id: uuid.UUID, _: User = Depends(current_user), db: Session = Depends(get_db)):
    return _detail(*_load(db, alert_id)).events


@router.get("/evidence/{evidence_id}", response_model=EvidenceOut)
def get_evidence(evidence_id: uuid.UUID, _: User = Depends(current_user), db: Session = Depends(get_db)):
    ev = db.get(Evidence, evidence_id)
    if ev is None:
        raise HTTPException(404, "Evidence not found")
    out = EvidenceOut.model_validate(ev)
    out.kind = ev.kind.value
    out.url = store.presigned_url(ev.storage_key) if ev.storage_key else None
    return out
