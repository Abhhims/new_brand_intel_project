"""Findings and candidates, their timeline and observations, and analyst decisions (SP2, RDA-11/12/15)."""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import Select, String, cast, func, or_, select
from sqlalchemy.orm import Session, selectinload

from app.core import evidence as store
from app.core.findings import InvalidTransition, set_decision
from app.core.security import current_user
from app.db.models import (
    Alert,
    Brand,
    EvidenceKind,
    Finding,
    FindingDecision,
    FindingEvent,
    FindingStage,
    ModuleName,
    RiskLevel,
    User,
)
from app.db.session import get_db
from app.schemas.api import (
    AlertRecordOut,
    BulkDecisionIn,
    DecisionIn,
    EventOut,
    EvidenceOut,
    FindingDetailOut,
    FindingOut,
    FindingPage,
    ObservationOut,
)

router = APIRouter(tags=["findings"])

SORTS = {
    "newest": Finding.first_seen.desc(),
    "oldest": Finding.first_seen.asc(),
    "risk": Finding.score.desc(),
    "confidence": Finding.signals["confidence"]["score"].as_integer().desc().nulls_last(),
    "last_seen": Finding.last_seen.desc(),
}


def thumb(finding: Finding) -> str | None:
    for ev in finding.evidence:
        if ev.kind == EvidenceKind.screenshot and ev.storage_key:
            return store.presigned_url(ev.storage_key)
    for ev in finding.evidence:
        if ev.kind == EvidenceKind.image and ev.storage_key:
            return store.presigned_url(ev.storage_key)
    return None


def finding_out(f: Finding, alert_count: int = 0) -> FindingOut:
    out = FindingOut(
        **{k: getattr(f, k) for k in FindingOut.model_fields if k not in ("brand_name", "thumbnail_url",
                                                                          "alert_count")},
        brand_name=f.brand.name, alert_count=alert_count,
    )
    out.thumbnail_url = thumb(f)
    return out


def evidence_out(f: Finding) -> list[EvidenceOut]:
    out = []
    for ev in f.evidence:
        e = EvidenceOut.model_validate(ev)
        e.kind = ev.kind.value
        e.url = store.presigned_url(ev.storage_key) if ev.storage_key else None
        out.append(e)
    return out


def events_out(f: Finding) -> list[EventOut]:
    out = []
    for ev in sorted(f.events, key=lambda e: e.at, reverse=True):
        item = EventOut.model_validate(ev)
        item.user_name = ev.user.name if ev.user else "System"
        out.append(item)
    return out


def load_finding(db: Session, finding_id: uuid.UUID) -> Finding:
    f = db.scalar(select(Finding).where(Finding.id == finding_id).options(
        selectinload(Finding.brand), selectinload(Finding.evidence), selectinload(Finding.observations),
        selectinload(Finding.alerts), selectinload(Finding.events).selectinload(FindingEvent.user),
    ))
    if f is None:
        raise HTTPException(404, "Finding not found")
    return f


def finding_detail(db: Session, f: Finding) -> FindingDetailOut:
    base = finding_out(f, alert_count=len(f.alerts))
    decided_by = db.get(User, f.decided_by) if f.decided_by else None
    return FindingDetailOut(
        **base.model_dump(), decided_by_name=decided_by.name if decided_by else None,
        evidence=evidence_out(f), events=events_out(f),
        observations=[ObservationOut.model_validate(o) for o in f.observations[:50]],
        alerts=[AlertRecordOut.model_validate(a) for a in f.alerts],
    )


class FindingFilters:
    """Shared by the findings list and the findings CSV/PDF exports, so exports match what the analyst sees."""

    def __init__(
        self,
        brand_id: Annotated[list[uuid.UUID] | None, Query()] = None,
        module: Annotated[list[ModuleName] | None, Query()] = None,
        stage: Annotated[list[FindingStage] | None, Query()] = None,
        decision: Annotated[list[FindingDecision] | None, Query()] = None,
        risk_level: Annotated[list[RiskLevel] | None, Query()] = None,
        alerted: bool | None = None,
        platform: Annotated[list[str] | None, Query()] = None,
        content_type: Annotated[list[str] | None, Query()] = None,
        q: str | None = None,
        sort: str = "newest",
    ):
        self.brand_id, self.module, self.stage, self.decision = brand_id, module, stage, decision
        self.risk_level, self.alerted, self.platform, self.content_type = risk_level, alerted, platform, content_type
        self.q = (q or "").strip()
        self.sort = sort if sort in SORTS else "newest"

    def select(self) -> Select:
        stmt = select(Finding).join(Brand)
        if self.brand_id:
            stmt = stmt.where(Finding.brand_id.in_(self.brand_id))
        if self.module:
            stmt = stmt.where(Finding.module.in_(self.module))
        if self.stage:
            stmt = stmt.where(Finding.stage.in_(self.stage))
        if self.decision:
            stmt = stmt.where(Finding.decision.in_(self.decision))
        if self.risk_level:
            stmt = stmt.where(Finding.risk_level.in_(self.risk_level))
        if self.alerted is not None:
            stmt = stmt.where(Finding.last_alert_at.is_not(None) if self.alerted else Finding.last_alert_at.is_(None))
        if self.platform:
            stmt = stmt.where(Finding.details["Platform"].astext.in_(self.platform))
        if self.content_type:
            stmt = stmt.where(Finding.details["Content Type"].astext.in_(self.content_type))
        if self.q:
            like = f"%{self.q.lower()}%"
            stmt = stmt.where(or_(func.lower(Finding.title).like(like), func.lower(Finding.entity_key).like(like),
                                  func.lower(Brand.name).like(like),
                                  func.lower(cast(Finding.details, String)).like(like)))
        return stmt

    def order(self) -> tuple:
        return SORTS[self.sort], Finding.id


@router.get("/findings", response_model=FindingPage)
def list_findings(
    filters: FindingFilters = Depends(),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    _: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    stmt = filters.select()
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(stmt.options(selectinload(Finding.brand), selectinload(Finding.evidence))
                      .order_by(*filters.order())
                      .offset((page - 1) * page_size).limit(page_size)).all()
    counts = dict(db.execute(select(Alert.finding_id, func.count()).where(Alert.finding_id.in_([f.id for f in rows]))
                             .group_by(Alert.finding_id)).all()) if rows else {}
    return FindingPage(items=[finding_out(f, counts.get(f.id, 0)) for f in rows], total=total, page=page,
                       page_size=page_size)


@router.get("/findings/{finding_id}", response_model=FindingDetailOut)
def get_finding(finding_id: uuid.UUID, _: User = Depends(current_user), db: Session = Depends(get_db)):
    return finding_detail(db, load_finding(db, finding_id))


@router.post("/findings/decision", response_model=list[FindingOut])
def bulk_decision(body: BulkDecisionIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Same decision and note for many findings; all-or-nothing (D-35)."""
    rows = db.scalars(select(Finding).where(Finding.id.in_(body.finding_ids))
                      .options(selectinload(Finding.brand), selectinload(Finding.evidence))).all()
    missing = set(body.finding_ids) - {f.id for f in rows}
    if missing:
        raise HTTPException(404, f"Finding not found: {sorted(map(str, missing))[0]}")
    for f in rows:
        try:
            set_decision(db, f, body.decision, user.id, body.note, body.add_to_allowlist)
        except InvalidTransition as exc:
            db.rollback()
            raise HTTPException(409, f"{f.entity_key}: {exc}") from None
    db.commit()
    return [finding_out(f) for f in rows]


@router.post("/findings/{finding_id}/decision", response_model=FindingDetailOut)
def decide(finding_id: uuid.UUID, body: DecisionIn, user: User = Depends(current_user),
           db: Session = Depends(get_db)):
    f = load_finding(db, finding_id)
    try:
        set_decision(db, f, body.decision, user.id, body.note, body.add_to_allowlist)
    except InvalidTransition as exc:
        raise HTTPException(409, str(exc)) from None
    db.commit()
    db.expire_all()
    return finding_detail(db, load_finding(db, finding_id))
