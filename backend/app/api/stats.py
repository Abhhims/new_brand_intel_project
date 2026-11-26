"""Executive dashboard numbers and trend charts (DSH-01…06, DSH-17)."""

import uuid
from datetime import UTC, date, datetime, time, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import Date, cast, func, select
from sqlalchemy.dialects.postgresql import distinct_on
from sqlalchemy.orm import Session

from app.core.security import current_user
from app.db.models import (
    Alert,
    Finding,
    FindingDecision,
    FindingStage,
    ModuleName,
    RiskLevel,
    ScanRun,
    ScanStatus,
    User,
)
from app.db.session import get_db
from app.schemas.api import ExecutiveStats, TrendPoint

router = APIRouter(prefix="/stats", tags=["dashboard"])

# Open = alerted findings not yet closed by an analyst; confirmed threats stay open until resolved (D-35)
OPEN = (FindingDecision.new, FindingDecision.investigating, FindingDecision.confirmed_threat)
ALERTED = Finding.last_alert_at.is_not(None)
DOMAIN = (ModuleName.typosquat, ModuleName.mx, ModuleName.phishing)
MOBILE = (ModuleName.apk, ModuleName.rogue_app)
EMAIL_SPOOF = (ModuleName.email, ModuleName.email_posture, ModuleName.dmarc)


COMPLETED = (ScanStatus.completed, ScanStatus.partially_completed, ScanStatus.completed_with_errors)


def _scan_coverage(db: Session, brand_id: list[uuid.UUID] | None) -> tuple[datetime | None, int, int]:
    """(newest completed scan time, non-ok components and failed/cancelled scans) — judged on the LATEST finished run
    of each brand and scanner, so an old good run never hides a newer failure (D-31)."""
    last = select(func.max(ScanRun.finished_at)).where(ScanRun.status.in_(COMPLETED))
    runner = ScanRun.stats["runner"].astext
    latest = (select(ScanRun).where(ScanRun.finished_at.is_not(None))
              .ext(distinct_on(ScanRun.brand_id, runner))
              .order_by(ScanRun.brand_id, runner, ScanRun.finished_at.desc()))
    if brand_id:
        last = last.where(ScanRun.brand_id.in_(brand_id))
        latest = latest.where(ScanRun.brand_id.in_(brand_id))
    runs = db.scalars(latest).all()
    failed = sum(1 for r in runs if r.status in (ScanStatus.failed, ScanStatus.cancelled))
    gaps = sum(1 for r in runs if r.status not in (ScanStatus.failed, ScanStatus.cancelled)
               for c in (r.components or []) if c.get("status") not in ("ok", "skipped"))
    return db.scalar(last), gaps, failed


def _day_bounds(d: date) -> tuple[datetime, datetime]:
    start = datetime.combine(d, time.min, tzinfo=UTC)
    return start, start + timedelta(days=1)


@router.get("/executive", response_model=ExecutiveStats)
def executive(
    day: date | None = Query(None, alias="date"),
    brand_id: Annotated[list[uuid.UUID] | None, Query()] = None,
    _: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    day = day or datetime.now(UTC).date()
    start, end = _day_bounds(day)

    def count(*conds, alerted: bool = True) -> int:
        stmt = select(func.count()).select_from(Finding).where(*conds)
        if alerted:
            stmt = stmt.where(ALERTED)
        if brand_id:
            stmt = stmt.where(Finding.brand_id.in_(brand_id))
        return db.scalar(stmt) or 0

    # "today" = findings whose latest alert was raised today
    today = (Finding.last_alert_at >= start, Finding.last_alert_at < end)
    high = Finding.risk_level.in_((RiskLevel.high, RiskLevel.critical))
    is_open = Finding.decision.in_(OPEN)

    def grouped(col, *conds) -> dict[str, int]:
        stmt = select(col, func.count()).where(ALERTED, *conds).group_by(col)
        if brand_id:
            stmt = stmt.where(Finding.brand_id.in_(brand_id))
        return {(k.value if hasattr(k, "value") else str(k)): v for k, v in db.execute(stmt).all()}

    last_scan, gaps, failed = _scan_coverage(db, brand_id)
    return ExecutiveStats(
        date=day.isoformat(),
        last_completed_scan_at=last_scan,
        components_unavailable=gaps,
        scans_failed=failed,
        total_alerts_today=count(*today),
        high_critical_alerts=count(high, is_open),
        high_critical_today=count(high, *today),
        new_phishing_domains=count(Finding.module.in_(DOMAIN), *today),
        new_impersonation_accounts=count(Finding.module == ModuleName.social, *today),
        new_rogue_apps=count(Finding.module.in_(MOBILE), *today),
        sensitive_document_exposures=count(Finding.module == ModuleName.documents, *today),
        phishing_emails_today=count(Finding.module == ModuleName.email, *today),
        spoofed_sender_attempts=count(Finding.module.in_(EMAIL_SPOOF), high, is_open),
        open_alerts=count(is_open),
        by_module={m.value: 0 for m in ModuleName} | grouped(Finding.module, is_open),
        by_risk={r.value: 0 for r in RiskLevel} | grouped(Finding.risk_level, is_open),
        by_status={d.value: 0 for d in FindingDecision} | grouped(Finding.decision),
        candidates=count(Finding.stage == FindingStage.candidate, alerted=False),
        findings_below_alert_level=count(Finding.stage == FindingStage.finding, Finding.last_alert_at.is_(None),
                                         alerted=False),
    )


@router.get("/trends", response_model=list[TrendPoint])
def trends(
    days: int = Query(30, ge=1, le=365),
    brand_id: Annotated[list[uuid.UUID] | None, Query()] = None,
    _: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    end = datetime.now(UTC).date()
    start = end - timedelta(days=days - 1)
    day_col = cast(func.timezone("UTC", Alert.created_at), Date)
    stmt = (select(day_col, Alert.risk_level, func.count())
            .where(Alert.created_at >= datetime.combine(start, time.min, tzinfo=UTC))
            .group_by(day_col, Alert.risk_level))
    if brand_id:
        stmt = stmt.where(Alert.brand_id.in_(brand_id))
    buckets: dict[date, dict[str, int]] = {}
    for d, level, n in db.execute(stmt).all():
        buckets.setdefault(d, {})[level.value.lower()] = n
    out = []
    for i in range(days):
        d = start + timedelta(days=i)
        b = buckets.get(d, {})
        out.append(TrendPoint(date=d.isoformat(), total=sum(b.values()), low=b.get("low", 0),
                              medium=b.get("medium", 0), high=b.get("high", 0), critical=b.get("critical", 0)))
    return out
