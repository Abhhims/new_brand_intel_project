"""Run scans on demand and see scan history (FND-07, FND-13)."""

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.core.security import current_user
from app.db.models import Brand, ScanRun, ScanStatus, User
from app.db.session import get_db
from app.schemas.api import ScanIn, ScanOut
from app.workers.scan import create_scan_runs, runners_for

router = APIRouter(prefix="/scans", tags=["scans"])


def _out(run: ScanRun) -> ScanOut:
    out = ScanOut.model_validate(run)
    out.brand_name = run.brand.name if run.brand else None
    return out


@router.post("", response_model=list[ScanOut], status_code=202)
def start_scan(body: ScanIn, _: User = Depends(current_user), db: Session = Depends(get_db)):
    brand = db.get(Brand, body.brand_id)
    if brand is None:
        raise HTTPException(404, "Brand not found")
    runs = create_scan_runs(db, brand.id, runners_for(body.modules), trigger="manual",
                            date_from=body.date_from, date_to=body.date_to)
    db.commit()
    from app.workers.tasks import enqueue_runs  # local import: API doesn't need Celery until a scan starts

    try:
        enqueue_runs([(run.id, run.stats["runner"]) for run in runs])
    except Exception as exc:  # noqa: BLE001 - broker down: record instead of losing the request
        for run in runs:
            run.status, run.error = ScanStatus.failed, f"Could not queue scan: {exc}"
            run.finished_at = datetime.now(UTC)
            run.components = [{"name": "Task queue", "status": "failed", "message": f"Could not queue scan: {exc}",
                               "counts": {}, "fatal": True}]
    db.commit()
    for run in runs:
        db.refresh(run)
    return [ScanOut(**_out(r).model_dump() | {"brand_name": brand.name}) for r in runs]


@router.get("", response_model=list[ScanOut])
def list_scans(
    brand_id: Annotated[list[uuid.UUID] | None, Query()] = None,
    limit: int = Query(100, ge=1, le=500),
    _: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    stmt = select(ScanRun).options(selectinload(ScanRun.brand)).order_by(ScanRun.created_at.desc()).limit(limit)
    if brand_id:
        stmt = stmt.where(ScanRun.brand_id.in_(brand_id))
    return [_out(r) for r in db.scalars(stmt).all()]
