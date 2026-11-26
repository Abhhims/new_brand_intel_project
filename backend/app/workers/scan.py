"""Running a scan: one runner (module) for one brand, recorded in scan_runs."""

from __future__ import annotations

import time
import traceback
import uuid
from datetime import UTC, date, datetime, timedelta

import structlog
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.core.findings import DOMAIN_MODULES, close_authorized, record_detection
from app.db.models import Brand, ModuleName, ScanRun, ScanStatus
from app.db.session import session_scope
from app.core import search
from app.modules.base import BrandContext, ScanReport, derive_run_status, parse_date
from app.modules.registry import RUNNERS, get_runner

log = structlog.get_logger(__name__)

# Runners that drive the headless browser go to the isolated browser worker (D-18)
BROWSER_RUNNERS = {"domains", "logo", "social", "social_media", "rogue_app"}

# The ModuleName a scan run is recorded under, per runner
RUNNER_MODULE: dict[str, ModuleName] = {
    "domains": ModuleName.phishing,
    "apk": ModuleName.apk,
    "rogue_app": ModuleName.rogue_app,
    "social": ModuleName.social,
    "documents": ModuleName.documents,
    "logo": ModuleName.logo,
    "email_posture": ModuleName.email_posture,
    "social_media": ModuleName.social_media,
}


def runners_for(modules: list[ModuleName] | None) -> list[str]:
    selected = modules or list(ModuleName)
    # modules without a scan runner (e.g. emails that arrive by upload) are skipped
    return list(dict.fromkeys(RUNNERS[m] for m in selected if m in RUNNERS))


STALE_AFTER = timedelta(minutes=90)  # longer than the 1-hour task time limit


def close_stale_runs(db: Session, brand_id: uuid.UUID) -> int:
    """Runs left queued/running by a worker restart would otherwise look stuck forever on the Scans page."""
    cutoff = datetime.now(UTC) - STALE_AFTER
    stale = db.scalars(select(ScanRun).where(
        ScanRun.brand_id == brand_id, ScanRun.status.in_((ScanStatus.queued, ScanStatus.running)),
        ScanRun.created_at < cutoff)).all()
    for run in stale:
        run.status, run.finished_at = ScanStatus.cancelled, datetime.now(UTC)
        note = "Interrupted (worker restarted or timed out); a newer scan replaces it"
        run.error = f"{run.error}\n{note}" if run.error else note
    return len(stale)


def create_scan_runs(db: Session, brand_id: uuid.UUID, runners: list[str], trigger: str,
                     date_from: date | None = None, date_to: date | None = None) -> list[ScanRun]:
    close_stale_runs(db, brand_id)
    rng = {k: v.isoformat() for k, v in (("date_from", date_from), ("date_to", date_to)) if v}
    runs = [ScanRun(brand_id=brand_id, module=RUNNER_MODULE[r], trigger=trigger, status=ScanStatus.queued,
                    stats={"runner": r, **rng}) for r in runners]
    db.add_all(runs)
    db.flush()
    return runs


def _cancelled(scan_id: uuid.UUID) -> bool:
    with session_scope() as db:
        return db.scalar(select(ScanRun.status).where(ScanRun.id == scan_id)) == ScanStatus.cancelled


def execute_scan(scan_id: uuid.UUID) -> dict:
    """Run one scan to completion. Each finding is committed on its own so partial progress survives."""
    with session_scope() as db:
        run = db.get(ScanRun, scan_id)
        if run is None:
            raise ValueError(f"scan {scan_id} not found")
        if run.status not in (ScanStatus.queued, ScanStatus.running):
            # a redelivered task for a run that already ended (or was closed as interrupted): don't run it twice
            log.info("scan_already_finished", scan_id=str(scan_id), status=run.status.value)
            return {"skipped": f"already {run.status.value}"}
        run.status, run.started_at, run.error = ScanStatus.running, datetime.now(UTC), None
        runner_name = run.stats.get("runner") or next(k for k, v in RUNNER_MODULE.items() if v == run.module)
        brand_id = run.brand_id
        date_from, date_to = parse_date(run.stats.get("date_from")), parse_date(run.stats.get("date_to"))

    stats = {"runner": runner_name, "findings": 0, "created": 0, "updated": 0, "alerts": 0, "errors": 0,
             **{k: v.isoformat() for k, v in (("date_from", date_from), ("date_to", date_to)) if v}}
    search.set_date_range(date_from, date_to)
    report = ScanReport()
    crashed = False
    try:
        with session_scope() as db:
            brand = db.scalar(select(Brand).where(Brand.id == brand_id)
                              .options(selectinload(Brand.assets), selectinload(Brand.allowlist)))
            ctx = BrandContext.from_brand(brand)
            ctx.date_from, ctx.date_to = date_from, date_to
        runner = get_runner(runner_name)
        report = runner.report
        with session_scope() as db:
            checked_at = time.monotonic()
            for finding in runner.run(ctx, db):
                if time.monotonic() - checked_at > 20:
                    checked_at = time.monotonic()
                    if _cancelled(scan_id):  # cancelled or replaced by a newer scan: stop and free the worker
                        log.info("scan_cancelled_stopping", scan_id=str(scan_id))
                        stats["stopped"] = "cancelled"
                        break
                stats["findings"] += 1
                try:
                    with db.begin_nested():
                        module = getattr(finding, "module", None) or RUNNER_MODULE[runner_name]
                        _, alert, created = record_detection(db, ctx.id, module, finding, scan_id=scan_id)
                    db.commit()
                    stats["created" if created else "updated"] += 1
                    stats["alerts"] += int(alert is not None)
                except Exception as exc:  # noqa: BLE001 - one bad finding must not stop the scan
                    db.rollback()
                    stats["errors"] += 1
                    report.failed("Saving findings", f"{finding.entity_key}: {type(exc).__name__}: {exc}", failed=1)
                    log.exception("finding_failed", entity=finding.entity_key)
            stats.update(getattr(runner, "stats", {}) or {})
            scanned = RUNNER_MODULE[runner_name]
            stats["closed_authorized"] = close_authorized(
                db, ctx.id, DOMAIN_MODULES if scanned in DOMAIN_MODULES else (scanned,))
            db.commit()
    except Exception as exc:  # noqa: BLE001
        crashed = True
        report.failed("Scan engine", "".join(traceback.format_exception_only(type(exc), exc)).strip(), fatal=True)
        log.exception("scan_failed", scan_id=str(scan_id), runner=runner_name)

    components = report.as_list()
    status = derive_run_status(components, crashed)
    errors = report.errors

    with session_scope() as db:
        run = db.get(ScanRun, scan_id)
        if run.status != ScanStatus.cancelled:  # a cancelled run stays cancelled; its partial results are kept
            run.status, run.finished_at = status, datetime.now(UTC)
        run.stats = stats
        run.components = components
        run.error = "\n".join(errors[:50]) or None
    log.info("scan_finished", scan_id=str(scan_id), status=status.value, stats=stats)
    return stats
