import uuid
from collections import defaultdict
from datetime import UTC, datetime

import structlog
from sqlalchemy import select

from app.core import autoscan
from app.db.models import Brand
from app.db.session import session_scope
from app.workers.celery_app import celery
from app.workers.scan import BROWSER_RUNNERS, create_scan_runs, execute_scan

log = structlog.get_logger(__name__)


def _queue(runner: str) -> str:
    return "browser" if runner in BROWSER_RUNNERS else "default"


@celery.task(name="app.workers.tasks.run_scan", bind=True, max_retries=2, default_retry_delay=120)
def run_scan(self, scan_id: str, then: list[str] | None = None) -> dict:
    """Run one scan. `then` = [scan_id, runner] of a follow-up scan to queue once this one is finished
    (successfully, or failed for good) — used to crawl logos after the domain scan."""
    try:
        result = execute_scan(uuid.UUID(scan_id))
    except ValueError:
        _start_follow_up(then)
        raise
    except Exception as exc:  # infrastructure failure (DB/Redis down): retry later
        if self.request.retries >= self.max_retries:
            _start_follow_up(then)
            raise
        raise self.retry(exc=exc) from exc
    _start_follow_up(then)
    return result


def _start_follow_up(then: list[str] | None) -> None:
    if then:
        scan_id, runner = then
        run_scan.apply_async(args=[scan_id], queue=_queue(runner))


def enqueue(scan_id: uuid.UUID, runner: str) -> None:
    run_scan.apply_async(args=[str(scan_id)], queue=_queue(runner))


def enqueue_runs(runs: list[tuple[uuid.UUID, str]]) -> None:
    """Queue one brand's scans in parallel, except the logo crawl, which follows the domain scan so it also
    crawls the live look-alike sites that scan just found (LOGO-01)."""
    ids = {runner: scan_id for scan_id, runner in runs}
    for scan_id, runner in runs:
        if runner == "logo" and "domains" in ids:
            continue
        then = [str(ids["logo"]), "logo"] if runner == "domains" and "logo" in ids else None
        run_scan.apply_async(args=[str(scan_id)], kwargs={"then": then}, queue=_queue(runner))


@celery.task(name="app.workers.tasks.analyse_email", bind=True, max_retries=2, default_retry_delay=120)
def analyse_email(self, email_id: str):
    """Re-analyse a stored email (e.g. engines were down at upload time)."""
    import uuid as _uuid

    from sqlalchemy import select

    from app.db.models import EmailMessage
    from app.db.session import session_scope
    try:
        from app.core import evidence as store
        from app.modules.email.service import analyse_stored

        with session_scope() as db:
            row = db.scalar(select(EmailMessage).where(EmailMessage.id == _uuid.UUID(email_id)))
            if row is None or not row.raw_storage_key:
                return {"skipped": "not found"}
            raw = store.get(row.raw_storage_key)
            analyse_stored(db, row, raw)
        return {"ok": True}
    except Exception as exc:  # infrastructure failure
        if self.request.retries >= self.max_retries:
            # D-31: out of retries — show the email as failed with the reason, never leave it "queued" forever
            with session_scope() as db:
                row = db.get(EmailMessage, _uuid.UUID(email_id))
                if row is not None:
                    row.status, row.error = "failed", f"{type(exc).__name__}: {exc}"[:2000]
            raise
        raise self.retry(exc=exc) from exc


@celery.task(name="app.workers.tasks.poll_mailbox")
def poll_mailbox() -> dict:
    from app.modules.email.intake.mailbox import poll_reporting_mailbox

    return poll_reporting_mailbox()


@celery.task(name="app.workers.tasks.poll_dmarc")
def poll_dmarc() -> dict:
    from app.modules.email.intake.mailbox import poll_dmarc_mailbox

    return poll_dmarc_mailbox()


@celery.task(name="app.workers.tasks.schedule_all")
def schedule_all(runners: list[str] | None = None) -> int:
    """Beat schedule: queue scans only where automatic scanning is switched on (D-39). Manual scans are separate."""
    per_brand: dict[uuid.UUID, list[tuple[uuid.UUID, str]]] = defaultdict(list)
    now = datetime.now(UTC)
    with session_scope() as db:
        if not autoscan.master_enabled(db):
            log.info("auto_scan_skipped", reason="automatic scans are switched off", job=runners or "all")
            return 0
        brands = db.scalars(select(Brand).where(Brand.is_active.is_(True), Brand.auto_scan_enabled.is_(True))).all()
        for brand in brands:
            todo = autoscan.plan(brand, runners, now)
            if not todo:
                continue
            for run in create_scan_runs(db, brand.id, todo, trigger="schedule"):
                per_brand[brand.id].append((run.id, run.stats["runner"]))
            if runners is None:
                brand.last_auto_scan_at = now
    for runs in per_brand.values():
        enqueue_runs(runs)
    return sum(len(r) for r in per_brand.values())
