"""Automatic (scheduled) scan control (D-39): a master switch plus per-brand on/off, frequency and scanners.

Scheduled jobs only queue scans for brands that are switched on, due by their frequency, and only for the scanners
the brand selected. Manual "Run scan now" is never affected.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from app.db.models import AppSetting, Brand

AUTO_SCAN_KEY = "auto_scan"
FREQUENCY_DAYS = {"daily": 1, "every_3_days": 3, "weekly": 7}
# A daily scan queued at 02:00 yesterday must count as due today even if it was queued a few minutes later
DUE_SLACK = timedelta(hours=2)
ALL_RUNNERS = ["domains", "apk", "rogue_app", "social", "social_media", "documents", "logo", "email_posture"]


def master_enabled(db: Session) -> bool:
    row = db.get(AppSetting, AUTO_SCAN_KEY)
    return bool(row.value.get("enabled", True)) if row else True


def set_master(db: Session, enabled: bool, user_id=None) -> AppSetting:
    row = db.get(AppSetting, AUTO_SCAN_KEY)
    if row is None:
        row = AppSetting(key=AUTO_SCAN_KEY, value={})
        db.add(row)
    row.value = {"enabled": enabled}
    row.updated_by = user_id
    row.updated_at = datetime.now(UTC)
    db.flush()
    return row


def brand_runners(brand: Brand) -> list[str]:
    """Scanners the brand runs automatically; an empty selection means every scanner."""
    return list(brand.auto_scan_runners or []) or list(ALL_RUNNERS)


def next_due(brand: Brand) -> datetime | None:
    if not brand.auto_scan_enabled:
        return None
    if brand.last_auto_scan_at is None:
        return datetime.now(UTC)
    return brand.last_auto_scan_at + timedelta(days=FREQUENCY_DAYS.get(brand.auto_scan_frequency, 1))


def is_due(brand: Brand, now: datetime | None = None) -> bool:
    if not brand.auto_scan_enabled:
        return False
    if brand.last_auto_scan_at is None:
        return True  # switched on and never scanned automatically: run at the next check
    return next_due(brand) - DUE_SLACK <= (now or datetime.now(UTC))


def plan(brand: Brand, requested: list[str] | None, now: datetime | None = None) -> list[str]:
    """Runners to queue for this brand in a scheduled job, or [] when nothing should run.

    requested=None is the main daily job (respects the frequency); a narrower job (domains re-check every 6 h,
    email posture) only runs for brands on a daily frequency that selected that scanner.
    """
    if not (brand.is_active and brand.auto_scan_enabled):
        return []
    selected = brand_runners(brand)
    if requested is None:
        return selected if is_due(brand, now) else []
    if brand.auto_scan_frequency != "daily":
        return []
    return [r for r in requested if r in selected]
