"""Platform settings changed from the dashboard: the automatic-scan master switch (D-39)."""

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core import autoscan
from app.core.security import current_user, require_admin
from app.db.models import AppSetting, Brand, User
from app.db.session import get_db
from app.schemas.api import AutoScanSettings, AutoScanSettingsIn

router = APIRouter(prefix="/settings", tags=["settings"])


def _out(db: Session) -> AutoScanSettings:
    row = db.get(AppSetting, autoscan.AUTO_SCAN_KEY)
    active = select(func.count()).select_from(Brand).where(Brand.is_active.is_(True))
    return AutoScanSettings(
        enabled=autoscan.master_enabled(db), updated_at=row.updated_at if row else None,
        brands_total=db.scalar(active) or 0,
        brands_enabled=db.scalar(active.where(Brand.auto_scan_enabled.is_(True))) or 0,
    )


@router.get("/auto-scan", response_model=AutoScanSettings)
def get_auto_scan(_: User = Depends(current_user), db: Session = Depends(get_db)):
    return _out(db)


@router.put("/auto-scan", response_model=AutoScanSettings)
def put_auto_scan(body: AutoScanSettingsIn, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    autoscan.set_master(db, body.enabled, user.id)
    db.commit()
    return _out(db)
