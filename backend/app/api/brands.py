"""Brand onboarding: keywords, official assets (logo upload) and allowlists (FND-04/05/06, OUT-01)."""

import re
import uuid

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from app.api.stats import OPEN
from app.core import autoscan
from app.core import evidence as store
from app.core.allowlist import normalize as normalize_allow
from app.core.assets import NotAnImage, add_asset
from app.core.security import current_user, require_admin
from app.db.models import AssetKind, Brand, BrandAllow, BrandAsset, Finding, User
from app.db.session import get_db
from app.schemas.api import AllowIn, AllowOut, AssetOut, BrandIn, BrandOut, BrandUpdate

router = APIRouter(prefix="/brands", tags=["brands"])

MAX_ASSET_BYTES = 5 * 1024 * 1024


_URL_LIKE = re.compile(r"^(https?://|www\.)|\.(com|in|net|org|co|io)(/|$)", re.I)


def _clean_terms(values: list[str]) -> list[str]:
    terms = list(dict.fromkeys(v.strip() for v in values if v and v.strip()))
    # Every module searches for these words and matches content against them; a URL matches nothing
    urls = [t for t in terms if _URL_LIKE.search(t)]
    if urls:
        raise HTTPException(422, f"Keywords and product terms must be words such as the brand name, not website "
                                 f"addresses ({', '.join(urls[:3])}). Add websites under Allowlist → Domain.")
    return terms


def _normalize_allow(kind, value: str) -> str:
    value = normalize_allow(kind.value, value)
    if not value:
        raise HTTPException(422, f"Could not read a {kind.value.replace('_', ' ')} from that value")
    if kind.value == "signing_cert" and not re.fullmatch(r"[0-9A-F]{64}", value):
        raise HTTPException(422, "A signing certificate must be its SHA-256 fingerprint (64 hex characters)")
    return value


def _out(db: Session, brand: Brand) -> BrandOut:
    out = BrandOut.model_validate(brand)
    for a in out.assets:
        asset = next(x for x in brand.assets if x.id == a.id)
        a.url = store.presigned_url(asset.storage_key)
    out.open_alerts = db.scalar(
        select(func.count()).select_from(Finding).where(Finding.brand_id == brand.id, Finding.decision.in_(OPEN),
                                                        Finding.last_alert_at.is_not(None))
    ) or 0
    out.next_auto_scan_at = autoscan.next_due(brand)
    return out


def _get(db: Session, brand_id: uuid.UUID) -> Brand:
    brand = db.scalar(
        select(Brand).where(Brand.id == brand_id).options(selectinload(Brand.assets), selectinload(Brand.allowlist))
    )
    if brand is None:
        raise HTTPException(404, "Brand not found")
    return brand


@router.get("", response_model=list[BrandOut])
def list_brands(_: User = Depends(current_user), db: Session = Depends(get_db)):
    brands = db.scalars(
        select(Brand).order_by(Brand.name).options(selectinload(Brand.assets), selectinload(Brand.allowlist))
    ).all()
    return [_out(db, b) for b in brands]


@router.post("", response_model=BrandOut, status_code=201)
def create_brand(body: BrandIn, _: User = Depends(require_admin), db: Session = Depends(get_db)):
    brand = Brand(name=body.name.strip(), description=body.description,
                  keywords=_clean_terms(body.keywords) or [body.name.strip().lower()],
                  product_terms=_clean_terms(body.product_terms),
                  is_active=body.is_active, alert_min_level=body.alert_min_level,
                  auto_scan_enabled=body.auto_scan_enabled, auto_scan_frequency=body.auto_scan_frequency,
                  auto_scan_runners=list(body.auto_scan_runners or []))
    seen = set()
    for item in body.allowlist:
        value = _normalize_allow(item.kind, item.value)
        if (item.kind, value) not in seen:
            seen.add((item.kind, value))
            brand.allowlist.append(BrandAllow(kind=item.kind, value=value))
    db.add(brand)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "A brand with this name already exists") from None
    return _out(db, _get(db, brand.id))


@router.get("/{brand_id}", response_model=BrandOut)
def get_brand(brand_id: uuid.UUID, _: User = Depends(current_user), db: Session = Depends(get_db)):
    return _out(db, _get(db, brand_id))


@router.patch("/{brand_id}", response_model=BrandOut)
def update_brand(brand_id: uuid.UUID, body: BrandUpdate, _: User = Depends(require_admin),
                 db: Session = Depends(get_db)):
    brand = _get(db, brand_id)
    data = body.model_dump(exclude_unset=True)
    for key in ("keywords", "product_terms"):
        if key in data and data[key] is not None:
            data[key] = _clean_terms(data[key])
    for key, value in data.items():
        if value is not None:
            setattr(brand, key, value)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "A brand with this name already exists") from None
    return _out(db, _get(db, brand_id))


@router.delete("/{brand_id}", status_code=204)
def delete_brand(brand_id: uuid.UUID, _: User = Depends(require_admin), db: Session = Depends(get_db)):
    db.delete(_get(db, brand_id))
    db.commit()


# ------------------------------------------------------------------ assets (official logo upload)
@router.post("/{brand_id}/assets", response_model=AssetOut, status_code=201)
def upload_asset(
    brand_id: uuid.UUID,
    kind: AssetKind = Form(AssetKind.logo),
    file: UploadFile = File(...),
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    brand = _get(db, brand_id)
    data = file.file.read(MAX_ASSET_BYTES + 1)
    if len(data) > MAX_ASSET_BYTES:
        raise HTTPException(413, "File is larger than 5 MB")
    try:
        asset = add_asset(db, brand, kind, file.filename or "", data, file.content_type)
    except NotAnImage as exc:
        raise HTTPException(422, str(exc)) from None
    db.commit()
    out = AssetOut.model_validate(asset)
    out.url = store.presigned_url(asset.storage_key)
    return out


@router.delete("/{brand_id}/assets/{asset_id}", status_code=204)
def delete_asset(brand_id: uuid.UUID, asset_id: uuid.UUID, _: User = Depends(require_admin),
                 db: Session = Depends(get_db)):
    asset = db.get(BrandAsset, asset_id)
    if asset is None or asset.brand_id != brand_id:
        raise HTTPException(404, "Asset not found")
    db.delete(asset)
    db.commit()


# ------------------------------------------------------------------ allowlists
@router.get("/{brand_id}/allowlist", response_model=list[AllowOut])
def list_allow(brand_id: uuid.UUID, _: User = Depends(current_user), db: Session = Depends(get_db)):
    return _get(db, brand_id).allowlist


@router.post("/{brand_id}/allowlist", response_model=AllowOut, status_code=201)
def add_allow(brand_id: uuid.UUID, body: AllowIn, _: User = Depends(require_admin),
              db: Session = Depends(get_db)):
    _get(db, brand_id)
    row = BrandAllow(brand_id=brand_id, kind=body.kind, value=_normalize_allow(body.kind, body.value))
    db.add(row)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Already in the allowlist") from None
    return row


@router.delete("/{brand_id}/allowlist/{allow_id}", status_code=204)
def delete_allow(brand_id: uuid.UUID, allow_id: uuid.UUID, _: User = Depends(require_admin),
                 db: Session = Depends(get_db)):
    row = db.get(BrandAllow, allow_id)
    if row is None or row.brand_id != brand_id:
        raise HTTPException(404, "Allowlist entry not found")
    db.delete(row)
    db.commit()
