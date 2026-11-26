"""Storing official brand assets (FND-05): fingerprints for matching + the file in object storage."""

import uuid

from sqlalchemy.orm import Session

from app.core import evidence as store
from app.core.imaging import favicon_hash, hashes_for
from app.db.models import AssetKind, Brand, BrandAsset


class NotAnImage(ValueError):
    pass


def add_asset(db: Session, brand: Brand, kind: AssetKind, filename: str, data: bytes,
              content_type: str | None) -> BrandAsset:
    hashes = hashes_for(data)
    if hashes is None:
        raise NotAnImage("Not a readable image (PNG, JPG, GIF, WEBP, ICO, BMP)")
    name = (filename or f"{kind.value}.png").replace("/", "_").replace("\\", "_")[:200]
    obj = store.put(f"brands/{brand.id}/{kind.value}/{uuid.uuid4().hex}-{name}", data, content_type)
    asset = BrandAsset(brand_id=brand.id, kind=kind, filename=name, storage_key=obj.storage_key,
                       content_type=obj.content_type, sha256=obj.sha256, phash=hashes.phash, dhash=hashes.dhash,
                       mmh3=favicon_hash(data) if kind == AssetKind.favicon else None)
    db.add(asset)
    db.flush()
    return asset
