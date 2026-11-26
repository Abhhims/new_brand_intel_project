"""Evidence storage in the S3-compatible bucket (FND-10, FND-12). Nothing fetched is written anywhere else."""

import hashlib
import mimetypes
from dataclasses import dataclass, field
from functools import lru_cache

import boto3
from botocore.client import Config
from botocore.exceptions import ClientError

from app.config import get_settings


@dataclass
class EvidenceItem:
    """Something a module wants stored with its alert."""

    kind: str  # EvidenceKind value
    data: bytes | None = None
    content_type: str | None = None
    meta: dict = field(default_factory=dict)
    name: str | None = None  # file name hint


@dataclass
class StoredObject:
    storage_key: str
    sha256: str
    size: int
    content_type: str


def _client(endpoint: str | None = None):
    s = get_settings()
    return boto3.client(
        "s3",
        endpoint_url=endpoint or s.s3_endpoint_url,
        aws_access_key_id=s.s3_access_key,
        aws_secret_access_key=s.s3_secret_key,
        region_name=s.s3_region,
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
    )


@lru_cache
def client():
    return _client()


@lru_cache
def ensure_bucket() -> str:
    bucket = get_settings().s3_bucket
    c = client()
    try:
        c.head_bucket(Bucket=bucket)
    except ClientError:
        c.create_bucket(Bucket=bucket)
    return bucket


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def put(key: str, data: bytes, content_type: str | None = None) -> StoredObject:
    bucket = ensure_bucket()
    ctype = content_type or mimetypes.guess_type(key)[0] or "application/octet-stream"
    # Stored as an attachment so a malicious HTML/SVG never renders inline from the bucket
    client().put_object(
        Bucket=bucket, Key=key, Body=data, ContentType=ctype,
        ContentDisposition=f'attachment; filename="{key.rsplit("/", 1)[-1]}"'
        if not ctype.startswith("image/") or ctype == "image/svg+xml" else "inline",
    )
    return StoredObject(storage_key=key, sha256=sha256(data), size=len(data), content_type=ctype)


def get(key: str) -> bytes:
    return client().get_object(Bucket=ensure_bucket(), Key=key)["Body"].read()


def presigned_url(key: str, expires: int = 3600) -> str:
    s = get_settings()
    public = _client(s.s3_public_endpoint_url) if s.s3_public_endpoint_url else client()
    return public.generate_presigned_url(
        "get_object", Params={"Bucket": s.s3_bucket, "Key": key}, ExpiresIn=expires
    )


_EXT = {
    "image/png": "png", "image/jpeg": "jpg", "image/gif": "gif", "image/webp": "webp",
    "image/x-icon": "ico", "image/vnd.microsoft.icon": "ico", "image/svg+xml": "svg",
    "text/html": "html", "application/json": "json", "application/pdf": "pdf",
    "application/vnd.android.package-archive": "apk",
}


def extension_for(content_type: str | None, name: str | None = None) -> str:
    if name and "." in name:
        return name.rsplit(".", 1)[-1][:10].lower()
    return _EXT.get((content_type or "").lower(), "bin")
