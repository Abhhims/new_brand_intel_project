"""Image fingerprints: perceptual hashes for logo matching (LOGO-03/04, APK-05, SOC-08) and the
Shodan-style favicon hash (PHI-03/06)."""

import base64
import io
from dataclasses import dataclass

import imagehash
import mmh3
from PIL import Image, ImageOps, UnidentifiedImageError

HASH_BITS = 64  # 8x8 hashes


@dataclass(frozen=True)
class ImageHashes:
    phash: str
    dhash: str
    ahash: str

    def as_dict(self) -> dict[str, str]:
        return {"phash": self.phash, "dhash": self.dhash, "ahash": self.ahash}


def _load(data: bytes) -> Image.Image | None:
    try:
        img = Image.open(io.BytesIO(data))
        img.seek(0)  # first frame of ICO/GIF
        img.load()
    except (UnidentifiedImageError, OSError, ValueError, Image.DecompressionBombError):
        return None
    if img.mode in ("RGBA", "LA", "P"):
        img = img.convert("RGBA")
        background = Image.new("RGBA", img.size, (255, 255, 255, 255))
        img = Image.alpha_composite(background, img)
    return img.convert("RGB")


def _trim(img: Image.Image) -> Image.Image:
    """Crop uniform borders so a logo with padding still matches the bare logo."""
    gray = ImageOps.grayscale(img)
    bg = gray.getpixel((0, 0))
    mask = gray.point(lambda p: 255 if abs(p - bg) > 12 else 0)
    box = mask.getbbox()
    return img.crop(box) if box else img


def hashes_for(data: bytes) -> ImageHashes | None:
    img = _load(data)
    if img is None or min(img.size) < 8:
        return None
    img = _trim(img)
    return ImageHashes(
        phash=str(imagehash.phash(img)),
        dhash=str(imagehash.dhash(img)),
        ahash=str(imagehash.average_hash(img)),
    )


def _distance(a: str, b: str) -> int:
    return int(imagehash.hex_to_hash(a) - imagehash.hex_to_hash(b))  # plain int, not numpy


def match_score(candidate: ImageHashes, official: ImageHashes) -> float:
    """0-100: 100 = identical fingerprints. Average of pHash and dHash agreement (robust to
    re-encoding, resizing and small colour changes)."""
    p = 1 - _distance(candidate.phash, official.phash) / HASH_BITS
    d = 1 - _distance(candidate.dhash, official.dhash) / HASH_BITS
    return float(round(max(0.0, (p + d) / 2) * 100, 2))


def best_match(candidate: ImageHashes, officials: list[ImageHashes]) -> float:
    return float(max((match_score(candidate, o) for o in officials), default=0.0))


def favicon_hash(data: bytes) -> int:
    """Shodan-compatible favicon hash: mmh3 of the base64 (with newlines) of the raw bytes."""
    return mmh3.hash(base64.encodebytes(data))


def is_image(data: bytes) -> bool:
    return _load(data) is not None
