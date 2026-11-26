"""Normalising allowlist values (FND-06), so analysts can paste URLs and still get matching values."""

import re
from urllib.parse import urlsplit

# First path segment(s) that are not the account name, per site
_PREFIX_SEGMENTS = {"company", "in", "school", "showcase", "channel", "c", "user", "people", "pg", "s"}
_IGNORED_SEGMENTS = {"about", "posts", "videos", "featured", "home", "reels", "photos", "community"}


def _host(value: str) -> str:
    return (urlsplit(value if "://" in value else f"https://{value}").hostname or "").lower().removeprefix("www.")


def social_handle(value: str) -> str:
    """'https://www.instagram.com/kodachadrichits/' → 'kodachadrichits';
    'https://www.linkedin.com/company/chitkart/?original_referer=' → 'chitkart';
    'https://www.youtube.com/@Chitkart' → 'chitkart'; '@examplebank' → 'examplebank'."""
    value = value.strip()
    looks_like_url = "://" in value or re.match(r"^(www\.)?[a-z0-9-]+\.[a-z]{2,}/", value, re.I)
    if looks_like_url:
        parts = [p for p in urlsplit(value if "://" in value else f"https://{value}").path.split("/") if p]
        parts = [p for p in parts if p.lower() not in _IGNORED_SEGMENTS]
        while parts and parts[0].lower() in _PREFIX_SEGMENTS and len(parts) > 1:
            parts = parts[1:]
        if parts:
            value = parts[0]
        elif _host(value) == "t.me":
            value = ""
    return value.lstrip("@").strip().lower()


_HOST_ALIASES = {"twitter.com": "x.com", "fb.com": "facebook.com", "youtu.be": "youtube.com"}


def social_entry(value: str) -> str:
    """Allowlist value for a social account: 'site/handle' when a profile URL is given, so the same name on two
    sites stays two entries ('x.com/axisbank' vs 'facebook.com/axisbank'). A bare handle stays bare.
    social_handle() of the result is still the plain handle, which is what scans compare."""
    value = value.strip()
    handle = social_handle(value)
    looks_like_url = "://" in value or re.match(r"^(www\.)?[a-z0-9-]+\.[a-z]{2,}/", value, re.I)
    if not looks_like_url or not handle:
        return handle
    host = _host(value).removeprefix("m.").removeprefix("mobile.")
    return f"{_HOST_ALIASES.get(host, host)}/{handle}"


def domain(value: str) -> str:
    value = value.strip().lower()
    if "://" in value or "/" in value:
        value = _host(value)
    return value.removeprefix("www.").strip("/").strip(".")


def normalize(kind: str, value: str) -> str:
    """Kind is an AllowKind value."""
    value = value.strip()
    if kind in ("domain", "email_domain"):
        return domain(value.split("@")[-1] if kind == "email_domain" else value)
    if kind == "package":
        m = re.search(r"[?&]id=([\w.]+)", value)  # Play Store URL → package
        return (m.group(1) if m else value).lower()
    if kind == "social_handle":
        return social_entry(value)
    if kind == "signing_cert":
        from app.modules.apk.signing import normalize_fingerprint

        return normalize_fingerprint(value)
    return value  # publisher: keep exactly as written in the store
