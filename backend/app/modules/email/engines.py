"""Analysis engines: Rspamd (spam/phish scoring), ClamAV (attachment malware), YARA (pattern rules).

Rspamd and ClamAV are separate containers reached over their network APIs; YARA runs in-process against bundled
rules. Each returns a ToolVerdict; when an engine is unreachable or disabled the verdict is `not_checked`, never a
guess (spec §4 precision safeguard).
"""

from __future__ import annotations

import socket
import struct
from datetime import UTC, datetime
from functools import lru_cache

import structlog

from app.config import get_settings
from app.modules.email.model import ToolVerdict

log = structlog.get_logger(__name__)

PHISH_SYMBOLS = ("PHISHING", "PHISHED", "DMARC_POLICY_REJECT", "DMARC_POLICY_QUARANTINE", "SPOOF",
                 "FORGED_SENDER", "FAKE_REPLY", "URL_PHISHED", "CLAM_VIRUS")
CLAMAV_MAX = 40 * 1024 * 1024


def _now() -> datetime:
    return datetime.now(UTC)


def _rspamd_url() -> str:
    return get_settings().rspamd_url.rstrip("/")


def rspamd_check(raw: bytes) -> ToolVerdict:
    url = f"{_rspamd_url()}/checkv2"
    try:
        # Rspamd is an internal, trusted service; it is not an untrusted external host, so it is called directly.
        import httpx

        with httpx.Client(timeout=20.0) as client:
            resp = client.post(url, content=raw, headers={"Content-Type": "application/octet-stream"})
        if resp.status_code != 200:
            return ToolVerdict("rspamd", status="error", details={"http": resp.status_code}, checked_at=_now())
        data = resp.json()
    except Exception as exc:  # noqa: BLE001 - container down
        log.info("rspamd_unavailable", error=str(exc)[:150])
        return ToolVerdict("rspamd", status="not_checked", details={"reason": str(exc)[:150]}, checked_at=_now())
    symbols = data.get("symbols", {})
    action = str(data.get("action", "")).lower()
    fired = [s for s in symbols if any(p in s.upper() for p in PHISH_SYMBOLS)]
    malicious = action in ("reject", "add header", "rewrite subject") or bool(fired)
    return ToolVerdict("rspamd", status="ok", malicious=malicious, score=data.get("score"),
                       details={"action": action, "required_score": data.get("required_score"),
                                "symbols": list(symbols), "phish_symbols": fired}, checked_at=_now())


def _clamd_instream(host: str, port: int, data: bytes) -> str:
    with socket.create_connection((host, port), timeout=30) as sock:
        sock.sendall(b"zINSTREAM\x00")
        view = memoryview(data)
        for i in range(0, len(view), 65536):
            chunk = view[i : i + 65536]
            sock.sendall(struct.pack("!I", len(chunk)) + chunk)
        sock.sendall(struct.pack("!I", 0))
        reply = b""
        while b"\x00" not in reply and len(reply) < 4096:
            part = sock.recv(4096)
            if not part:
                break
            reply += part
    return reply.rstrip(b"\x00").decode("utf-8", "replace").strip()


def clamav_scan(data: bytes) -> ToolVerdict:
    s = get_settings()
    if not s.clamav_enabled:
        return ToolVerdict("clamav", status="not_checked", details={"reason": "disabled"}, checked_at=_now())
    try:
        reply = _clamd_instream(s.clamav_host, s.clamav_port, data[:CLAMAV_MAX])
    except Exception as exc:  # noqa: BLE001 - container down
        log.info("clamav_unavailable", error=str(exc)[:150])
        return ToolVerdict("clamav", status="not_checked", details={"reason": str(exc)[:150]}, checked_at=_now())
    if reply.endswith("FOUND"):
        signature = reply.split(":", 1)[-1].rsplit(" FOUND", 1)[0].strip()
        return ToolVerdict("clamav", status="ok", malicious=True, details={"signature": signature}, checked_at=_now())
    if reply.endswith("OK"):
        return ToolVerdict("clamav", status="ok", malicious=False, checked_at=_now())
    return ToolVerdict("clamav", status="error", details={"reply": reply[:200]}, checked_at=_now())


@lru_cache(maxsize=1)
def _yara_rules():
    import os

    import yara

    rules_dir = get_settings().yara_rules_dir
    files = {}
    if os.path.isdir(rules_dir):
        for name in sorted(os.listdir(rules_dir)):
            if name.endswith((".yar", ".yara")):
                files[name] = os.path.join(rules_dir, name)
    if not files:
        return None
    try:
        return yara.compile(filepaths=files)
    except Exception as exc:  # noqa: BLE001 - a broken rule file must not disable analysis
        log.warning("yara_compile_failed", error=str(exc)[:200])
        return None


def yara_scan(data: bytes) -> ToolVerdict:
    rules = _yara_rules()
    if rules is None:
        return ToolVerdict("yara", status="not_checked", details={"reason": "no rules"}, checked_at=_now())
    try:
        matches = rules.match(data=data, timeout=20)
    except Exception as exc:  # noqa: BLE001
        return ToolVerdict("yara", status="error", details={"reason": str(exc)[:150]}, checked_at=_now())
    names = [m.rule for m in matches]
    return ToolVerdict("yara", status="ok", malicious=bool(names), details={"matches": names}, checked_at=_now())
