"""Static attachment analysis: malware scan, pattern rules, macros, dangerous types. Nothing is executed."""

from __future__ import annotations

import io
import re
import zipfile

from app.modules.email import engines, intel
from app.modules.email.model import Attachment

EXECUTABLE_EXT = {"exe", "scr", "com", "pif", "bat", "cmd", "msi", "jar", "vbs", "vbe", "js", "jse", "wsf", "wsh",
                  "ps1", "hta", "cpl", "dll", "lnk", "iso", "img", "apk"}
MACRO_OFFICE_EXT = {"doc", "docm", "xls", "xlsm", "xlsb", "ppt", "pptm", "dotm", "xlam"}
ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tar", "ace", "cab"}
_EXE_ALT = "|".join(EXECUTABLE_EXT)
DANGEROUS_DOUBLE = re.compile(rf"\.(pdf|doc|xls|ppt|jpg|png|txt|htm|html)\.({_EXE_ALT})$", re.I)


def _ext(name: str) -> str:
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def _has_macros(data: bytes) -> bool:
    try:
        from oletools.olevba import VBA_Parser

        parser = VBA_Parser(filename="a", data=data)
        try:
            return bool(parser.detect_vba_macros())
        finally:
            parser.close()
    except Exception:  # noqa: BLE001 - not an Office file, or oletools cannot read it
        return False


def _archive_has_executable(att: Attachment) -> bool:
    if att.archive_members:
        return any(_ext(m) in EXECUTABLE_EXT or DANGEROUS_DOUBLE.search(m) for m in att.archive_members)
    if _ext(att.name) in ARCHIVE_EXT and att.data[:2] == b"PK":
        try:
            with zipfile.ZipFile(io.BytesIO(att.data)) as z:
                return any(_ext(n) in EXECUTABLE_EXT for n in z.namelist())
        except (zipfile.BadZipFile, OSError):
            return False
    return False


def analyse_attachment(att: Attachment) -> dict:
    ext = _ext(att.name)
    reasons: list[str] = []
    clam = engines.clamav_scan(att.data)
    yr = engines.yara_scan(att.data)
    hashv = intel.urlhaus_hash(att.sha256)

    malware = clam.malicious or hashv.malicious
    if ext in EXECUTABLE_EXT:
        reasons.append(f"executable/script type .{ext}")
    if DANGEROUS_DOUBLE.search(att.name):
        reasons.append("double extension hiding an executable")
    if ext in MACRO_OFFICE_EXT and _has_macros(att.data):
        reasons.append("Office file contains macros")
    if _archive_has_executable(att):
        reasons.append("archive contains an executable")
    if yr.malicious:
        reasons.append("matched a phishing/malware rule")

    return {
        "name": att.name, "content_type": att.content_type, "sha256": att.sha256, "size": att.size,
        "malware": malware, "suspicious": bool(reasons),
        "reasons": reasons, "archive_members": att.archive_members[:50],
        "verdicts": [clam.as_dict(), yr.as_dict(), hashv.as_dict()],
    }
