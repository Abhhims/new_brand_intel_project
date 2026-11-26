"""Dataclasses shared across the email module (parser output + analysis result)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class UrlRef:
    url: str                       # unwrapped, de-obfuscated, normalised
    text: str = ""                 # visible link text (HTML)
    source: str = "text"           # text | html | header
    text_mismatch: bool = False    # visible text is a different domain from the href


@dataclass
class Attachment:
    name: str
    content_type: str
    data: bytes
    sha256: str
    size: int
    archive_members: list[str] = field(default_factory=list)
    nested: bool = False


@dataclass
class ImageRef:
    url: str
    source: str = "html"


@dataclass
class ParsedEmail:
    message_id: str | None = None
    sent_at: datetime | None = None
    subject: str = ""
    from_addr: str | None = None
    from_name: str = ""
    reply_to: str | None = None
    return_path: str | None = None
    to: list[str] = field(default_factory=list)
    received: list[str] = field(default_factory=list)
    sender_ip: str | None = None
    auth_results_header: str = ""
    text: str = ""
    html: str = ""
    urls: list[UrlRef] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    images_remote: list[ImageRef] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    is_forwarded_original: bool = False
    forwarded_by: str | None = None
    warnings: list[str] = field(default_factory=list)
    raw_sha256: str = ""

    @property
    def from_domain(self) -> str | None:
        return self.from_addr.split("@")[-1].lower() if self.from_addr and "@" in self.from_addr else None


@dataclass
class ToolVerdict:
    tool: str
    status: str = "ok"           # ok | not_checked | error
    malicious: bool = False
    score: float | None = None
    details: dict = field(default_factory=dict)
    checked_at: datetime | None = None

    def as_dict(self) -> dict:
        return {"tool": self.tool, "status": self.status, "malicious": self.malicious, "score": self.score,
                "details": self.details, "checked_at": self.checked_at.isoformat() if self.checked_at else None}
