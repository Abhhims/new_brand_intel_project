"""What every detection module produces and receives."""

from __future__ import annotations

import re
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from typing import Protocol

from sqlalchemy.orm import Session

from app.core.allowlist import social_handle
from app.core.evidence import EvidenceItem
from app.core.imaging import ImageHashes
from app.core.scoring import Signals
from app.core.similarity import best_similarity, brand_terms_in_text, domain_label
from app.db.models import AllowKind, AssetKind, Brand, ModuleName, ScanStatus

STRONG_TERM_LEN = 6
FUZZY_ALONE_LEN = 8
COMPANY_WORDS = {"private", "limited", "public", "company", "group", "india", "global", "services", "service",
                 "solutions", "technologies", "technology", "official", "agent", "the", "and", "corp", "corporation",
                 "enterprises", "holdings", "international", "bank"}


def parse_date(value) -> date | None:
    """ISO strings ('2026-01-05', '2026-01-05T10:00:00Z', '2026-01-05 10:00:00+00'), epoch seconds, date/datetime."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if isinstance(value, int | float) or (isinstance(value, str) and value.isdigit()):
        try:
            ts = float(value)
            return datetime.fromtimestamp(ts / 1000 if ts > 1e11 else ts, UTC).date()
        except (ValueError, OverflowError, OSError):
            return None
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})", str(value).strip())
    if not m:
        return None
    try:
        return date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    except ValueError:
        return None


def _flat(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


@dataclass
class Relevance:
    strong_hits: list[str]
    weak_hits: list[str]
    context_hits: list[str]
    similarity: float
    relevant: bool

    @property
    def terms_used(self) -> list[str]:
        return list(dict.fromkeys(self.strong_hits + self.weak_hits))


# ---------------------------------------------------------------- scan components (D-31)
# Severity order: a component reports the worst thing that happened to it during the run.
COMPONENT_SEVERITY = {"ok": 0, "skipped": 1, "not_configured": 2, "unavailable": 3, "failed": 4}


@dataclass
class Component:
    name: str
    status: str = "ok"
    messages: list[str] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    fatal: bool = False


class ScanReport:
    """Per-component outcome of one scan run (D-31). A component that could not run is reported as such —
    never as "nothing found"."""

    def __init__(self) -> None:
        self._components: dict[str, Component] = {}

    def _add(self, name: str, status: str, message: str = "", fatal: bool = False, **counts: int) -> None:
        c = self._components.setdefault(name, Component(name))
        if COMPONENT_SEVERITY[status] > COMPONENT_SEVERITY[c.status]:
            c.status = status
        if message and message not in c.messages:
            c.messages.append(message)
        for key, n in counts.items():
            c.counts[key] = c.counts.get(key, 0) + int(n)
        c.fatal = c.fatal or fatal

    def ok(self, name: str, message: str = "", **counts: int) -> None:
        self._add(name, "ok", message, **counts)

    def failed(self, name: str, message: str, fatal: bool = False, **counts: int) -> None:
        self._add(name, "failed", message, fatal, **counts)

    def unavailable(self, name: str, message: str, fatal: bool = False) -> None:
        self._add(name, "unavailable", message, fatal)

    def not_configured(self, name: str, message: str, fatal: bool = False) -> None:
        self._add(name, "not_configured", message, fatal)

    def skipped(self, name: str, message: str) -> None:
        self._add(name, "skipped", message)

    def as_list(self) -> list[dict]:
        return [{"name": c.name, "status": c.status, "message": "; ".join(c.messages[:5]), "counts": c.counts,
                 "fatal": c.fatal} for c in self._components.values()]

    @property
    def errors(self) -> list[str]:
        return [f"{c.name}: {m}" for c in self._components.values()
                if c.status in ("failed", "unavailable") for m in c.messages]


def derive_run_status(components: list[dict], crashed: bool) -> ScanStatus:
    """The run's state from its components (D-31): failed > completed_with_errors > partially_completed."""
    if crashed or any(c.get("fatal") and c["status"] in ("failed", "unavailable", "not_configured")
                      for c in components):
        return ScanStatus.failed
    statuses = {c["status"] for c in components}
    if "failed" in statuses:
        return ScanStatus.completed_with_errors
    if statuses & {"unavailable", "not_configured"}:
        return ScanStatus.partially_completed
    return ScanStatus.completed


@dataclass
class Detection:
    """One thing a module observed. The engine (app/core/findings.py) turns it into a Candidate or Finding,
    an observation, and — when the alert rule is met — an alert (SP2, D-33)."""

    entity_key: str                 # stable identity, e.g. the domain or "store:package"
    title: str
    signals: Signals
    details: dict                   # the module's Expected Output fields (requirements §3)
    similarity: float | None = None
    suspected_phishing: bool = False
    source_url: str | None = None
    evidence: list[EvidenceItem] = field(default_factory=list)
    module: ModuleName | None = None  # override, e.g. the domain pipeline's stage (D-19)
    analysed: bool = True           # False = Candidate: discovered, but no deeper evidence yet (D-33)
    state: dict = field(default_factory=dict)  # comparable facts the module knows best; None = unknown (D-36)


@dataclass
class BrandContext:
    """Read-only snapshot of a brand, so modules never depend on ORM sessions for brand data."""

    id: uuid.UUID
    name: str
    keywords: list[str]
    product_terms: list[str]
    official_domains: list[str]
    official_packages: list[str]
    official_publishers: list[str]
    official_handles: list[str]
    email_domains: list[str]
    logo_hashes: list[ImageHashes]
    favicon_hashes: list[ImageHashes]
    favicon_mmh3: list[int]
    official_signers: list[str] = field(default_factory=list)  # APK signing cert SHA-256 (D-26)
    # Optional date range chosen when starting a scan (D-50): only content published / domains created in it
    date_from: date | None = None
    date_to: date | None = None

    @property
    def has_date_range(self) -> bool:
        return bool(self.date_from or self.date_to)

    def in_date_range(self, value) -> bool:
        """True when the date is inside the scan's range. Unknown/unparseable dates are kept (never hidden)."""
        if not self.has_date_range:
            return True
        d = parse_date(value)
        if d is None:
            return True
        return (self.date_from is None or d >= self.date_from) and (self.date_to is None or d <= self.date_to)

    @property
    def terms(self) -> list[str]:
        """Brand words to look for: keywords, else the brand name."""
        return self.keywords or [self.name]

    @property
    def labels(self) -> list[str]:
        """Comparable labels: keywords + labels of official domains (example.com -> example)."""
        out = [k.lower().replace(" ", "") for k in self.terms]
        out += [domain_label(d) for d in self.official_domains]
        return list(dict.fromkeys(x for x in out if x))

    @property
    def all_brand_image_hashes(self) -> list[ImageHashes]:
        return self.logo_hashes + self.favicon_hashes

    # ---- term strength (D-25): short abbreviations like "KCPL" collide with many unrelated names
    @property
    def strong_terms(self) -> list[str]:
        """Distinctive brand words/phrases (6+ letters once spaces are removed): count on their own, fuzzily."""
        return [t for t in self.terms + self.product_terms if len(_flat(t)) >= STRONG_TERM_LEN] or self.terms

    @property
    def weak_terms(self) -> list[str]:
        """Short abbreviations: only count as an exact word, and only together with context."""
        return [t for t in self.terms + self.product_terms if len(_flat(t)) < STRONG_TERM_LEN]

    @property
    def strong_labels(self) -> list[str]:
        return [x for x in self.labels if len(x) >= STRONG_TERM_LEN] or self.labels

    @property
    def context_words(self) -> list[str]:
        """Words from the brand name/keywords that confirm a short abbreviation refers to this brand
        ('Kodachadri Chits Private Limited' → kodachadri, chits)."""
        words = re.findall(r"[a-z]{4,}", " ".join([self.name, *self.terms, *self.product_terms]).lower())
        weak = {_flat(t) for t in self.weak_terms}  # an abbreviation is never its own confirmation
        return list(dict.fromkeys(w for w in words if w not in COMPANY_WORDS and w not in weak))

    def relevance(self, text: str, name: str | None = None, threshold: float = 85.0) -> Relevance:
        """Does `text` (and the item's `name`) refer to this brand? Shared by app, APK, social, document modules."""
        strong = brand_terms_in_text(text, self.strong_terms)
        weak = brand_terms_in_text(text, self.weak_terms)
        context = brand_terms_in_text(text, self.context_words)
        long_terms = [t for t in self.strong_terms if len(_flat(t)) >= FUZZY_ALONE_LEN]
        medium_terms = [t for t in self.strong_terms if len(_flat(t)) < FUZZY_ALONE_LEN]
        sim_long = best_similarity(name, long_terms)[0] if name and long_terms else 0.0
        sim_medium = best_similarity(name, medium_terms)[0] if name and medium_terms else 0.0
        # A look-alike of a long name stands on its own; of a 6-7 letter name (one letter = ~15%) it needs context
        relevant = (bool(strong) or sim_long >= threshold or bool(weak and context)
                    or (sim_medium >= threshold and bool(context or weak)))
        return Relevance(strong_hits=strong, weak_hits=weak, context_hits=context,
                         similarity=max(sim_long, sim_medium), relevant=relevant)

    @classmethod
    def from_brand(cls, brand: Brand) -> BrandContext:
        def hashes(kinds: set[AssetKind]) -> list[ImageHashes]:
            return [
                ImageHashes(a.phash, a.dhash, a.phash)
                for a in brand.assets if a.kind in kinds and a.phash and a.dhash
            ]

        return cls(
            id=brand.id,
            name=brand.name,
            keywords=list(brand.keywords or []),
            product_terms=list(brand.product_terms or []),
            official_domains=[d.lower() for d in brand.allowed(AllowKind.domain)],
            official_packages=[p.lower() for p in brand.allowed(AllowKind.package)],
            official_publishers=brand.allowed(AllowKind.publisher),
            # normalised again here so values saved before normalisation existed still match
            official_handles=[social_handle(h) for h in brand.allowed(AllowKind.social_handle)],
            email_domains=[d.lower() for d in brand.allowed(AllowKind.email_domain)],
            logo_hashes=hashes({AssetKind.logo, AssetKind.app_icon}),
            favicon_hashes=hashes({AssetKind.favicon}),
            favicon_mmh3=[a.mmh3 for a in brand.assets if a.kind == AssetKind.favicon and a.mmh3 is not None],
            official_signers=[v.upper() for v in brand.allowed(AllowKind.signing_cert)],
        )


class Module(Protocol):
    name: ModuleName

    def run(self, ctx: BrandContext, db: Session) -> Iterable[Detection]: ...
