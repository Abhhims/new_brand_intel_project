"""Brand logo on websites (§3.6, LOGO-01…06).

Crawls suspicious websites — live domains found by the domain pipeline, plus extra target URLs
(demo fixtures) — extracts every image (img tags, CSS backgrounds, inline SVG rendered to PNG),
computes perceptual hashes and compares them with the official logos. A match above the threshold
creates an alert with a screenshot of the page and the matched image as evidence.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

import structlog
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.core.browser import capture
from app.core.evidence import EvidenceItem
from app.core.scoring import Signals
from app.core.similarity import registered_domain
from app.db.models import DomainCheck, ModuleName
from app.modules.base import BrandContext, Detection, ScanReport
from app.modules.pagecheck import analyse

log = structlog.get_logger(__name__)

LOOKBACK_DAYS = 7
MAX_TARGETS = 200


class LogoModule:
    name = ModuleName.logo

    def __init__(self, capture_fn=capture, extra_targets: list[str] | None = None) -> None:
        self._capture = capture_fn
        self._extra = extra_targets
        self.stats: dict = {}
        self.report = ScanReport()

    def targets(self, ctx: BrandContext, db: Session) -> list[str]:
        since = datetime.now(UTC) - timedelta(days=LOOKBACK_DAYS)
        rows = db.scalars(select(DomainCheck.final_url).where(
            DomainCheck.brand_id == ctx.id, DomainCheck.checked_at >= since, DomainCheck.final_url.is_not(None))).all()
        urls = list(dict.fromkeys(rows))
        if self._extra is not None:  # injected targets (tests)
            urls += self._extra
        official = {registered_domain(d) for d in ctx.official_domains}
        out = [u for u in dict.fromkeys(urls) if registered_domain(urlsplit(u).hostname or "") not in official]
        return out[:MAX_TARGETS]

    def run(self, ctx: BrandContext, db: Session) -> Iterator[Detection]:
        if not ctx.logo_hashes:
            # nothing to compare against: the run cannot claim "no logo misuse" (D-31)
            self.report.not_configured("Official logo assets", "No official logo uploaded for this brand - upload "
                                                               "one under Brands > Assets", fatal=True)
            return
        self.report.ok("Official logo assets", logos=len(ctx.logo_hashes))
        targets = self.targets(ctx, db)
        self.report.ok("Target websites", targets=len(targets))
        self.stats.update(pages_checked=0, images_compared=0, matches=0, targets=len(targets))
        threshold = get_settings().logo_match_threshold
        for url in targets:
            try:
                cap = self._capture(url, collect_images=True)
            except Exception as exc:  # noqa: BLE001
                self.report.failed("Browser capture", f"{url}: {type(exc).__name__}: {exc}", capture_failed=1)
                continue
            if cap.status is None:
                self.report.failed("Browser capture", f"{url}: {cap.error or 'no response'}", capture_failed=1)
                continue
            self.report.ok("Browser capture", captured=1)
            self.stats["pages_checked"] += 1
            self.stats["images_compared"] += len(cap.images)
            facts = analyse(cap, ctx)
            if facts.logo_score < threshold:
                continue
            self.stats["matches"] += 1
            host = urlsplit(cap.final_url).hostname or url
            evidence = []
            if cap.screenshot:
                evidence.append(EvidenceItem("screenshot", data=cap.screenshot, content_type="image/png",
                                             meta={"url": cap.final_url, "title": cap.title}))
            if facts.logo_image:
                evidence.append(EvidenceItem("image", data=facts.logo_image, meta={
                    "url": facts.logo_image_url, "logo_match_score": facts.logo_score}))
            signals = Signals(official_logo=True, https=cap.final_url.startswith("https://"),
                              login_payment_keywords=facts.login_payment)
            details = {
                "Website": host,
                "Page URL": cap.final_url,
                "Logo Match Score": round(facts.logo_score),
                "Screenshot": bool(cap.screenshot),
                "Matched Image URL": facts.logo_image_url,
                "Page Title": cap.title,
                "Keywords Found": facts.keywords_found,
            }
            yield Detection(entity_key=cap.final_url, title=f"Official logo used on {host}", signals=signals,
                          details=details, similarity=facts.logo_score, source_url=cap.final_url, evidence=evidence)
        if targets and self.stats["pages_checked"] == 0:
            # every target page failed to load: nothing was compared, so this is not "no logo misuse" (D-31)
            self.report.failed("Browser capture", "no target page could be captured", fatal=True)
