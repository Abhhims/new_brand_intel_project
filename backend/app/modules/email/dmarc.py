"""Capability D: DMARC aggregate report parsing and alerting.

A DMARC aggregate report (rua) lists every source IP that sent email claiming to be from the brand's domain, and
whether each passed SPF/DKIM/DMARC. Reports arrive as XML, often gzip- or zip-compressed, by email to a mailbox.
We parse them with defusedxml (safe against XML bombs) and raise an alert for each source that fails DMARC while
sending as the brand — i.e. a spoofing source.
"""

from __future__ import annotations

import gzip
import io
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime

import structlog
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.evidence import EvidenceItem
from app.core.scoring import Signals
from app.db.models import DmarcReport, ModuleName
from app.modules.base import BrandContext, Detection

log = structlog.get_logger(__name__)


@dataclass
class DmarcRow:
    source_ip: str
    count: int
    disposition: str | None
    dkim_result: str | None
    spf_result: str | None
    header_from: str | None

    @property
    def dmarc_pass(self) -> bool:
        return self.dkim_result == "pass" or self.spf_result == "pass"


@dataclass
class ParsedDmarcReport:
    org_name: str | None
    report_id: str | None
    domain: str | None
    policy: str | None
    begin: datetime | None
    end: datetime | None
    rows: list[DmarcRow] = field(default_factory=list)


def _xml_bytes(blob: bytes, filename: str) -> bytes:
    name = filename.lower()
    if name.endswith(".gz") or blob[:2] == b"\x1f\x8b":
        return gzip.decompress(blob)
    if name.endswith(".zip") or blob[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(blob)) as z:
            inner = next((n for n in z.namelist() if n.lower().endswith(".xml")), z.namelist()[0])
            return z.read(inner)
    return blob


def _text(node, tag: str) -> str | None:
    child = node.find(tag)
    return child.text.strip() if child is not None and child.text else None


def _ts(value: str | None) -> datetime | None:
    try:
        return datetime.fromtimestamp(int(value), UTC) if value else None
    except (ValueError, TypeError):
        return None


def parse_report(blob: bytes, filename: str = "report.xml") -> ParsedDmarcReport:
    from defusedxml.ElementTree import fromstring

    root = fromstring(_xml_bytes(blob, filename))  # raises on entity-expansion / external-entity attacks
    meta = root.find("report_metadata")
    policy = root.find("policy_published")
    date_range = meta.find("date_range") if meta is not None else None
    report = ParsedDmarcReport(
        org_name=_text(meta, "org_name") if meta is not None else None,
        report_id=_text(meta, "report_id") if meta is not None else None,
        domain=_text(policy, "domain") if policy is not None else None,
        policy=_text(policy, "p") if policy is not None else None,
        begin=_ts(_text(date_range, "begin")) if date_range is not None else None,
        end=_ts(_text(date_range, "end")) if date_range is not None else None,
    )
    for record in root.findall("record"):
        row = record.find("row")
        if row is None:
            continue
        pe = row.find("policy_evaluated")
        ident = record.find("identifiers")
        report.rows.append(DmarcRow(
            source_ip=_text(row, "source_ip") or "",
            count=int(_text(row, "count") or 0),
            disposition=_text(pe, "disposition") if pe is not None else None,
            dkim_result=_text(pe, "dkim") if pe is not None else None,
            spf_result=_text(pe, "spf") if pe is not None else None,
            header_from=_text(ident, "header_from") if ident is not None else None,
        ))
    return report


def store_and_findings(db: Session, brand: BrandContext, report: ParsedDmarcReport,
                       raw: bytes) -> Iterator[Detection]:
    """Persist report rows and yield a finding per failing source IP (grouped by domain+IP)."""
    for row in report.rows:
        if not row.source_ip:
            continue
        existing = db.scalar(select(DmarcReport).where(
            DmarcReport.report_id == (report.report_id or ""), DmarcReport.source_ip == row.source_ip,
            DmarcReport.header_from == (row.header_from or report.domain)))
        if existing is None:
            db.add(DmarcReport(
                brand_id=brand.id, report_id=report.report_id or "", org_name=report.org_name,
                domain=report.domain or "", policy=report.policy, begin=report.begin, end=report.end,
                source_ip=row.source_ip, count=row.count, header_from=row.header_from or report.domain,
                disposition=row.disposition, dkim_result=row.dkim_result, spf_result=row.spf_result,
                dmarc_pass=row.dmarc_pass))
        if row.dmarc_pass:
            continue  # legitimate authenticated source
        details = {
            "Domain": report.domain, "Source IP": row.source_ip, "Reporting Organisation": report.org_name,
            "Messages": row.count, "SPF": row.spf_result, "DKIM": row.dkim_result,
            "Disposition": row.disposition,
            "Report Period": f"{report.begin:%Y-%m-%d} to {report.end:%Y-%m-%d}" if report.begin and report.end else None,
        }
        yield Detection(
            entity_key=f"dmarc:{report.domain}:{row.source_ip}",
            title=f"Unauthenticated sender {row.source_ip} using {report.domain} ({row.count} messages)",
            signals=Signals(auth_fail_brand_from=True), details=details,
            evidence=[EvidenceItem("metadata", meta={"row": details, "raw_report_sha": None})],
            module=ModuleName.dmarc)


class DmarcModule:
    """Invoked by the DMARC-mailbox poller with the report blobs it fetched (not a scheduled scan runner)."""

    name = ModuleName.dmarc

    def __init__(self, reports: list[tuple[bytes, str]]) -> None:
        self._reports = reports
        self.stats: dict = {}
        self.errors: list[str] = []

    def run(self, ctx: BrandContext, db: Session) -> Iterator[Detection]:
        parsed_count = 0
        for blob, filename in self._reports:
            try:
                report = parse_report(blob, filename)
            except Exception as exc:  # noqa: BLE001 - malformed / hostile report
                self.errors.append(f"{filename}: {type(exc).__name__}: {exc}")
                continue
            if report.domain and report.domain.lower() not in {d.lower() for d in ctx.official_domains}:
                continue  # report is for a domain we do not own
            parsed_count += 1
            yield from store_and_findings(db, ctx, report, blob)
        self.stats["reports_parsed"] = parsed_count
