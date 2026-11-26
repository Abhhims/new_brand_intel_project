"""Sensitive document monitoring (§3.5, DOC-01…08, D-06).

Sources: search-engine-indexed documents (filetype: queries), public file-sharing links (Drive,
OneDrive, Dropbox, Box, S3) and — for demo brands — fixtures/sources/documents_search.json.
Each document reachable without authentication is downloaded into the evidence bucket, its type is
detected from the bytes, text is extracted (never executing macros) and checked for brand keywords,
official domains, email addresses and sensitive patterns.
"""

from __future__ import annotations

import io
import re
import sys
from collections.abc import Iterator
from urllib.parse import unquote, urlsplit

import structlog
from sqlalchemy.orm import Session

from app.core import search
from app.core.evidence import EvidenceItem, sha256
from app.core.fetch import try_fetch
from app.core.scoring import Signals
from app.core.similarity import brand_terms_in_text
from app.db.models import ModuleName
from app.modules.base import BrandContext, Detection, ScanReport
from app.modules.common import report_search_failure

log = structlog.get_logger(__name__)

FILE_TYPES = ["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "csv"]
SHARE_SITES = ["drive.google.com", "docs.google.com", "onedrive.live.com", "1drv.ms", "dropbox.com", "box.com",
               "s3.amazonaws.com", "sharepoint.com"]
# DOC-07 filename/content patterns
SENSITIVE_PATTERNS = ["confidential", "internal", "internal use only", "restricted", "private", "salary", "payroll",
                      "compensation", "ctc", "customer", "customers", "client list", "employee", "password",
                      "credentials", "invoice", "bank statement", "account number", "pan", "aadhaar", "ssn",
                      "kyc", "not for distribution", "strictly", "secret", "audit", "board"]
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]{1,63}\.)+[a-z]{2,24}\b", re.I)
MANY_EMAILS = 5
MAX_TEXT = 2_000_000


def sniff_type(data: bytes, name: str) -> str:
    """File type from content (magic bytes), falling back to the extension."""
    head = data[:8]
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if head.startswith(b"%PDF"):
        return "PDF"
    if head.startswith(b"PK"):
        try:
            import zipfile

            names = zipfile.ZipFile(io.BytesIO(data)).namelist()
            if any(n.startswith("word/") for n in names):
                return "DOCX"
            if any(n.startswith("xl/") for n in names):
                return "XLSX"
            if any(n.startswith("ppt/") for n in names):
                return "PPTX"
        except Exception:  # noqa: BLE001
            pass
    if head.startswith(b"\xd0\xcf\x11\xe0"):
        return {"xls": "XLS", "ppt": "PPT"}.get(ext, "DOC")
    if sys.platform != "win32":  # libmagic is available in the Linux image
        try:
            import magic

            mime = magic.from_buffer(data[:4096], mime=True)
            if "csv" in mime or ext == "csv":
                return "CSV"
            if mime.startswith("text/"):
                return "TXT"
        except Exception:  # noqa: BLE001
            pass
    return ext.upper() or "UNKNOWN"


def extract_text(data: bytes, ftype: str) -> str:
    """Text only. Macros and embedded objects are never run."""
    try:
        if ftype == "PDF":
            from pdfminer.high_level import extract_text as pdf_text

            return pdf_text(io.BytesIO(data), maxpages=50)[:MAX_TEXT]
        if ftype == "DOCX":
            import docx

            d = docx.Document(io.BytesIO(data))
            parts = [p.text for p in d.paragraphs]
            for t in d.tables:
                parts += [c.text for row in t.rows for c in row.cells]
            return "\n".join(parts)[:MAX_TEXT]
        if ftype == "XLSX":
            from openpyxl import load_workbook

            wb = load_workbook(io.BytesIO(data), read_only=True, data_only=True)
            out = []
            for ws in wb.worksheets[:20]:
                for row in ws.iter_rows(max_row=5000, values_only=True):
                    out.append(" ".join(str(c) for c in row if c is not None))
            return "\n".join(out)[:MAX_TEXT]
        if ftype == "PPTX":
            from pptx import Presentation

            prs = Presentation(io.BytesIO(data))
            return "\n".join(sh.text_frame.text for sl in prs.slides for sh in sl.shapes
                             if sh.has_text_frame)[:MAX_TEXT]
        if ftype in ("CSV", "TXT"):
            return data[:MAX_TEXT].decode("utf-8", "ignore")
        # Legacy binary Office: printable strings only
        return " ".join(s.decode() for s in re.findall(rb"[\x20-\x7e]{4,}", data[:MAX_TEXT]))
    except Exception as exc:  # noqa: BLE001 - corrupted/encrypted documents
        log.info("text_extraction_failed", type=ftype, error=str(exc)[:200])
        return ""


class LiveDocSource:
    def results(self, ctx: BrandContext, report: ScanReport) -> list[dict]:
        out: dict[str, dict] = {}
        terms = " OR ".join(f'"{t}"' for t in ctx.terms[:3])
        queries = [f"({terms}) filetype:{ft}" for ft in ("pdf", "docx", "xlsx", "pptx", "doc", "xls")]
        queries.append(f"({terms}) ({' OR '.join('site:' + s for s in SHARE_SITES)})")
        component = search.component_name()
        for q in queries:
            try:
                for r in search.search(q, count=20):
                    source = "public-share-link" if any(s in r.url for s in SHARE_SITES) else "search-engine"
                    out.setdefault(r.url, {"title": r.title, "url": r.url, "snippet": r.snippet, "source": source})
                report.ok(component, queries=1)
            except search.SearchUnavailable as exc:
                # the provider is down or rate-limited: the remaining queries would fail the same way
                searched = any(c["name"] == component and c["counts"].get("queries") for c in report.as_list())
                report_search_failure(report, component, exc, fatal=not searched)
                break
        return list(out.values())


def _download_url(url: str) -> str:
    """Direct-download form of common share links."""
    m = re.search(r"drive\.google\.com/file/d/([\w-]+)", url)
    if m:
        return f"https://drive.google.com/uc?export=download&id={m.group(1)}"
    if "dropbox.com" in url:
        return re.sub(r"([?&])dl=0", r"\1dl=1", url) if "dl=0" in url else url + ("&" if "?" in url else "?") + "dl=1"
    return url


class DocumentsModule:
    name = ModuleName.documents

    def __init__(self, source=None) -> None:
        self._source = source
        self.stats: dict = {}
        self.report = ScanReport()

    def run(self, ctx: BrandContext, db: Session) -> Iterator[Detection]:
        source = self._source or LiveDocSource()
        results = source.results(ctx, self.report)
        self.stats.update(documents_checked=len(results), downloaded=0, flagged=0)
        for r in results:
            try:
                finding = self.analyse(ctx, r)
            except Exception as exc:  # noqa: BLE001
                self.report.failed("Document analysis", f"{r.get('url')}: {type(exc).__name__}: {exc}", failed=1)
                continue
            if finding:
                self.stats["flagged"] += 1
                yield finding

    def analyse(self, ctx: BrandContext, r: dict) -> Detection | None:
        url = r["url"]
        name = unquote(urlsplit(url).path.rsplit("/", 1)[-1]) or r.get("title") or "document"
        resp = try_fetch(_download_url(url))
        accessible = bool(resp and resp.status == 200 and resp.content
                          and "text/html" not in resp.content_type)  # an HTML page = login wall / preview
        data = resp.content if accessible else b""
        if resp is None:
            self.report.failed("Download & text extraction", f"{url}: could not be downloaded", failed=1)
        else:
            self.report.ok("Download & text extraction", fetched=1, downloaded=int(accessible))
        ftype = sniff_type(data, name) if data else (name.rsplit(".", 1)[-1].upper() if "." in name else "UNKNOWN")
        text = extract_text(data, ftype) if data else ""
        if data:
            self.stats["downloaded"] += 1

        surface = " ".join([name.replace("_", " ").replace("-", " "), r.get("title", ""), r.get("snippet", "")])
        host = (urlsplit(url).hostname or "").lower()
        host_official = any(host == d or host.endswith("." + d) for d in ctx.official_domains)
        rel = ctx.relevance(surface + " " + text)
        official_ref = bool(set(ctx.official_domains + ctx.email_domains)
                            & {d.lower() for d in DOMAIN_RE.findall(surface + " " + text)})
        brand_hits = rel.terms_used
        if not (rel.relevant or official_ref):
            return None  # DOC-04: must reference the brand (short abbreviations need context, D-25)

        emails = sorted(set(EMAIL_RE.findall(text)))
        lowered = (surface + " " + text).lower()
        # The company's own name ("... Private Limited") must not trigger sensitive patterns like "private"
        for phrase in sorted({ctx.name.lower(), *[t.lower() for t in ctx.terms]}, key=len, reverse=True):
            lowered = lowered.replace(phrase, " ")
        lowered = re.sub(r"\b(private|pvt\.?)\s+(limited|ltd\.?)\b", " ", lowered)
        official_domains = set(ctx.official_domains + ctx.email_domains)
        found_domains = sorted({d.lower() for d in DOMAIN_RE.findall(text)} & official_domains |
                               {e.split("@", 1)[1].lower() for e in emails} & official_domains)
        patterns = [p for p in SENSITIVE_PATTERNS if re.search(rf"(?<![a-z]){re.escape(p)}(?![a-z])", lowered)]
        brand_emails = [e for e in emails if e.split("@", 1)[1].lower() in official_domains]

        # D-06 exposure confidence
        if not accessible:
            confidence = "Low"
        elif patterns or len(emails) >= MANY_EMAILS:
            confidence = "High"
        elif brand_terms_in_text(text, ctx.terms):
            confidence = "Medium"
        else:
            confidence = "Low"

        signals = Signals(doc_brand_keyword=True, doc_official_domain=bool(found_domains),
                          doc_sensitive_pattern=bool(patterns), doc_many_emails=len(emails) >= MANY_EMAILS)
        file_sha = sha256(data) if data else None
        details = {
            "Document Name": name,
            "File Type": ftype,
            "URL": url,
            "Brand Match": brand_hits,
            "Exposure Confidence": confidence,
            "Sensitive Patterns": patterns,
            "Emails Found": len(emails),
            "Brand Emails": brand_emails[:20],
            "Domains Found": found_domains,
            "SHA256": file_sha,
            "Discovery Source": r.get("source", "search-engine").replace("-", " ").title(),
            "Hosted On Official Domain": host_official,
            "Accessible Without Login": accessible,
            "Size (bytes)": len(data) if data else None,
        }
        evidence = [EvidenceItem("metadata", meta={"search_title": r.get("title"), "snippet": r.get("snippet"),
                                                   "url": url, "http_status": resp.status if resp else None,
                                                   "text_excerpt": text[:1500]})]
        if data:
            evidence.append(EvidenceItem("file", data=data, content_type=resp.content_type or None, name=name,
                                         meta={"url": url, "sha256": file_sha, "type": ftype}))
        return Detection(entity_key=url, title=f"Exposed {ftype} document: {name}", signals=signals, details=details,
                       source_url=url, evidence=evidence,
                       analysed=accessible and confidence != "Low")  # D-33: not downloadable / weak = Candidate
