"""CSV and PDF export of the filtered alert list (DSH-18, DSH-19) and of filtered findings (Social Media page)."""

import csv
import html
import io
from datetime import UTC, datetime
from itertools import zip_longest

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response, StreamingResponse
from sqlalchemy.orm import Session, selectinload

from app.api.alerts import SORTS, AlertFilters
from app.api.findings import FindingFilters
from app.core.security import current_user
from app.db.models import Alert, Finding, ModuleName, RiskLevel, User
from app.db.session import get_db
from app.modules.registry import MODULE_LABELS, OUTPUT_FIELDS

router = APIRouter(prefix="/exports", tags=["exports"])

MAX_EXPORT_ROWS = 10_000
BASE_COLUMNS = ["Alert ID", "Finding ID", "Scan ID", "Brand", "Module", "Title", "Risk Level", "Score", "Decision",
                "Alert Trigger", "Alert Reason", "Alerted (UTC)", "Suspected Phishing", "First Seen (UTC)",
                "Last Seen (UTC)", "Source URL"]


def _rows(db: Session, filters: AlertFilters) -> list[tuple[Alert, Finding]]:
    stmt = filters.select().options(selectinload(Finding.brand))
    return [tuple(r) for r in db.execute(stmt.order_by(SORTS[filters.sort]).limit(MAX_EXPORT_ROWS)).all()]


def _detail_columns(alerts: list[tuple[Alert, Finding]]) -> list[str]:
    cols: list[str] = []
    for _, a in alerts:
        for label in OUTPUT_FIELDS.get(a.module, []):
            if label not in cols:
                cols.append(label)
    return cols


def _fmt(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, list):
        return "; ".join(_fmt(v) for v in value)
    if isinstance(value, dict):
        return "; ".join(f"{k}: {_fmt(v)}" for k, v in value.items())
    return str(value)


def _base(alert: Alert, a: Finding) -> list[str]:
    return [str(alert.id), str(a.id), str(alert.scan_id or ""), a.brand.name, a.module.value, a.title,
            a.risk_level.value, str(a.score), a.decision.value, alert.trigger, alert.reason,
            alert.created_at.astimezone(UTC).strftime("%Y-%m-%d %H:%M"), "Yes" if a.suspected_phishing else "No", a.first_seen.astimezone(UTC).strftime("%Y-%m-%d %H:%M"),
            a.last_seen.astimezone(UTC).strftime("%Y-%m-%d %H:%M"), a.source_url or ""]


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%d-%H%M")


SIMPLE_COLUMNS = ["Brand", "Module", "Title", "Risk Level", "Score", "Status", "Alerted (UTC)", "Link"]


def _link(f: Finding) -> str:
    """Where the finding lives: source URL, else the post/profile URL, else the look-alike domain."""
    for v in (f.source_url, f.details.get("URL"), f.details.get("Profile URL")):
        if isinstance(v, str) and v.strip():
            return v.strip()
    domain = f.details.get("Domain")
    return f"https://{domain}" if isinstance(domain, str) and domain.strip() else ""


def _simple(alert: Alert, a: Finding) -> list[str]:
    """Simple format: the core facts only — no IDs, no reason text, no module-specific detail fields."""
    return [a.brand.name, MODULE_LABELS.get(a.module, a.module.value), a.title, a.risk_level.value, str(a.score),
            a.decision.value, alert.created_at.astimezone(UTC).strftime("%Y-%m-%d %H:%M"), _link(a)]


@router.get("/alerts.csv")
def export_csv(filters: AlertFilters = Depends(), simple: bool = False, _: User = Depends(current_user),
               db: Session = Depends(get_db)):
    alerts = _rows(db, filters)
    buf = io.StringIO()
    w = csv.writer(buf)
    if simple:
        w.writerow(SIMPLE_COLUMNS)
        w.writerows(_simple(alert, a) for alert, a in alerts)
    else:
        extra = _detail_columns(alerts)
        w.writerow(BASE_COLUMNS + extra)
        for alert, a in alerts:
            w.writerow(_base(alert, a) + [_fmt(a.details.get(c)) for c in extra])
    data = "﻿" + buf.getvalue()  # BOM so Excel opens UTF-8 correctly
    name = f"alerts-simple-{_stamp()}" if simple else f"alerts-{_stamp()}"
    return StreamingResponse(iter([data]), media_type="text/csv; charset=utf-8",
                             headers={"Content-Disposition": f'attachment; filename="{name}.csv"'})


def _pdf_html(alerts: list[tuple[Alert, Finding]], filters: AlertFilters, simple: bool = False) -> str:
    e = html.escape
    applied = []
    for label, val in [("Modules", filters.module), ("Risk", filters.risk_level), ("Status", filters.status),
                       ("From", filters.date_from), ("To", filters.date_to), ("Search", filters.q)]:
        if val:
            applied.append(f"{label}: {', '.join(getattr(v, 'value', str(v)) for v in val) if isinstance(val, list) else val}")
    rows = []
    for alert, a in alerts:
        if simple:
            link = f"<div class='f'>{e(_link(a))}</div>" if _link(a) else ""
            rows.append(
                f"<tr class='r-{a.risk_level.value.lower()}'><td><span class='pill'>{e(a.risk_level.value)}</span>"
                f"<br>{a.score}</td><td>{e(MODULE_LABELS.get(a.module, a.module.value))}</td>"
                f"<td><b>{e(a.title)}</b>{link}</td><td>{e(a.brand.name)}</td><td>{e(a.decision.value)}</td>"
                f"<td>{alert.created_at.astimezone(UTC):%Y-%m-%d %H:%M}</td></tr>"
            )
            continue
        fields = "".join(
            f"<div><b>{e(k)}:</b> {e(_fmt(a.details.get(k)))}</div>" for k in OUTPUT_FIELDS.get(a.module, [])
            if k not in ("Screenshot",) and a.details.get(k) not in (None, "", [])
        )
        rows.append(
            f"<tr class='r-{a.risk_level.value.lower()}'><td><span class='pill'>{e(a.risk_level.value)}</span>"
            f"<br>{a.score}</td><td>{e(a.module.value)}</td><td><b>{e(a.title)}</b><div class='f'>{fields}</div></td>"
            f"<td>{e(a.brand.name)}</td><td>{e(a.decision.value)}<div class='f'>{e(alert.reason)}</div></td>"
            f"<td>{a.first_seen.astimezone(UTC):%Y-%m-%d}</td></tr>"
        )
    return f"""<!doctype html><html><head><meta charset="utf-8"><style>
@page {{ size: A4 landscape; margin: 14mm; @bottom-right {{ content: "Page " counter(page) " of " counter(pages); font-size: 8pt; color:#666 }} }}
body {{ font-family: "DejaVu Sans", Arial, sans-serif; font-size: 8.5pt; color:#1b1f24 }}
h1 {{ font-size: 15pt; margin: 0 }} .sub {{ color:#555; margin: 2px 0 10px }}
table {{ width:100%; border-collapse: collapse }} th {{ text-align:left; background:#f1f3f5; padding:5px; font-size:8pt }}
td {{ padding:5px; border-top:1px solid #e3e6ea; vertical-align: top; overflow-wrap: anywhere }} .f {{ color:#444; margin-top:2px }}
.pill {{ font-weight:bold }} .r-critical .pill {{ color:#b00020 }} .r-high .pill {{ color:#c2410c }}
.r-medium .pill {{ color:#a16207 }} .r-low .pill {{ color:#15803d }}
</style></head><body>
<h1>Beyond Cloud Brand Intelligence — Alert Report</h1>
<div class="sub">Generated {datetime.now(UTC):%Y-%m-%d %H:%M} UTC · {len(alerts)} alerts{' · ' + e(' · '.join(applied)) if applied else ''}</div>
<table><thead><tr>{
    '<th>Risk</th><th>Module</th><th>Finding / link</th><th>Brand</th><th>Status</th><th>Alerted (UTC)</th>' if simple else
    '<th>Risk</th><th>Module</th><th>Finding</th><th>Brand</th><th>Decision / why alerted</th><th>First seen</th>'
}</tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan=6>No alerts match these filters.</td></tr>'}</tbody></table></body></html>"""


def _render_pdf(doc: str) -> bytes:
    try:
        from weasyprint import HTML  # needs Pango; available in the Docker image
    except OSError as exc:
        raise HTTPException(503, "PDF export needs the system libraries in the Docker image") from exc
    return HTML(string=doc).write_pdf()


# ------------------------------------------------------------------ findings (e.g. the Social Media page)
FINDING_COLUMNS = ["Finding ID", "Brand", "Module", "Title", "Risk Level", "Score", "Stage", "Decision",
                   "First Seen (UTC)", "Last Seen (UTC)", "Last Alerted (UTC)", "Source URL"]
SOCIAL_MODULES = {ModuleName.social, ModuleName.social_media}


def _finding_rows(db: Session, filters: FindingFilters) -> list[Finding]:
    stmt = filters.select().options(selectinload(Finding.brand))
    return list(db.scalars(stmt.order_by(*filters.order()).limit(MAX_EXPORT_ROWS)).all())


def _finding_cols(findings: list[Finding]) -> list[str]:
    cols: list[str] = []
    for f in findings:
        for label in OUTPUT_FIELDS.get(f.module, []):
            if label not in cols and label not in ("Screenshot", "Risk Level"):
                cols.append(label)
    return cols


def _utc(dt) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%d %H:%M") if dt else ""


def _finding_base(f: Finding) -> list[str]:
    return [str(f.id), f.brand.name, f.module.value, f.title, f.risk_level.value, str(f.score), f.stage.value,
            f.decision.value, _utc(f.first_seen), _utc(f.last_seen), _utc(f.last_alert_at), f.source_url or ""]


def _findings_name(filters: FindingFilters) -> tuple[str, str]:
    """(filename prefix, report title) — social-only filters get a Social Media report."""
    if filters.module and set(filters.module) <= SOCIAL_MODULES:
        return "social-media", "Social Media Report"
    return "findings", "Findings Report"


LEVELS_DESC = [RiskLevel.critical, RiskLevel.high, RiskLevel.medium, RiskLevel.low]


def _links(findings: list[Finding]) -> dict[RiskLevel, list[str]]:
    """Links grouped by criticality (Critical first). A link seen more than once is listed once, under its
    highest risk; order within a group follows the export sort."""
    best: dict[str, RiskLevel] = {}
    for f in findings:
        link = _link(f)
        if link and (link not in best or LEVELS_DESC.index(f.risk_level) < LEVELS_DESC.index(best[link])):
            best[link] = f.risk_level
    return {level: [link for link, lv in best.items() if lv == level] for level in LEVELS_DESC}


@router.get("/findings.csv")
def export_findings_csv(filters: FindingFilters = Depends(), links_only: bool = False,
                        _: User = Depends(current_user), db: Session = Depends(get_db)):
    findings = _finding_rows(db, filters)
    buf = io.StringIO()
    w = csv.writer(buf)
    if links_only:
        # one column per risk level, side by side, so each level's links stay separate
        groups = {level: links for level, links in _links(findings).items() if links}
        w.writerow([f"{level.value} ({len(links)})" for level, links in groups.items()] or ["No links"])
        w.writerows(zip_longest(*groups.values(), fillvalue=""))
    else:
        extra = _finding_cols(findings)
        w.writerow(FINDING_COLUMNS + [f"Content {c}" if c in FINDING_COLUMNS else c for c in extra])
        for f in findings:
            w.writerow(_finding_base(f) + [_fmt(f.details.get(c)) for c in extra])
    prefix, _title = _findings_name(filters)
    prefix += "-links" if links_only else ""
    return StreamingResponse(iter(["﻿" + buf.getvalue()]), media_type="text/csv; charset=utf-8",
                             headers={"Content-Disposition": f'attachment; filename="{prefix}-{_stamp()}.csv"'})


def _clip(text: str, limit: int = 300) -> str:
    """Long excerpts and bios are kept whole in the CSV; the PDF stays readable (and fast to render)."""
    return text if len(text) <= limit else text[:limit].rstrip() + "…"


def _applied(filters: FindingFilters) -> list[str]:
    applied = []
    for label, val in [("Platform", filters.platform), ("Type", filters.content_type), ("Stage", filters.stage),
                       ("Decision", filters.decision), ("Risk", filters.risk_level), ("Search", filters.q)]:
        if val:
            applied.append(f"{label}: {', '.join(getattr(v, 'value', str(v)) for v in val) if isinstance(val, list) else val}")
    return applied


LEVEL_NOTES = {
    RiskLevel.critical: "fake contact details or scam wording",
    RiskLevel.high: "impersonation accounts (look-alike name or logo)",
    RiskLevel.medium: "brand misuse without scam signs (logo, ads, look-alike accounts)",
    RiskLevel.low: "informative mentions",
}


def _links_pdf_html(groups: dict[RiskLevel, list[str]], filters: FindingFilters) -> str:
    e = html.escape
    applied = _applied(filters)
    _prefix, title = _findings_name(filters)
    total = sum(len(v) for v in groups.values())
    summary, sections = [], []
    for level, links in groups.items():
        if not links:
            continue
        cls = f"r-{level.value.lower()}"
        summary.append(f"<tr><td class='{cls}'><b>{e(level.value)}</b></td><td class='n'>{len(links)}</td>"
                       f"<td>{e(LEVEL_NOTES.get(level, ''))}</td></tr>")
        items = "".join(f"<li><a href='{e(link)}'>{e(link)}</a></li>" for link in links)
        note = f"<div class='note'>{e(LEVEL_NOTES[level])}</div>" if level in LEVEL_NOTES else ""
        sections.append(f"<section class='{cls}'><h2><span class='lv'>{e(level.value)} risk</span> · {len(links)} link{'' if len(links) == 1 else 's'}"
                        f"</h2>{note}<ol>{items}</ol></section>")
    overview = (f"<table class='sum'><thead><tr><th>Risk</th><th>Links</th><th>What it means</th></tr></thead>"
                f"<tbody>{''.join(summary)}</tbody></table>") if summary else "<p>Nothing matches these filters.</p>"
    return f"""<!doctype html><html><head><meta charset="utf-8"><style>
@page {{ size: A4; margin: 16mm 14mm 14mm;
  @top-left {{ content: string(level, first-except); font-size: 9pt; font-weight: bold; color:#555 }}
  @bottom-right {{ content: "Page " counter(page) " of " counter(pages); font-size: 8pt; color:#666 }} }}
body {{ font-family: "DejaVu Sans", Arial, sans-serif; font-size: 9pt; color:#1b1f24 }}
h1 {{ font-size: 15pt; margin: 0 }} .sub {{ color:#555; margin: 2px 0 12px }}
table.sum {{ border-collapse: collapse; margin-bottom: 4px }} .sum th {{ text-align:left; background:#f1f3f5; padding:5px 10px }}
.sum td {{ padding:5px 10px; border-top:1px solid #e3e6ea }} .sum .n {{ text-align:right; font-weight:bold }}
section {{ break-before: page }}
h2 {{ font-size: 13pt; margin: 0 0 2px; padding: 6px 10px }}
h2 .lv {{ string-set: level content() " links (continued)" }}
section h2 {{ color: #fff }} section.r-critical h2 {{ background:#b00020 }} section.r-high h2 {{ background:#c2410c }}
section.r-medium h2 {{ background:#a16207 }} section.r-low h2 {{ background:#15803d }}
.note {{ color:#555; margin: 0 0 8px; padding-left: 10px }}
.r-critical {{ color:#b00020 }} .r-high {{ color:#c2410c }} .r-medium {{ color:#a16207 }} .r-low {{ color:#15803d }}
ol {{ color:#1b1f24 }} li {{ padding: 2px 0; overflow-wrap: anywhere }} a {{ color:#1b1f24; text-decoration: none }}
</style></head><body>
<h1>Beyond Cloud Brand Intelligence — {e(title)} (links by risk)</h1>
<div class="sub">Generated {datetime.now(UTC):%Y-%m-%d %H:%M} UTC · {total} links{' · ' + e(' · '.join(applied)) if applied else ''}</div>
{overview}{''.join(sections)}</body></html>"""


def _findings_pdf_html(findings: list[Finding], filters: FindingFilters) -> str:
    e = html.escape
    applied = _applied(filters)
    rows = []
    for f in findings:
        fields = "".join(
            f"<div><b>{e(k)}:</b> {e(_clip(_fmt(f.details.get(k))))}</div>" for k in OUTPUT_FIELDS.get(f.module, [])
            if k not in ("Screenshot", "Risk Level") and f.details.get(k) not in (None, "", [])
        )
        link = f"<div class='f'>{e(f.source_url)}</div>" if f.source_url else ""
        rows.append(
            f"<tr class='r-{f.risk_level.value.lower()}'><td><span class='pill'>{e(f.risk_level.value)}</span>"
            f"<br>{f.score}</td><td>{e(f.details.get('Platform') or f.module.value)}</td>"
            f"<td><b>{e(f.title)}</b>{link}<div class='f'>{fields}</div></td><td>{e(f.brand.name)}</td>"
            f"<td>{e(f.stage.value)}<br>{e(f.decision.value)}</td><td>{f.first_seen.astimezone(UTC):%Y-%m-%d}</td></tr>"
        )
    _prefix, title = _findings_name(filters)
    return f"""<!doctype html><html><head><meta charset="utf-8"><style>
@page {{ size: A4 landscape; margin: 14mm; @bottom-right {{ content: "Page " counter(page) " of " counter(pages); font-size: 8pt; color:#666 }} }}
body {{ font-family: "DejaVu Sans", Arial, sans-serif; font-size: 8.5pt; color:#1b1f24 }}
h1 {{ font-size: 15pt; margin: 0 }} .sub {{ color:#555; margin: 2px 0 10px }}
table {{ width:100%; border-collapse: collapse }} th {{ text-align:left; background:#f1f3f5; padding:5px; font-size:8pt }}
td {{ padding:5px; border-top:1px solid #e3e6ea; vertical-align: top; overflow-wrap: anywhere }} .f {{ color:#444; margin-top:2px }}
.pill {{ font-weight:bold }} .r-critical .pill {{ color:#b00020 }} .r-high .pill {{ color:#c2410c }}
.r-medium .pill {{ color:#a16207 }} .r-low .pill {{ color:#15803d }}
</style></head><body>
<h1>Beyond Cloud Brand Intelligence — {e(title)}</h1>
<div class="sub">Generated {datetime.now(UTC):%Y-%m-%d %H:%M} UTC · {len(findings)} items{' · ' + e(' · '.join(applied)) if applied else ''}</div>
<table><thead><tr><th>Risk</th><th>Platform</th><th>Finding</th><th>Brand</th><th>Stage / decision</th><th>First seen</th></tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan=6>Nothing matches these filters.</td></tr>'}</tbody></table></body></html>"""


@router.get("/findings.pdf")
def export_findings_pdf(filters: FindingFilters = Depends(), links_only: bool = False,
                        _: User = Depends(current_user), db: Session = Depends(get_db)):
    findings = _finding_rows(db, filters)
    doc = _links_pdf_html(_links(findings), filters) if links_only else _findings_pdf_html(findings, filters)
    pdf = _render_pdf(doc)
    prefix, _title = _findings_name(filters)
    prefix += "-links" if links_only else ""
    return Response(pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{prefix}-{_stamp()}.pdf"'})


@router.get("/alerts.pdf")
def export_pdf(filters: AlertFilters = Depends(), simple: bool = False, _: User = Depends(current_user),
               db: Session = Depends(get_db)):
    alerts = _rows(db, filters)
    pdf = _render_pdf(_pdf_html(alerts, filters, simple))
    name = f"alerts-simple-{_stamp()}" if simple else f"alerts-{_stamp()}"
    return Response(pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{name}.pdf"'})
