"""Turn a parsed email into Signals + output fields + evidence (spec §4). Deterministic and explainable."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import structlog

from app.core.evidence import EvidenceItem
from app.core.scoring import Signals
from app.core.similarity import best_similarity, registered_domain
from app.modules.base import BrandContext
from app.modules.email import engines, intel
from app.modules.email.attachments import analyse_attachment
from app.modules.email.auth import authenticate
from app.modules.email.model import ParsedEmail
from app.modules.pagecheck import PHISHING_KEYWORDS

log = structlog.get_logger(__name__)

URGENCY_TERMS = ["urgent", "immediately", "within 24 hours", "suspended", "locked", "expire", "verify now",
                 "action required", "final notice", "confirm your", "update your", "unusual activity",
                 "unauthorized", "limited", "restricted"]
MAX_LIVE_PAGE_CHECKS = 5
YOUNG_DOMAIN_DAYS = 30


@dataclass
class EmailAnalysis:
    signals: Signals
    details: dict
    indicators: list[dict] = field(default_factory=list)
    evidence: list[EvidenceItem] = field(default_factory=list)
    not_checked: list[dict] = field(default_factory=list)
    verdict_summary: str = ""
    related_domains: list[str] = field(default_factory=list)


def _domain_age_days(domain: str) -> int | None:
    from datetime import UTC, datetime

    from app.modules.domains.infra import LiveInfra

    try:
        whois = LiveInfra().whois(domain)
        created = whois.get("created")
        if not created:
            return None
        dt = datetime.fromisoformat(str(created).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return (datetime.now(UTC) - dt).days
    except Exception:  # noqa: BLE001
        return None


def _live_page_phishing(urls: list[str], ctx: BrandContext) -> list[dict]:
    """Run the first few URLs through the existing website pipeline; return those that are Suspected Phishing."""
    from app.core.browser import capture
    from app.modules.pagecheck import analyse as analyse_page

    out = []
    for url in urls[:MAX_LIVE_PAGE_CHECKS]:
        try:
            cap = capture(url, collect_images=True)
        except Exception:  # noqa: BLE001 - unreachable link is normal
            continue
        if cap.status is None:
            continue
        facts = analyse_page(cap, ctx)
        if facts.login_payment or facts.favicon_match or facts.logo_score >= 85:
            out.append({"url": cap.final_url, "keywords": facts.keywords_found,
                        "logo_score": facts.logo_score, "screenshot": cap.screenshot})
    return out


def _language_flags(text: str) -> list[str]:
    low = text.lower()
    flags = [k for k in PHISHING_KEYWORDS if re.search(rf"(?<![a-z]){re.escape(k)}(?![a-z])", low)]
    flags += [t for t in URGENCY_TERMS if t in low]
    return sorted(set(flags))


def analyse(parsed: ParsedEmail, raw: bytes, ctx: BrandContext) -> EmailAnalysis:
    not_checked: list[dict] = []
    indicators: list[dict] = []
    evidence: list[EvidenceItem] = [
        EvidenceItem("metadata", meta={"from": parsed.from_addr, "reply_to": parsed.reply_to,
                                       "return_path": parsed.return_path, "subject": parsed.subject,
                                       "sender_ip": parsed.sender_ip, "message_id": parsed.message_id,
                                       "warnings": parsed.warnings})]

    auth = authenticate(parsed, raw)
    # The receiver's Authentication-Results is authoritative for what happened in transit; our own DMARC
    # evaluation is the cross-check used when the header is silent.
    dmarc_verdict = auth["header"].get("dmarc") or auth["dmarc"]["result"]
    official_sender = (parsed.from_domain in ctx.official_domains and dmarc_verdict == "pass")

    # ---- URLs: reputation + corroboration + live-page analysis
    url_values = [u.url for u in parsed.urls]
    best_sources = 0
    malicious_urls: list[str] = []
    for url in url_values:
        verdicts = intel.url_reputation(url)
        for v in verdicts:
            if v.status == "not_checked":
                not_checked.append({"tool": v.tool, "target": url, "status": "not_checked"})
        sources = intel.corroborated(verdicts)
        indicators.append({"kind": "url", "value": url,
                           "verdicts": [v.as_dict() for v in verdicts], "malicious_sources": sources})
        if sources:
            malicious_urls.append(url)
        best_sources = max(best_sources, sources)

    live_hits = _live_page_phishing(url_values, ctx)
    if live_hits:
        best_sources += 1  # our own pipeline is one independent source
        for hit in live_hits:
            if hit.get("screenshot"):
                evidence.append(EvidenceItem("screenshot", data=hit["screenshot"], content_type="image/png",
                                             meta={"url": hit["url"]}))

    # ---- attachments
    attachment_reports = [analyse_attachment(a) for a in parsed.attachments]
    for a, rep in zip(parsed.attachments, attachment_reports, strict=True):
        indicators.append({"kind": "attachment", "value": a.name, "verdicts": rep["verdicts"],
                           "malicious_sources": int(rep["malware"])})
        for v in rep["verdicts"]:
            if v["status"] == "not_checked":
                not_checked.append({"tool": v["tool"], "target": a.name, "status": "not_checked"})
        evidence.append(EvidenceItem("file", data=a.data, content_type=a.content_type, name=a.name,
                                     meta={"sha256": a.sha256, "analysis": rep,
                                           "warning": "Untrusted attachment. Do not open."}))
    malware_attachment = any(r["malware"] for r in attachment_reports)
    suspicious_attachment = any(r["suspicious"] and not r["malware"] for r in attachment_reports)

    # ---- sender / look-alike / impersonation
    full_text = f"{parsed.subject}\n{parsed.text}\n{parsed.html}"
    link_domains = {registered_domain(u) for u in url_values}
    sender_domains = {d for d in (parsed.from_domain, _dom(parsed.reply_to), _dom(parsed.return_path)) if d}
    candidate_domains = (sender_domains | link_domains) - set(ctx.official_domains)
    related = sorted(d for d in candidate_domains if d)
    lookalike = not official_sender and any(
        best_similarity(registered_domain(d), ctx.labels)[0] > 80 for d in candidate_domains)

    rel = ctx.relevance(full_text)
    brand_impersonation = (not official_sender) and rel.relevant

    reply_to_mismatch = bool(parsed.reply_to and parsed.from_domain
                             and _dom(parsed.reply_to) != parsed.from_domain
                             and _dom(parsed.reply_to) not in ctx.official_domains)

    auth_fail_brand_from = (parsed.from_domain in ctx.official_domains
                            and dmarc_verdict == "fail")

    # ---- sender IP, domain age, engines
    rspamd = engines.rspamd_check(raw) if raw else engines.rspamd_check(b"")
    if rspamd.status == "not_checked":
        not_checked.append({"tool": "rspamd", "target": "message", "status": "not_checked"})
    ip_verdict = intel.abuseipdb_check(parsed.sender_ip) if parsed.sender_ip else None
    if ip_verdict and ip_verdict.status == "not_checked":
        not_checked.append({"tool": "abuseipdb", "target": parsed.sender_ip, "status": "not_checked"})
    youngest = None
    for d in candidate_domains:
        age = _domain_age_days(d)
        if age is not None:
            youngest = age if youngest is None else min(youngest, age)

    signals = Signals(
        known_malicious_url=best_sources >= 2,
        single_source_url_hit=best_sources == 1,
        malware_attachment=malware_attachment,
        suspicious_attachment=suspicious_attachment,
        auth_fail_brand_from=auth_fail_brand_from,
        lookalike_sender=lookalike,
        brand_impersonation=brand_impersonation,
        reply_to_mismatch=reply_to_mismatch,
        credential_or_payment_language=bool(_language_flags(full_text)),
        young_domain=youngest is not None and youngest < YOUNG_DOMAIN_DAYS,
        bad_sender_ip=bool(ip_verdict and ip_verdict.malicious),
        rspamd_phish=rspamd.malicious,
        live_phishing_page=bool(live_hits),
    )

    details = {
        "Subject": parsed.subject, "From": parsed.from_addr, "Sender Domain": parsed.from_domain,
        "Reply-To": parsed.reply_to, "Return-Path": parsed.return_path, "Sender IP": parsed.sender_ip,
        "SPF": auth["header"].get("spf"), "DKIM": auth["header"].get("dkim"),
        "DMARC": f'{auth["header"].get("dmarc")} (independent: {auth["dmarc"]["result"]})',
        "Rspamd": rspamd.details.get("action") if rspamd.status == "ok" else rspamd.status,
        "URLs": len(url_values), "Malicious URLs": malicious_urls,
        "Attachments": len(parsed.attachments),
        "Malicious Attachments": [r["name"] for r in attachment_reports if r["malware"] or r["suspicious"]],
        "Brand Match": rel.terms_used, "Look-alike Domains": [d for d in related if d not in ctx.official_domains],
        "Language Flags": _language_flags(full_text)[:12],
        "Not Checked": sorted({n["tool"] for n in not_checked}),
        "Official Sender": official_sender,
    }
    summary = ("Likely phishing" if (signals.known_malicious_url or malware_attachment or auth_fail_brand_from)
               else "Suspicious" if (lookalike or brand_impersonation or signals.single_source_url_hit)
               else "Low risk")
    return EmailAnalysis(signals=signals, details=details, indicators=indicators, evidence=evidence,
                         not_checked=not_checked, verdict_summary=summary, related_domains=related)


def _dom(addr: str | None) -> str | None:
    return addr.split("@")[-1].lower() if addr and "@" in addr else None
