"""Capability B: email security posture of the brand's own domains (SPF, DMARC, DKIM, MTA-STS).

One finding per official domain. Checks the real published records and reports what lets an attacker spoof the
domain: no/duplicate/invalid DMARC, p=none, missing or permissive SPF, no DKIM, no MTA-STS.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator

import structlog
from sqlalchemy.orm import Session

from app.core.evidence import EvidenceItem
from app.core.scoring import Signals
from app.db.models import ModuleName
from app.modules.base import BrandContext, Detection, ScanReport

log = structlog.get_logger(__name__)

def domain_can_send(txt_records: list[str]) -> bool:
    """A domain that publishes an SPF record is configured to send email (look-alike email-readiness, EML-17)."""
    return any(r.lower().strip().startswith("v=spf1") for r in txt_records)


COMMON_DKIM_SELECTORS = ["default", "selector1", "selector2", "google", "k1", "s1", "s2", "dkim", "mail",
                         "smtp", "mandrill", "mailgun", "zoho", "amazonses"]


class DnsUnknown(Exception):
    """The DNS question could not be answered (timeout / SERVFAIL) — never read as "no record" (D-31)."""


def _resolve_txt(domain: str, rtype: str = "TXT") -> list[str]:
    import dns.exception
    import dns.name
    import dns.resolver

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
    resolver.timeout, resolver.lifetime = 3.0, 6.0
    try:
        answers = resolver.resolve(domain, rtype)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.name.LabelTooLong, dns.name.EmptyLabel, ValueError):
        return []  # a definitive "no such record"
    except dns.exception.DNSException as exc:  # Timeout, NoNameservers (SERVFAIL), …
        raise DnsUnknown(f"{rtype} {domain}: {type(exc).__name__}") from exc
    return [b"".join(r.strings).decode("utf-8", "replace") if hasattr(r, "strings") else r.to_text().strip('"')
            for r in answers]


def _dkim_selector_exists(domain: str, selector: str) -> bool:
    return bool(_resolve_txt(f"{selector}._domainkey.{domain}"))


def evaluate(domain: str, ctx: BrandContext, dns: Callable[[str, str], list[str]] = _resolve_txt,
             dkim_selectors: Callable[[str, str], bool] = _dkim_selector_exists) -> Detection | None:
    all_dmarc_txt = dns(f"_dmarc.{domain}", "TXT")
    dmarc_records = [r for r in all_dmarc_txt if r.lower().replace(" ", "").startswith("v=dmarc1")]
    malformed_dmarc = [r for r in all_dmarc_txt if "v=dmarc1" in r.lower().replace(" ", "")
                       and not r.lower().replace(" ", "").startswith("v=dmarc1")]
    spf_records = [r for r in dns(domain, "TXT") if r.lower().startswith("v=spf1")]
    mta_sts = bool(dns(f"_mta-sts.{domain}", "TXT"))

    dmarc_issues: list[str] = []
    spf_issues: list[str] = []
    signals_kw: dict[str, bool] = {}

    # DMARC
    if not dmarc_records:
        dmarc_issues.append("no DMARC record — anyone can spoof this domain")
        signals_kw["posture_dmarc_missing"] = True
        policy = None
    elif len(dmarc_records) > 1:
        dmarc_issues.append(f"{len(dmarc_records)} DMARC records found — receivers treat DMARC as absent")
        signals_kw["posture_dmarc_missing"] = True
        policy = None
    else:
        if malformed_dmarc:
            dmarc_issues.append(f"a malformed DMARC record is also published ({malformed_dmarc[0][:40]}...) — fix or remove it")
        tags = dict(part.strip().split("=", 1) for part in dmarc_records[0].split(";")
                    if "=" in part and part.strip())
        policy = (tags.get("p") or "").strip().lower() or None
        if policy in (None, ""):
            dmarc_issues.append("DMARC record has no policy (p=) — not enforced")
            signals_kw["posture_dmarc_missing"] = True
        elif policy == "none":
            dmarc_issues.append("DMARC policy is p=none — spoofing is reported but not blocked")
            signals_kw["posture_dmarc_none"] = True

    # SPF
    if not spf_records:
        spf_issues.append("no SPF record")
        signals_kw["posture_spf_missing"] = True
    elif len(spf_records) > 1:
        spf_issues.append("multiple SPF records — SPF is invalid")
        signals_kw["posture_spf_missing"] = True
    else:
        spf = spf_records[0].lower()
        if "+all" in spf or spf.rstrip().endswith("all") and " all" in f" {spf}" and "+all" in spf:
            spf_issues.append("SPF ends with +all — any server may send as this domain")
            signals_kw["posture_spf_missing"] = True
        elif "~all" in spf:
            spf_issues.append("SPF uses ~all (softfail) — spoofed mail is accepted, only marked")
            signals_kw["posture_spf_softfail"] = True

    # DKIM
    found_selectors = [s for s in COMMON_DKIM_SELECTORS if dkim_selectors(domain, s)]
    if not found_selectors:
        signals_kw["posture_dkim_missing"] = True

    # MTA-STS
    if not mta_sts:
        signals_kw["posture_mta_sts_missing"] = True

    if not signals_kw:
        return None  # well configured

    signals = Signals(**signals_kw)
    summary = "; ".join(dmarc_issues + spf_issues) or "minor email-security gaps"
    details = {
        "Domain": domain,
        "DMARC Record": dmarc_records[0] if len(dmarc_records) == 1
        else (f"{len(dmarc_records)} records" if dmarc_records else None),
        "DMARC Policy": policy,
        "DMARC Issues": dmarc_issues,
        "SPF Record": spf_records[0] if len(spf_records) == 1
        else (f"{len(spf_records)} records" if spf_records else None),
        "SPF Issues": spf_issues,
        "DKIM Selectors Found": found_selectors,
        "MTA-STS": mta_sts,
        "Summary": summary,
    }
    evidence = [EvidenceItem("metadata", meta={"dmarc": dmarc_records, "spf": spf_records,
                                               "dkim_selectors": found_selectors, "mta_sts": mta_sts})]
    return Detection(entity_key=f"posture:{domain}", title=f"Email security gap: {domain}", signals=signals,
                   details=details, evidence=evidence, module=ModuleName.email_posture)


class PostureModule:
    name = ModuleName.email_posture

    def __init__(self) -> None:
        self.stats: dict = {}
        self.report = ScanReport()

    def run(self, ctx: BrandContext, db: Session) -> Iterator[Detection]:
        domains = list(dict.fromkeys(ctx.official_domains + ctx.email_domains))
        if not domains:
            self.report.skipped("DNS TXT lookups", "no official or email domains configured for this brand")
        self.stats["domains_checked"] = len(domains)
        flagged = 0
        for domain in domains:
            try:
                finding = evaluate(domain, ctx)
            except Exception as exc:  # noqa: BLE001
                self.report.failed("DNS TXT lookups", f"{domain}: {type(exc).__name__}: {exc}", failed=1)
                continue
            self.report.ok("DNS TXT lookups", domains=1)
            if finding is not None:
                flagged += 1
                yield finding
        self.stats["flagged"] = flagged
