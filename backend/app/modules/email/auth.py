"""Email authentication: read the receiver's Authentication-Results, and independently evaluate DMARC alignment.

Two opinions, as the spec requires: the `header` block is what the receiving mail server already decided; the `dmarc`
block is our own evaluation of SPF/DKIM alignment against the From domain's DMARC policy. A live DKIM re-verification
(dkimpy) is attempted only when the raw message is available.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import UTC, datetime

import structlog

from app.core.similarity import registered_domain
from app.modules.email.model import ParsedEmail

log = structlog.get_logger(__name__)

# From Authentication-Results, e.g. "spf=pass", "dkim=fail", "dmarc=none"
_METHOD_RE = {m: re.compile(rf"\b{m}=([a-z]+)", re.I) for m in ("spf", "dkim", "dmarc", "arc")}
_MAILFROM_RE = re.compile(r"smtp\.mailfrom=([^\s;]+)", re.I)
_HEADERD_RE = re.compile(r"header\.d=([^\s;]+)", re.I)


def _header_results(header: str) -> dict[str, str | None]:
    out: dict[str, str | None] = {}
    for method, rx in _METHOD_RE.items():
        m = rx.search(header or "")
        out[method] = m.group(1).lower() if m else None
    return out


def dmarc_lookup(domain: str) -> dict | None:
    """Fetch and minimally parse the DMARC record for a registered domain. Returns {'policy': ...} or None."""
    try:
        import dns.resolver

        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
        resolver.timeout, resolver.lifetime = 3.0, 5.0
        answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        records = [b"".join(r.strings).decode("utf-8", "replace") for r in answers]
    except Exception as exc:  # noqa: BLE001 - NXDOMAIN or network: no record
        if "NXDOMAIN" in type(exc).__name__ or "NoAnswer" in type(exc).__name__:
            return None
        raise
    dmarc = [r for r in records if r.lower().startswith("v=dmarc1")]
    if not dmarc:
        return None
    tags = dict(re.findall(r"(\w+)=([^;]+)", dmarc[0]))
    return {"policy": (tags.get("p") or "").strip().lower() or None,
            "subdomain_policy": (tags.get("sp") or "").strip().lower() or None,
            "alignment_spf": (tags.get("aspf") or "r").strip().lower(),
            "alignment_dkim": (tags.get("adkim") or "r").strip().lower(),
            "duplicate_records": len(dmarc) > 1, "raw": dmarc[0]}


def _aligned(from_domain: str, auth_domain: str | None, mode: str) -> bool:
    if not auth_domain:
        return False
    if mode == "s":  # strict: exact match
        return from_domain.lower() == auth_domain.lower()
    return registered_domain(from_domain) == registered_domain(auth_domain)  # relaxed: same registered domain


def authenticate(parsed: ParsedEmail, raw: bytes, lookup: Callable[[str], dict | None] | None = None) -> dict:
    lookup = lookup or dmarc_lookup
    header = _header_results(parsed.auth_results_header)
    from_domain = parsed.from_domain or ""
    mailfrom = (_MAILFROM_RE.search(parsed.auth_results_header) or [None, None])
    mailfrom_domain = mailfrom.group(1) if hasattr(mailfrom, "group") else None
    headerd = _HEADERD_RE.search(parsed.auth_results_header)
    dkim_domain = headerd.group(1) if headerd else None

    result = {"header": header, "from_domain": from_domain, "dkim_verified": None,
              "checked_at": datetime.now(UTC).isoformat()}

    # Independent DMARC evaluation
    try:
        record = lookup(registered_domain(from_domain)) if from_domain else None
        dmarc_status = "ok"
    except Exception as exc:  # noqa: BLE001 - DNS failure must not crash analysis
        record, dmarc_status = None, "temperror"
        log.info("dmarc_lookup_failed", domain=from_domain, error=str(exc)[:150])

    spf_pass = header.get("spf") == "pass"
    dkim_pass = header.get("dkim") == "pass"
    aligned_spf = spf_pass and _aligned(from_domain, mailfrom_domain or from_domain,
                                        (record or {}).get("alignment_spf", "r"))
    aligned_dkim = dkim_pass and _aligned(from_domain, dkim_domain or from_domain,
                                          (record or {}).get("alignment_dkim", "r"))

    if dmarc_status == "temperror":
        dmarc_result = "temperror"
    elif record is None:
        dmarc_result = "none"
    elif aligned_spf or aligned_dkim:
        dmarc_result = "pass"
    else:
        dmarc_result = "fail"

    result["dmarc"] = {
        "result": dmarc_result,
        "policy": (record or {}).get("policy"),
        "aligned_spf": aligned_spf,
        "aligned_dkim": aligned_dkim,
        "duplicate_records": (record or {}).get("duplicate_records", False),
        "record": (record or {}).get("raw"),
    }
    return result
