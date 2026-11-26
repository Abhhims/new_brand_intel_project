"""Cross-module correlation (SP4, D-49): link findings that share a stable identifier in their own evidence.

Only exact values are linked, and only values that point to one operator: a certificate issued for the domain, an
APK signing key, the same file, the same scam phone / UPI / Telegram contact, the same private mail server, the
same developer e-mail or website, a look-alike domain that a phishing email links to. Shared hosting is NOT proof:
an IP address or a favicon is a *weak* link that is shown but never forms a campaign, and values shared by very
many findings (big mail providers, parking hosts, generic icons) are ignored. Campaigns are groups of findings
connected by strong links — "probably the same operator", never an attribution.
"""

from __future__ import annotations

import re
import uuid
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.similarity import registered_domain
from app.db.models import Finding, FindingIndicator, ModuleName

DOMAIN_MODULES = (ModuleName.typosquat, ModuleName.mx, ModuleName.phishing)

# kind: (label shown to analysts, strong?, largest group that still means "one operator")
KINDS: dict[str, tuple[str, bool, int]] = {
    "tls_cert": ("Same TLS certificate (issued for both domains)", True, 50),
    "apk_signer": ("Same APK signing certificate", True, 200),
    "file_sha256": ("Same file (SHA-256)", True, 200),
    "contact_phone": ("Same phone / WhatsApp number", True, 200),
    "contact_upi": ("Same UPI ID", True, 200),
    "contact_telegram": ("Same Telegram contact", True, 200),
    "mail_server": ("Mail handled by another look-alike domain", True, 50),
    "developer_email": ("Same app developer e-mail", True, 100),
    "developer_site": ("Same app developer website", True, 100),
    "domain": ("Same look-alike domain (linked from an email or seen as a domain finding)", True, 200),
    "ip": ("Same IP address (shared hosting is common: not proof)", False, 25),
    "favicon": ("Same favicon (not the official one; generic icons are common: not proof)", False, 25),
}

# Mail providers shared by unrelated customers: never a link
MAIL_PROVIDERS = frozenset({
    "google.com", "googlemail.com", "outlook.com", "hotmail.com", "office365.us", "zoho.com", "zohomail.com", "zoho.in",
    "zoho.eu", "mailgun.org", "sendgrid.net", "pphosted.com", "mimecast.com", "yandex.net", "yandex.ru",
    "yahoodns.net", "icloud.com", "secureserver.net", "hostinger.com", "titan.email", "privateemail.com",
    "registrar-servers.com", "mxrouting.net", "ovh.net", "ionos.com", "1and1.com", "kundenserver.de", "gandi.net",
    "messagingengine.com", "amazonaws.com", "emailsrvr.com", "mail.ru", "qq.com", "163.com", "hostgator.com",
    "bluehost.com", "websitewelcome.com", "cloudflare.net", "improvmx.com", "forwardemail.net", "namecheaphosting.com",
    "migadu.com", "protonmail.ch", "beget.com", "timeweb.ru", "netcore.co.in", "rediffmail.com", "hostingraja.in",
})
_FREE_MAIL = frozenset({"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "proton.me", "protonmail.com",
                        "icloud.com", "rediffmail.com", "yandex.com", "mail.ru", "aol.com", "gmx.com"})

SELF = "the look-alike domain itself"  # source of a domain finding's own domain indicator


@dataclass(frozen=True)
class Indicator:
    kind: str
    value: str
    source: str


def _phone(raw: str) -> str | None:
    digits = re.sub(r"\D", "", raw)
    return digits[-10:] if len(digits) >= 10 else None


def _covers(cert_names: list[str], domain: str) -> bool:
    for n in cert_names:
        n = (n or "").lower().rstrip(".")
        if n == domain or (n.startswith("*.") and (domain == n[2:] or domain.endswith(n[1:]))):
            return True
    return False


def extract(module: ModuleName, entity_key: str, details: dict, evidence: list[tuple[str, dict]]) -> list[Indicator]:
    """Indicators from a finding's own output fields and evidence metadata. `evidence` = [(kind, meta)]."""
    d, out = details or {}, []

    def add(kind: str, value, source: str) -> None:
        if value:
            out.append(Indicator(kind, str(value).strip().lower()[:500], source))

    if module in DOMAIN_MODULES or module == ModuleName.logo:
        domain = entity_key.lower()
        if module in DOMAIN_MODULES:
            add("domain", domain, SELF)
        for ip in d.get("A Records") or []:
            add("ip", ip, "DNS A record")
        for mx in d.get("MX Records") or []:
            host = mx.split()[-1].rstrip(".") if mx.split() else ""
            reg = registered_domain(host) if "." in host and not re.fullmatch(r"[\d.]+", host) else ""
            if reg and reg != registered_domain(domain) and reg not in MAIL_PROVIDERS:
                add("mail_server", reg, f"MX record {mx}")
        for kind, meta in evidence:
            if kind == "ssl" and meta.get("sha256") and _covers([meta.get("subject_cn"), *(meta.get("san") or [])],
                                                               domain):
                add("tls_cert", meta["sha256"], "TLS certificate presented by the website")
            if kind == "favicon" and meta.get("mmh3") is not None and not meta.get("match"):
                add("favicon", meta["mmh3"], "website favicon (mmh3)")
    if module == ModuleName.apk:
        if d.get("Signer Matches Official") is False:
            for fp in str(d.get("Signer SHA-256") or "").split(","):
                add("apk_signer", fp.strip(), "APK signing certificate")
        add("file_sha256", d.get("SHA256"), "APK file")
    if module == ModuleName.documents:
        add("file_sha256", d.get("SHA256"), "document file")
    if module == ModuleName.rogue_app:
        email = str(d.get("Developer Email") or "").lower()
        add("developer_email", email, "store listing developer e-mail")
        site = d.get("Developer Website")
        if site:
            reg = registered_domain(str(site))
            if reg and reg not in _FREE_MAIL:
                add("developer_site", reg, "store listing developer website")
    if module == ModuleName.social_media:
        for entry in d.get("Scam Contacts") or []:
            kind, _, value = str(entry).partition(": ")
            if kind in ("phone", "whatsapp"):
                add("contact_phone", _phone(value), f"{kind} number in the post")
            elif kind == "upi":
                add("contact_upi", value, "UPI ID in the post")
            elif kind == "telegram":
                add("contact_telegram", value.rsplit("/", 1)[-1], "Telegram link in the post")
    if module == ModuleName.email:
        for dom in d.get("Look-alike Domains") or []:
            add("domain", registered_domain(str(dom)) or dom, "domain linked from the email")
    return list({(i.kind, i.value): i for i in out}.values())


def store(db: Session, finding: Finding, indicators: list[Indicator]) -> None:
    """Upsert this finding's indicators (history kept: values seen before only get a new last_seen)."""
    now = datetime.now(UTC)
    existing = {(r.kind, r.value): r for r in db.scalars(select(FindingIndicator)
                                                          .where(FindingIndicator.finding_id == finding.id))}
    for ind in indicators:
        row = existing.get((ind.kind, ind.value))
        if row is not None:
            row.last_seen = now
        else:
            db.add(FindingIndicator(brand_id=finding.brand_id, finding_id=finding.id, kind=ind.kind,
                                    value=ind.value, source=ind.source[:200], first_seen=now, last_seen=now))
    db.flush()


@dataclass
class Link:
    finding_id: uuid.UUID
    kind: str
    value: str
    strong: bool
    label: str
    source: str


def _groups(rows) -> dict[tuple[str, str], dict[uuid.UUID, str]]:
    """{(kind, value): {finding_id: where it was seen}} for values that may link findings.

    A shared mail server only counts when its domain is itself one of the brand's look-alike findings (the operator
    runs mail on its own look-alike); that domain finding joins the group. A third-party mail or parking host shared
    by unrelated customers never links findings (D-49). Groups larger than the kind's limit are generic: dropped."""
    raw: dict[tuple[str, str], dict[uuid.UUID, str]] = defaultdict(dict)
    hosts: dict[str, tuple[uuid.UUID, str]] = {}
    for fid, kind, value, source in rows:
        raw[(kind, value)][fid] = source
        if kind == "domain" and source == SELF:
            hosts[value] = (fid, source)
    out = {}
    for (kind, value), members in raw.items():
        if kind == "mail_server":
            if value not in hosts:
                continue
            members = {**members, hosts[value][0]: "the look-alike domain that runs this mail server"}
        if 1 < len(members) <= KINDS.get(kind, ("", False, 0))[2]:
            out[(kind, value)] = members
    return out


def _rows(db: Session, brand_id: uuid.UUID, keys: set[tuple[str, str]] | None = None):
    stmt = select(FindingIndicator.finding_id, FindingIndicator.kind, FindingIndicator.value,
                  FindingIndicator.source).where(FindingIndicator.brand_id == brand_id)
    if keys is not None:
        values = {v for _, v in keys}
        stmt = stmt.where(FindingIndicator.value.in_(values))  # mail_server and domain rows share values
    return db.execute(stmt).all()


def related(db: Session, finding: Finding) -> list[Link]:
    """Other findings of the same brand that share an indicator with this one (generic values excluded)."""
    mine = {(r.kind, r.value) for r in db.scalars(select(FindingIndicator)
                                                   .where(FindingIndicator.finding_id == finding.id))}
    if not mine:
        return []
    links: list[Link] = []
    for (kind, value), members in _groups(_rows(db, finding.brand_id, mine)).items():
        if finding.id not in members:
            continue
        label, strong, _ = KINDS[kind]
        links += [Link(fid, kind, value, strong, label, src) for fid, src in members.items() if fid != finding.id]
    return links


def strong_link_count(db: Session, finding: Finding) -> int:
    return len({link.finding_id for link in related(db, finding) if link.strong})


def campaigns(db: Session, brand_id: uuid.UUID) -> list[dict]:
    """Groups of findings connected by strong links (union-find). Largest first."""
    groups = {k: m for k, m in _groups(_rows(db, brand_id)).items() if KINDS[k[0]][1]}
    parent: dict[uuid.UUID, uuid.UUID] = {}

    def find(x: uuid.UUID) -> uuid.UUID:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for members in groups.values():
        first, *rest = list(members)
        for other in rest:
            parent[find(other)] = find(first)
    out: dict[uuid.UUID, dict] = {}
    for (kind, value), members in groups.items():
        g = out.setdefault(find(next(iter(members))), {"findings": set(), "shared": []})
        g["findings"].update(members)
        g["shared"].append({"kind": kind, "label": KINDS[kind][0], "value": value, "findings": len(members)})
    result = [{"size": len(g["findings"]), "finding_ids": sorted(map(str, g["findings"])),
               "shared": sorted(g["shared"], key=lambda s: -s["findings"])} for g in out.values()]
    return sorted(result, key=lambda c: -c["size"])
