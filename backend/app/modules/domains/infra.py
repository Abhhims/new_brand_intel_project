"""Where domain facts come from: the live internet (DNS, RDAP/WHOIS, crt.sh, HTTP). Tests inject their own."""

from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from urllib.parse import quote

import dns.exception
import dns.resolver
import structlog

from app.core.fetch import FetchError, fetch, fetch_certificate, port_open
from app.core.similarity import hosting_platform, registered_domain

log = structlog.get_logger(__name__)


@dataclass
class DnsInfo:
    a: list[str] = field(default_factory=list)
    mx: list[str] = field(default_factory=list)
    ns: list[str] = field(default_factory=list)
    # resolved: answers received · nxdomain: definitively does not exist · unknown: timeout/SERVFAIL (D-31)
    status: str = "resolved"

    @property
    def registered(self) -> bool:
        return bool(self.a or self.mx or self.ns)


@dataclass
class CtEntry:
    domain: str
    issuer: str
    not_before: str


class LiveInfra:
    """Real lookups. Every HTTP call goes through the safe fetcher."""

    workers = 128
    discovery = True  # run the extra internet discovery sources (D-51)
    # Public resolvers directly: faster and more consistent than OS/ISP resolvers for bulk NXDOMAIN lookups
    nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "1.0.0.1", "8.8.4.4"]

    def __init__(self) -> None:
        self.resolver = dns.resolver.Resolver(configure=False)
        self.resolver.nameservers = self.nameservers
        self.resolver.rotate = True
        self.resolver.timeout = 1.5
        self.resolver.lifetime = 3.0

    def _records(self, name: str, rtype: str) -> tuple[list[str], bool]:
        """(records, definitive). NXDOMAIN / no answer is a definitive "no"; a timeout or SERVFAIL is not."""
        try:
            ans = self.resolver.resolve(name, rtype, raise_on_no_answer=False)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.name.LabelTooLong, dns.name.EmptyLabel,
                ValueError):
            return [], True
        except dns.exception.DNSException:  # Timeout, NoNameservers (SERVFAIL), …
            return [], False
        return (sorted({r.to_text().rstrip(".") for r in ans}) if ans.rrset else []), True

    def _mx(self, domain: str) -> list[str]:
        # "0 ." is a null MX (RFC 7505): the domain states it accepts no email, so it is not email-enabled
        return [r for r in self._records(domain, "MX")[0] if len(r.split()) == 2]

    def _resolve_one(self, domain: str) -> tuple[str, DnsInfo]:
        # One NS lookup decides "registered": unregistered names fail fast with NXDOMAIN, which is the
        # vast majority of variants. A and MX are only fetched for registered domains.
        ns, ok = self._records(domain, "NS")
        if not ns:
            a, ok_a = self._records(domain, "A")  # rare: delegated without NS answer at apex
            if not a:
                return domain, DnsInfo(status="nxdomain" if ok and ok_a else "unknown")
            return domain, DnsInfo(a=a, mx=self._mx(domain))
        return domain, DnsInfo(a=self._records(domain, "A")[0], mx=self._mx(domain), ns=ns)

    def resolve_many(self, domains: list[str]) -> dict[str, DnsInfo]:
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            return dict(pool.map(self._resolve_one, domains))

    def resolve(self, domain: str) -> DnsInfo:
        return self._resolve_one(domain)[1]

    def whois(self, domain: str) -> dict:
        platform = hosting_platform(domain)
        if platform:  # a site on vercel.app / web.app... has no registration of its own (D-51)
            return {"registrar": None, "created": None, "hosted_on": platform,
                    "note": f"Site on the {platform} hosting platform - no registration of its own"}
        domain = registered_domain(domain)  # brand-in-subdomain hosts: the registration is the parent domain's
        try:
            import whoisit

            if not whoisit.is_bootstrapped():
                whoisit.bootstrap()
            data = whoisit.domain(domain)
        except Exception as exc:  # noqa: BLE001 - RDAP coverage varies by TLD
            return {"error": f"{type(exc).__name__}: {str(exc)[:200]}"}
        registrar = data.get("registrar") or {}
        return {
            "registrar": registrar.get("name") if isinstance(registrar, dict) else str(registrar),
            "created": str(data.get("registration_date") or "") or None,
            "expires": str(data.get("expiration_date") or "") or None,
            "status": data.get("status"),
            "nameservers": data.get("nameservers"),
        }

    def ct_search(self, term: str) -> list[CtEntry]:
        url = f"https://crt.sh/?q={quote('%' + term + '%')}&output=json&exclude=expired"
        last = ""
        for attempt in range(3):  # crt.sh is often overloaded (502/503/timeouts): retry before giving up
            try:
                r = fetch(url, max_bytes=60 * 1024 * 1024, timeout=120)
                if r.status == 200:
                    return _ct_rows(json.loads(r.content or b"[]"))
                last = f"HTTP {r.status}"
            except (FetchError, ValueError) as exc:
                last = str(exc)[:160]
            log.info("ct_search_retry", term=term, attempt=attempt + 1, error=last)
            time.sleep(10 * (attempt + 1))
        raise FetchError(f"crt.sh unavailable after 3 tries ({last})")

    def web_urls(self, domain: str, info: DnsInfo | None = None) -> list[str]:
        """Only URLs that accept a connection — dead hosts never cost a 30-second browser timeout."""
        if info is not None and not info.a and not self._records(domain, "AAAA")[0]:
            return []  # no address: no website
        return [url for url, port in ((f"https://{domain}/", 443), (f"http://{domain}/", 80))
                if port_open(domain, port)]

    def reputation(self, domain: str) -> list:
        """Threat-intelligence verdicts for the domain (D-46)."""
        from app.modules.domains.reputation import domain_reputation

        return domain_reputation(domain)

    def email_records(self, domain: str) -> tuple[list[str], list[str]]:
        """(SPF records, DMARC records) of a look-alike domain (EML-17)."""
        from app.modules.email.posture import _resolve_txt

        spf = [r for r in _resolve_txt(domain) if r.lower().startswith("v=spf1")]
        dmarc = [r for r in _resolve_txt(f"_dmarc.{domain}") if r.lower().replace(" ", "").startswith("v=dmarc1")]
        return spf, dmarc

    def tls(self, domain: str) -> dict | None:
        try:
            return fetch_certificate(domain)
        except Exception as exc:  # noqa: BLE001
            return {"present": False, "error": f"{type(exc).__name__}: {str(exc)[:200]}"}


def _ct_rows(rows: list[dict]) -> list[CtEntry]:
    out: dict[str, CtEntry] = {}
    for row in rows:
        for name in str(row.get("name_value", "")).splitlines():
            name = name.strip().lower().lstrip("*.").removeprefix("www.")
            if name and "." in name and name not in out:
                out[name] = CtEntry(domain=name, issuer=row.get("issuer_name", ""),
                                    not_before=row.get("not_before", ""))
    return list(out.values())
