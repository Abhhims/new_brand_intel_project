"""Domain intelligence pipeline: Typosquat (§3.1) + MX (§3.1) + Active Phishing (§3.1), staged per D-19.

1. Generate typo variants of the official domains (TYP-01…08) and add Certificate Transparency
   hits for the brand keywords (TYP-09, D-11).
2. Resolve DNS for every candidate (TYP-11, MX-01). Registered ones become findings.
3. WHOIS/RDAP for registered domains (TYP-10). Store everything in domain_checks (MX-02).
4. Probe HTTP/HTTPS (PHI-01); if live, capture screenshot, title, favicon, page images (PHI-02…04),
   TLS certificate (PHI-05), favicon/logo comparison (PHI-06), keywords (PHI-07).
5. Threat intelligence: OpenPhish / urlscan.io / URLhaus listings of the domain (D-46).
6. Score (§6) and flag Suspected Phishing (PHI-08, D-04).
"""

from __future__ import annotations

import json
import time
from collections import Counter, deque
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.core.browser import PageCapture, capture
from app.core.evidence import EvidenceItem
from app.core.fetch import FetchError
from app.core.scoring import Signals, email_risk
from app.core.similarity import best_similarity, domain_label, host_labels, hosting_platform, registered_domain
from app.db.models import DomainCheck, Finding, ModuleName
from app.modules.base import BrandContext, Detection, ScanReport, parse_date
from app.modules.domains import discovery, reputation
from app.modules.domains.infra import DnsInfo, LiveInfra
from app.modules.domains.variants import DISCOVERED, category, generate_variants
from app.modules.email.intel import corroborated
from app.modules.email.posture import domain_can_send
from app.modules.pagecheck import PageFacts, analyse

log = structlog.get_logger(__name__)

MAX_HTML_EVIDENCE = 500_000
WHOIS_CACHE_DAYS = 7
WHOIS_WORKERS = 16
MIN_CT_SIMILARITY = 70  # CT results must still look like the brand

# Component names shown on the Scans page (D-31)
CT = "Certificate Transparency (crt.sh)"
# Order in which new domains from each source are checked (round-robin; generated typosquats come last in a round)
SOURCE_PRIORITY = {"phishing-feed": 0, "certstream": 1, "search-engine": 2, "hosting-platform": 3,
                   "brand-subdomain": 3, "certificate-transparency": 3, "commoncrawl": 3, "urlscan": 4}
DNS = "DNS resolution"
WHOIS = "WHOIS/RDAP"
CAPTURE = "Website probe & browser capture"
TLS = "TLS certificate"
EMAIL_RECORDS = "Look-alike email records (SPF/DMARC)"
INTEL = "Threat intel - {}"


class DomainModule:
    name = ModuleName.phishing

    def __init__(self, infra=None, capture_fn=capture) -> None:
        self._infra = infra
        self._capture = capture_fn
        self.stats: dict = {}
        self.report = ScanReport()
        self._intel: dict[str, Counter] = {}
        self._intel_reason: dict[str, str] = {}  # first failure reason per source, shown on the scan

    # ------------------------------------------------------------------ discovery
    def candidates(self, ctx: BrandContext, infra) -> dict[str, str]:
        """{domain: fuzzer} — generated variants plus CT discoveries."""
        variants = generate_variants(ctx.official_domains, ctx.terms)
        self.stats["variants_generated"] = len(variants)
        self.stats["variants_by_pattern"] = dict(Counter(category(f) for f in variants.values()))
        self.report.ok("Variant generation", variants=len(variants))
        official = {registered_domain(d) for d in ctx.official_domains}

        matcher = discovery.HostMatcher(ctx)
        ct_found = 0
        ct_terms = {t.lower().replace(" ", "") for t in ctx.terms} | set(matcher.strong)
        for term in sorted(ct_terms):
            try:
                entries = infra.ct_search(term)
            except (FetchError, ValueError) as exc:
                self.report.failed(CT, f"search failed for '{term}': {exc}", failed=1)
                continue
            self.report.ok(CT, searched=1)
            for e in entries:
                if ctx.has_date_range and not ctx.in_date_range(e.not_before):
                    continue  # D-50: certificate issued outside the chosen range
                # D-51: keep the site (hosting platforms included) or the exact brand-named host, not just the
                # registered domain - 'axisofficial.web.app' used to become 'web.app' and was dropped
                host = matcher.candidate(e.domain)
                if not host or host in official or host in variants:
                    continue
                variants[host] = ("hosting-platform" if hosting_platform(host)
                                  else "certificate-transparency" if host == registered_domain(host)
                                  else "brand-subdomain")
                ct_found += 1
        self.stats["ct_candidates"] = ct_found
        if getattr(infra, "discovery", False):  # internet discovery sources only with the live infrastructure
            for name, source in (("feeds", discovery.feed_hosts), ("certstream", discovery.certstream_hosts),
                                 ("search", discovery.search_hosts), ("urlscan", discovery.urlscan_hosts),
                                 ("commoncrawl", discovery.commoncrawl_hosts)):
                try:
                    found = source(ctx, self.report, matcher)
                except Exception as exc:  # noqa: BLE001 - one source must not stop the scan
                    self.report.failed(f"Discovery - {name}", f"{type(exc).__name__}: {str(exc)[:160]}")
                    log.exception("domain_discovery_failed", source=name)
                    continue
                new = {h: k for h, k in found.items() if h not in variants and h not in official}
                variants.update(new)
                self.stats[f"{name}_candidates"] = len(new)
        for d in getattr(infra, "extra_domains", []):  # injected sources (tests) may add known domains
            variants.setdefault(d, "various")
        return variants

    # ------------------------------------------------------------------ run
    def run(self, ctx: BrandContext, db: Session) -> Iterator[Detection]:
        started = time.monotonic()  # the time budget covers the whole scan (CT, DNS and WHOIS included)
        infra = self._infra or LiveInfra()
        cands = self.candidates(ctx, infra)
        dns_map = infra.resolve_many(list(cands))
        registered = {d: info for d, info in dns_map.items() if info.registered}
        unresolved = sum(1 for info in dns_map.values() if info.status == "unknown" and not info.registered)
        self.report.ok(DNS, checked=len(dns_map), registered=len(registered))
        if unresolved:
            # D-31: a timeout / SERVFAIL is "unknown", never "not registered"; those domains are retried next scan.
            # If nothing at all resolved, the resolvers are down: nothing was checked, so the run has failed.
            outage = unresolved == len(dns_map)
            self.report.failed(DNS, f"{unresolved} domains could not be resolved (timeout/SERVFAIL) - not treated "
                                    "as unregistered; retried next scan", fatal=outage, unresolved=unresolved)
        self.stats["unresolved"] = unresolved
        self.stats["registered"] = len(registered)
        self.stats["mx_enabled"] = sum(1 for i in registered.values() if i.mx)
        self._whois = self.prefetch_whois(ctx, db, infra, sorted(registered))
        if ctx.has_date_range:  # D-50: domains registered outside the chosen range (unknown dates are kept)
            outside = [d for d in registered
                       if parse_date((self._whois.get(d) or {}).get("created")) is not None
                       and not ctx.in_date_range((self._whois.get(d) or {}).get("created"))]
            for d in outside:
                registered.pop(d)
            self.stats["outside_date_range"] = len(outside)
        s = get_settings()
        workers = max(1, s.domain_check_workers)
        order = self.check_order(ctx, db, list(registered), cands)
        deadline = started + s.domain_scan_budget_seconds
        live, checked = 0, 0
        todo, pending = deque(order), deque()
        # Website captures (the slow part, up to ~40 s each) run a few at a time; everything that touches the
        # database stays in this thread. Domains never checked, or checked longest ago, go first, so a scan cut
        # short by the time budget is continued by the next one.
        with ThreadPoolExecutor(max_workers=workers) as pool:
            while todo or pending:
                while todo and len(pending) < 2 * workers and time.monotonic() < deadline:
                    d = todo.popleft()
                    pending.append((d, pool.submit(self.web_probe, infra, d, registered[d])))
                if not pending:
                    break  # time budget used up
                domain, future = pending.popleft()
                try:
                    finding, is_live = self.check_domain(ctx, db, infra, domain, cands[domain], registered[domain],
                                                         probe=future.result())
                except Exception as exc:  # noqa: BLE001 - keep going with other domains
                    self.report.failed("Domain checks", f"{domain}: {type(exc).__name__}: {exc}", failed=1)
                    log.exception("domain_check_failed", domain=domain)
                    continue
                checked += 1
                live += is_live
                if finding is not None:
                    yield finding
        if todo:
            self.report.unavailable("Domain checks", f"{len(todo)} of {len(order)} registered domains not checked "
                                                     f"within the {s.domain_scan_budget_seconds // 60}-minute time "
                                                     "budget - they are checked first on the next scan")
        elif checked:
            self.report.ok("Domain checks", checked=checked)
        self.stats.update(live_websites=live, domains_checked=checked, domains_deferred=len(todo))
        self._report_intel()

    def check_order(self, ctx: BrandContext, db: Session, domains: list[str],
                    sources: dict[str, str] | None = None) -> list[str]:
        """Never-checked domains first, then the ones checked longest ago. New domains are taken from every
        source in turn (feeds, CertStream, search, CT/hosting, urlscan, typosquats), so one big source cannot use
        up the whole time budget (D-52)."""
        rows = db.execute(select(DomainCheck.domain, func.max(DomainCheck.checked_at))
                          .where(DomainCheck.brand_id == ctx.id, DomainCheck.domain.in_(domains))
                          .group_by(DomainCheck.domain)).all()
        last = {d: t for d, t in rows if t is not None}
        epoch = datetime.min.replace(tzinfo=UTC)
        sources = sources or {}
        group = {d: SOURCE_PRIORITY.get(sources.get(d, ""), len(set(SOURCE_PRIORITY.values()))) for d in domains}
        rank: dict[str, int] = {}
        seen: dict[int, int] = {}
        for d in sorted(domains):
            if d not in last:
                rank[d] = seen.get(group[d], 0)
                seen[group[d]] = rank[d] + 1
        return sorted(domains, key=lambda d: (d in last, last.get(d, epoch), rank.get(d, 0), group[d], d))

    # ------------------------------------------------------------------ website probe (runs in worker threads)
    def web_probe(self, infra, domain: str, info: DnsInfo) -> tuple:
        """(urls tried, capture of the first live one, its url, capture errors). Network only, no database."""
        urls = infra.web_urls(domain, info)
        capture_errors: list[str] = []
        for url in urls:
            try:
                cap = self._capture(url, collect_images=True)
            except (FetchError, Exception) as exc:  # noqa: BLE001 - recorded, never read as "offline"
                log.info("web_probe_failed", url=url, error=str(exc)[:200])
                capture_errors.append(f"{type(exc).__name__}: {str(exc)[:120]}")
                cap = None
            if cap and cap.status is not None:
                return urls, cap, url, capture_errors
            if cap is not None and cap.error:
                # the browser reports navigation failures (timeouts, resets) this way rather than raising
                capture_errors.append(cap.error[:160])
        return urls, None, None, capture_errors

    # ------------------------------------------------------------------ WHOIS (parallel + 7-day cache)
    def prefetch_whois(self, ctx: BrandContext, db: Session, infra, domains: list[str]) -> dict[str, dict]:
        """Registration data rarely changes: reuse a successful lookup from the last 7 days, and look the rest
        up in parallel (registrar RDAP servers can take 20+ seconds each)."""
        since = datetime.now(UTC) - timedelta(days=WHOIS_CACHE_DAYS)
        cached: dict[str, dict] = {}
        rows = db.execute(select(DomainCheck.domain, DomainCheck.whois).where(
            DomainCheck.brand_id == ctx.id, DomainCheck.domain.in_(domains), DomainCheck.checked_at >= since)
            .order_by(DomainCheck.checked_at.desc())).all()
        for dom, w in rows:
            if dom not in cached and w and not w.get("error"):
                cached[dom] = w
        todo = [d for d in domains if d not in cached]
        if todo:
            with ThreadPoolExecutor(max_workers=WHOIS_WORKERS) as pool:
                cached.update(zip(todo, pool.map(infra.whois, todo), strict=True))
        self.stats["whois_cached"] = len(domains) - len(todo)
        failed = [d for d in domains if (cached.get(d) or {}).get("error")]
        if domains:
            self.report.ok(WHOIS, looked_up=len(domains) - len(failed))
        if failed:
            self.report.failed(WHOIS, f"{len(failed)} lookups failed (RDAP coverage/rate limits); registrar and dates "
                                      "shown as 'lookup failed'", failed=len(failed))
        return cached

    # ------------------------------------------------------------------ threat intelligence (D-46)
    def _reputation(self, domain: str, infra) -> list:
        lookup = getattr(infra, "reputation", None)
        if lookup is None:
            return []
        try:
            verdicts = lookup(domain)
        except Exception as exc:  # noqa: BLE001 - recorded; the domain is still checked without it
            self.report.failed(INTEL.format("lookup"), f"{domain}: {type(exc).__name__}: {str(exc)[:120]}", failed=1)
            return []
        for v in verdicts:
            counts = self._intel.setdefault(v.tool, Counter())
            counts[v.status] += 1
            counts["listed"] += int(v.malicious)
            if v.status != "ok" and v.details:
                self._intel_reason.setdefault(v.tool, ", ".join(f"{k} {x}" for k, x in v.details.items() if x))
        return verdicts

    def _report_intel(self) -> None:
        s = get_settings()
        for tool, c in self._intel.items():
            name = INTEL.format(reputation.SOURCES.get(tool, tool))
            if c["ok"]:
                self.report.ok(name, checked=c["ok"], listed=c["listed"])
            missed = sum(n for st, n in c.items() if st not in ("ok", "listed"))
            if not missed:
                continue
            env = reputation.KEYS.get(tool)
            if env and not getattr(s, env.lower()):
                self.report.not_configured(name, f"{env} not set - domains not checked against {tool}")
            else:
                why = self._intel_reason.get(tool)
                self.report.failed(name, f"{missed} lookups failed{f' ({why})' if why else ''} - not treated as "
                                         "'not listed'", failed=missed)

    # ------------------------------------------------------------------ email readiness of a look-alike (EML-17)
    def _email_records(self, domain: str, infra) -> tuple[list[str], list[str]]:
        try:
            spf, dmarc = infra.email_records(domain)
        except Exception as exc:  # noqa: BLE001
            self.report.failed(EMAIL_RECORDS, f"{domain}: {type(exc).__name__}", failed=1)
            return [], []
        self.report.ok(EMAIL_RECORDS, checked=1)
        return spf, dmarc

    # ------------------------------------------------------------------ one domain
    def check_domain(self, ctx: BrandContext, db: Session, infra, domain: str, fuzzer: str,
                     info: DnsInfo, probe: tuple | None = None) -> tuple[Detection | None, bool]:
        s = get_settings()
        whois = self._whois.get(domain) if domain in getattr(self, "_whois", {}) else infra.whois(domain)
        labels = host_labels(domain) or [domain_label(domain)]
        similarity, closest = max((best_similarity(lb, ctx.labels) for lb in labels), key=lambda x: x[0])
        # RSK-01 is the literal brand name; look-alike spellings are covered by typo similarity
        flat_name = "".join(labels).replace("-", "")
        exact = any(t.lower().replace(" ", "") in flat_name for t in ctx.terms)
        discovered = fuzzer in DISCOVERED

        facts, tls = PageFacts(), None
        urls, cap, web_url, capture_errors = probe or self.web_probe(infra, domain, info)
        is_live = cap is not None
        # A port answered but the page could not be captured: the website state is unknown, not "offline" (D-31)
        capture_unknown = bool(urls) and not is_live and bool(capture_errors)
        if capture_unknown:
            self.report.failed(CAPTURE, f"{domain}: {capture_errors[0]}", capture_failed=1)
            existing = db.scalar(select(Finding.id).where(Finding.brand_id == ctx.id, Finding.entity_key == domain))
            if existing is not None:
                return None, False  # keep the existing finding exactly as it is; retried next scan
        elif urls:
            self.report.ok(CAPTURE, probed=1, captured=int(is_live))
        if is_live:
            facts = analyse(cap, ctx)
            tls = infra.tls(domain)
            if tls and tls.get("error"):
                self.report.failed(TLS, f"{domain}: {str(tls['error'])[:120]}", failed=1)
            else:
                self.report.ok(TLS, checked=1)
        https = bool(is_live and tls and tls.get("present"))
        logo_found = facts.logo_score >= s.logo_match_threshold
        spf_records, dmarc_records = self._email_records(domain, infra)
        can_send = domain_can_send(spf_records)
        verdicts = self._reputation(domain, infra)
        listed_by = corroborated(verdicts)

        # D-29: a live page must itself show the brand before it can be High/Critical or Suspected Phishing
        brand_evidence = is_live and (facts.brand_evidence or logo_found)
        parked = is_live and facts.parked
        signals = Signals(
            brand_exact_in_domain=exact, typo_similarity=similarity, mx_present=bool(info.mx), https=https,
            login_payment_keywords=is_live and facts.login_payment, official_logo=is_live and logo_found,
            lookalike_can_send=can_send, page_live=is_live, brand_on_page=brand_evidence, parked_page=parked,
            known_malicious_url=listed_by >= 2, single_source_url_hit=listed_by == 1,
        )
        # D-51: a host found by its brand name/content (feeds, urlscan, search, CT subdomain) needs no typo
        # similarity - the page showing the brand plus a login/logo is what matters
        lookalike_name = similarity >= s.phishing_similarity_threshold or (discovered and (exact or fuzzer in (
            "phishing-feed", "urlscan", "search-engine")))
        suspected = (is_live and brand_evidence and not parked and lookalike_name
                     and (facts.login_payment or facts.favicon_match or logo_found)) or (is_live and listed_by >= 2)
        stage = ModuleName.phishing if is_live else (ModuleName.mx if info.mx else ModuleName.typosquat)

        db.add(DomainCheck(
            brand_id=ctx.id, domain=domain, fuzzer=fuzzer, registered=True, a_records=info.a,
            mx_records=info.mx, ns_records=info.ns, whois=whois, http_status=cap.status if cap else None,
            final_url=cap.final_url if cap else None, title=(cap.title[:1000] if cap else None),
            ssl=tls or {}, favicon_mmh3=facts.favicon_mmh3,
        ))

        details = {
            "Domain": domain,
            "Similarity Score": round(similarity),
            "MX Enabled": bool(info.mx),
            "Website Live": "unknown (capture failed)" if capture_unknown else is_live,
            "SSL Present": https,
            "Screenshot": bool(cap and cap.screenshot),
            "Email Risk": email_risk(bool(info.mx), is_live).value,
            "SPF Record": spf_records[0] if spf_records else None,
            "DMARC Record": dmarc_records[0] if dmarc_records else None,
            "Email-ready": can_send or bool(info.mx),
            "Suspected Phishing": suspected,
            "Threat Intel": reputation.summary(verdicts) if verdicts else "Not checked",
            "Fuzzer": category(fuzzer),
            "Registered": True,
            "Registrar": "lookup failed" if whois.get("error") else whois.get("registrar"),
            "Created": "lookup failed" if whois.get("error") else whois.get("created"),
            "MX Records": info.mx,
            "A Records": info.a,
            "Page Title": cap.title if cap else None,
            "HTTP Status": cap.status if cap else None,
            "Final URL": cap.final_url if cap else None,
            "Favicon Match": facts.favicon_match,
            "Keywords Found": facts.keywords_found,
            "SSL Issuer": (tls or {}).get("issuer_org") or (tls or {}).get("issuer_cn"),
            "SSL Expires": (tls or {}).get("not_after"),
            "Logo Match Score": round(facts.logo_score) if facts.logo_score else None,
            "Brand Evidence On Page": brand_evidence if is_live else None,
            "Brand Terms On Page": facts.brand_terms_found,
            "Official Site References": facts.official_refs,
            "Parked Page": parked,
            "Discovery Source": category(fuzzer) if discovered else f"Typosquat generation ({category(fuzzer)})",
            "Hosting Platform": hosting_platform(domain),
            "Closest Brand Term": closest,
        }
        evidence = [
            EvidenceItem("dns", meta={"a": info.a, "mx": info.mx, "ns": info.ns}),
            EvidenceItem("whois", data=json.dumps(whois, indent=2, default=str).encode(),
                         content_type="application/json", meta=whois),
        ]
        if verdicts:
            evidence.append(EvidenceItem("metadata", meta={"role": "threat_intel", "domain": domain,
                                                           "verdicts": [v.as_dict() for v in verdicts]}))
        if cap:
            evidence += self._page_evidence(cap, facts)
        if tls:
            evidence.append(EvidenceItem("ssl", data=json.dumps(tls, indent=2).encode(),
                                         content_type="application/json", meta=tls))
        title = {ModuleName.phishing: "Live look-alike website", ModuleName.mx: "Email-enabled look-alike domain",
                 ModuleName.typosquat: "Registered look-alike domain"}[stage]
        if suspected:
            title = "Suspected phishing website"
        elif parked:
            title = "Parked look-alike domain"
        return Detection(
            entity_key=domain, title=f"{title}: {domain}", signals=signals, details=details,
            similarity=similarity, suspected_phishing=suspected, source_url=web_url and (cap.final_url if cap else web_url),
            evidence=evidence, module=stage,
            analysed=is_live or bool(info.mx) or listed_by > 0,  # D-33: no website, MX or listing = Candidate
            state={**({"live": None, "login_form": None, "logo_match": None} if capture_unknown else {}),
                   "intel_listed": listed_by > 0 if any(v.status == "ok" for v in verdicts) else None},
        ), is_live

    @staticmethod
    def _page_evidence(cap: PageCapture, facts: PageFacts) -> list[EvidenceItem]:
        items = []
        meta = {"url": cap.url, "final_url": cap.final_url, "status": cap.status, "title": cap.title,
                "password_field": cap.has_password_field, "form_actions": cap.form_actions[:10]}
        if cap.screenshot:
            items.append(EvidenceItem("screenshot", data=cap.screenshot, content_type="image/png", meta=meta))
        if cap.favicon:
            items.append(EvidenceItem("favicon", data=cap.favicon, content_type="image/x-icon",
                                      meta={"url": cap.favicon_url, "mmh3": facts.favicon_mmh3,
                                            "match": facts.favicon_match,
                                            "match_score": facts.favicon_match_score}))
        if cap.html:
            items.append(EvidenceItem("html", data=cap.html[:MAX_HTML_EVIDENCE].encode("utf-8", "replace"),
                                      content_type="text/html", meta={"url": cap.final_url}))
        if facts.logo_image and facts.logo_score:
            items.append(EvidenceItem("image", data=facts.logo_image, meta={
                "url": facts.logo_image_url, "logo_match_score": facts.logo_score}))
        return items
