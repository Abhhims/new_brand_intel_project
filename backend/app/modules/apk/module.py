"""Fake APK monitoring (§3.2, APK-01…09, D-12).

Sources: the APK stores' own search — Aptoide's public API (with each build's signing certificate) and APKMirror's
search page — plus web search restricted to public APK sites. Direct sources keep working when the search engine
is rate-limited (seen live 2026-10-10: every DuckDuckGo-only APK scan failed).
For each listing: compare app name / package with the official ones, compare the icon with the
official logo and app icon, check the developer against approved publishers, and — when a direct
download is offered — store the APK as evidence, compute SHA256 and read the manifest only.
APKs are never executed or decompiled (OOS-03).
"""

from __future__ import annotations

import html as htmllib
import io
import json
import re
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass
from urllib.parse import quote, urlencode, urlsplit

import structlog
from rapidfuzz import fuzz
from sqlalchemy.orm import Session

from app.config import get_settings
from app.core import search
from app.core.evidence import EvidenceItem, sha256
from app.core.fetch import try_fetch
from app.core.scoring import Signals
from app.db.models import ModuleName
from app.modules.apk import commoncrawl
from app.modules.apk.signing import SignerInfo, read_signers
from app.modules.base import BrandContext, Detection, ScanReport
from app.modules.common import html_title, image_match, literal_brand_in, og_image, report_search_failure

log = structlog.get_logger(__name__)


APK_SITES = ["apkpure.com", "apkpure.net", "apkmirror.com", "apkcombo.com", "uptodown.com", "apk.support",
             "apkmonk.com", "aptoide.com", "malavida.com", "softonic.com", "apponic.com", "soft112.com",
             "apkfab.com", "apk20.com", "an1.com", "happymod.com", "apkdone.com", "apkmody.com", "liteapks.com",
             "moddroid.com", "apksfull.com", "apkgk.com", "apksupport.org", "filehippo.com", "apkaward.com"]
# Search engines rarely honour long OR lists of site: filters; ask for the main ones and keep any APK-site result
SEARCH_SITES = ["apkpure.com", "apkpure.net", "apkcombo.com", "uptodown.com", "apkmirror.com", "softonic.com",
                "apkfab.com", "apk.support"]
MAX_ARCHIVED_PAGES = 25
PACKAGE_RE = re.compile(r"\b([a-z][a-z0-9_]{1,40}(?:\.[a-z0-9_]{1,40}){1,6})\b")
RELEVANCE = 80


@dataclass
class Listing:
    site: str
    title: str
    package: str | None
    version: str | None
    developer: str | None
    listing_url: str
    icon_url: str | None
    download_url: str | None
    store_signer: str | None = None      # signing certificate owner reported by the store (Aptoide)
    store_signer_sha1: str | None = None
    discovered_via: str = "web search"


DOWNLOAD = "APK download & analysis"
APTOIDE = "Aptoide store search"
APKMIRROR = "APKMirror search"
MAX_DIRECT_PER_TERM = 50
MAX_MIRROR_PAGES = 15  # APKMirror release pages read per scan (each is one request)


def aptoide_listings(ctx: BrandContext, report: ScanReport) -> list[Listing]:
    """Aptoide's public JSON API: name, package, version, uploader store, icon, direct APK link and the build's
    signing certificate. No key needed."""
    out: dict[str, Listing] = {}
    for term in ctx.terms[:3]:
        r = try_fetch("https://ws75.aptoide.com/api/7/apps/search?" + urlencode({"query": term,
                                                                                 "limit": MAX_DIRECT_PER_TERM}))
        if not (r and r.status == 200):
            report.unavailable(APTOIDE, f"search '{term}': {'no response' if not r else f'HTTP {r.status}'}")
            continue
        try:
            items = json.loads(r.content).get("datalist", {}).get("list", [])
        except ValueError:
            report.failed(APTOIDE, f"search '{term}': unreadable response")
            continue
        report.ok(APTOIDE, queries=1, results=len(items))
        for it in items:
            pkg, f = it.get("package"), it.get("file") or {}
            if not pkg:
                continue
            sig = f.get("signature") or {}
            out.setdefault(f"{pkg}:{f.get('vercode')}", Listing(
                site="aptoide.com", title=it.get("name") or pkg, package=pkg.lower(), version=f.get("vername"),
                developer=(it.get("developer") or {}).get("name") or (it.get("store") or {}).get("name"),
                listing_url=f"https://{it.get('uname') or quote(pkg)}.en.aptoide.com/app", icon_url=it.get("icon"),
                download_url=f.get("path"), store_signer=sig.get("owner"), store_signer_sha1=sig.get("sha1"),
                discovered_via="Aptoide API"))
    return list(out.values())


_MIRROR_ROW = re.compile(r'<a class="fontBlack" href="(/apk/[^"]+)">([^<]+)</a>\s*</h5>\s*'
                         r'<a href="/apk/[^"]+" class="byDeveloper[^"]*">by ([^<]+)</a>')


def apkmirror_candidates(ctx: BrandContext, report: ScanReport) -> list[tuple[str, str, str]]:
    """(release page URL, title, developer) from APKMirror's own search page."""
    out: dict[str, tuple[str, str, str]] = {}
    for term in ctx.terms[:3]:
        r = try_fetch("https://www.apkmirror.com/?" + urlencode({"post_type": "app_release", "searchtype": "apk",
                                                                  "s": term}))
        if not (r and r.status == 200):
            report.unavailable(APKMIRROR, f"search '{term}': {'no response' if not r else f'HTTP {r.status}'}")
            continue
        rows = _MIRROR_ROW.findall(r.text)
        report.ok(APKMIRROR, queries=1, results=len(rows))
        for href, title, dev in rows:
            title, dev = htmllib.unescape(title).strip(), htmllib.unescape(dev).strip()
            app_key = "/".join(href.split("/")[:4])  # /apk/<developer>/<app>: one release per app is enough
            out.setdefault(app_key, ("https://www.apkmirror.com" + href, title, dev))
    return list(out.values())


class LiveApkSource:
    """Search-engine discovery of APK listing pages, then read the public listing page."""

    def listings(self, ctx: BrandContext, report: ScanReport) -> list[Listing]:
        out: list[Listing] = aptoide_listings(ctx, report)
        # APKMirror: only read the release pages of results that look like the brand (each page is a request)
        mirror = [c for c in apkmirror_candidates(ctx, report)
                  if ctx.relevance(f"{c[1]} {c[2]}", name=c[1]).relevant][:MAX_MIRROR_PAGES]
        for url, title, dev in mirror:
            li = self._read_listing(url, title, report)
            li.developer, li.discovered_via = li.developer or dev, "APKMirror search"
            out.append(li)

        sites = " OR ".join(f"site:{s}" for s in SEARCH_SITES)
        component = search.component_name()
        results, terms, failures = [], ctx.terms[:3], 0
        for term in terms:
            try:
                results += search.search(f'"{term}" apk ({sites})', count=20)
                report.ok(component, queries=1)
            except search.SearchUnavailable as exc:
                failures += 1
                report_search_failure(report, component, exc)
        if failures == len(terms) and not any(c["status"] == "ok" for c in report.as_list()):
            # nothing at all could be searched: the run cannot claim "no fake APKs" (D-31)
            report.failed("APK sources", "no APK source could be searched (stores and web search)", fatal=True)
        seen = {li.listing_url for li in out}
        for r in results:
            if r.url in seen or not any(s in (urlsplit(r.url).hostname or "") for s in APK_SITES):
                continue
            seen.add(r.url)
            out.append(self._read_listing(r.url, r.title, report))

        # Common Crawl: archived listing pages (also of APK sites unreachable live from this network, D-42)
        archived = 0
        for page in commoncrawl.find_pages(ctx, report):
            if page.url in seen or archived >= MAX_ARCHIVED_PAGES:
                continue
            guess = " ".join(p.replace("-", " ") for p in urlsplit(page.url).path.split("/") if p)
            if not ctx.relevance(guess, name=guess.split(" ")[0] if guess else None).relevant:
                continue  # only fetch archived pages whose URL looks like the brand
            html = commoncrawl.archived_html(page)
            if html is None:
                report.failed("Common Crawl archive", f"{page.url}: archived copy could not be read", failed=1)
                continue
            report.ok("Common Crawl archive", read=1)
            seen.add(page.url)
            archived += 1
            li = self._parse_listing(page.url, html, guess)
            li.discovered_via = f"Common Crawl ({page.collection}, archived {page.timestamp[:8]})"
            li.download_url = None  # never download from an archived link
            out.append(li)
        return out

    def _read_listing(self, url: str, title: str, report: ScanReport) -> Listing:
        page = try_fetch(url)
        if page and page.status == 200:
            report.ok("Listing pages", read=1)
        else:
            report.failed("Listing pages", f"{urlsplit(url).hostname}: could not be read", failed=1)
        return self._parse_listing(url, page.text if page and page.status == 200 else "", title)

    @staticmethod
    def _parse_listing(url: str, html: str, title: str) -> Listing:
        path_pkg = next((p for p in urlsplit(url).path.split("/") if PACKAGE_RE.fullmatch(p.lower())), None)
        pkg = path_pkg
        if not pkg and html:
            m = re.search(r"(?:package(?:\s*name)?|app\s*id)[^a-z0-9]{1,40}" + PACKAGE_RE.pattern, html, re.I)
            pkg = m.group(1) if m else None
        dev = None
        m = re.search(r"(?:developer|publisher|by)\s*[:\-]?\s*</?[^>]*>?\s*([A-Z][\w .,&'-]{2,60})", html)
        if m:
            dev = m.group(1).strip()
        ver = None
        m = re.search(r"(?:version|ver\.?)\s*[:\-]?\s*([0-9][0-9.]{0,20})", html, re.I)
        if m:
            ver = m.group(1)
        dl = None
        m = re.search(r'href=["\']([^"\']+\.apk)["\']', html, re.I)
        if m:
            dl = m.group(1) if m.group(1).startswith("http") else None
        return Listing(site=urlsplit(url).hostname or "", title=html_title(html) or title, package=pkg, version=ver,
                       developer=dev, listing_url=url, icon_url=og_image(html), download_url=dl)


def read_manifest(apk_bytes: bytes) -> dict:
    """Package/version/label from the manifest only (no decompilation). Best-effort."""
    try:
        from androguard.core.apk import APK

        apk = APK(apk_bytes, raw=True)
        return {"package": apk.get_package(), "version": apk.get_androidversion_name(),
                "app_name": apk.get_app_name(), "parsed_by": "androguard"}
    except Exception:  # noqa: BLE001 - malformed / fake APKs are common
        pass
    try:
        with zipfile.ZipFile(io.BytesIO(apk_bytes)) as z:
            manifest = z.read("AndroidManifest.xml")
        text = manifest.decode("utf-8", "ignore")
        pkg = re.search(r'package="([^"]+)"', text)
        ver = re.search(r'versionName="([^"]+)"', text)
        return {"package": pkg and pkg.group(1), "version": ver and ver.group(1), "parsed_by": "zip-manifest",
                "note": "Manifest is not compiled binary XML — not a genuine build"}
    except (zipfile.BadZipFile, KeyError, OSError):
        return {"parsed_by": None, "note": "Not a valid APK archive"}


class ApkModule:
    name = ModuleName.apk

    def __init__(self, source=None) -> None:
        self._source = source
        self.stats: dict = {}
        self.report = ScanReport()

    def run(self, ctx: BrandContext, db: Session) -> Iterator[Detection]:
        source = self._source or LiveApkSource()
        listings = source.listings(ctx, self.report)
        self.stats.update(listings_checked=len(listings), suspicious=0)
        for listing in listings:
            try:
                finding = self.analyse(ctx, listing)
            except Exception as exc:  # noqa: BLE001
                self.report.failed("Listing analysis", f"{listing.listing_url}: {type(exc).__name__}: {exc}",
                                   failed=1)
                continue
            if finding:
                self.stats["suspicious"] += 1
                yield finding

    def analyse(self, ctx: BrandContext, li: Listing) -> Detection | None:
        s = get_settings()
        pkg = (li.package or "").lower()
        official_pkg = pkg in ctx.official_packages
        official_dev = bool(li.developer) and li.developer.strip().lower() in {p.lower() for p in ctx.official_publishers}
        # Names are easy to copy, signatures are not (D-26): with official signers on record, a mirror listing that
        # claims to be the official app is downloaded and verified instead of being trusted by its label.
        verify_by_signature = bool(ctx.official_signers and li.download_url)
        if official_pkg and official_dev and not verify_by_signature:
            return None  # the genuine app re-hosted by a mirror

        rel = ctx.relevance(" ".join(x for x in (li.title, pkg.replace(".", " "), li.developer) if x), name=li.title)
        name_sim = rel.similarity
        pkg_sim = max((fuzz.ratio(pkg, o) for o in ctx.official_packages), default=0.0) if pkg else 0.0
        # D-25: a distinctive brand word in the package counts; a short abbreviation only with context
        pkg_brand = bool(pkg) and (literal_brand_in(pkg, ctx.strong_terms)
                                   or bool(rel.context_hits and literal_brand_in(pkg, ctx.weak_terms)))
        similarity = max(name_sim, float(pkg_sim), 100.0 if pkg_brand else 0.0)
        if not (rel.relevant or pkg_brand or pkg_sim >= RELEVANCE or official_pkg):
            return None

        logo_score, icon_bytes, icon_type = image_match(li.icon_url, ctx.logo_hashes)
        logo_match = logo_score >= s.logo_match_threshold

        evidence = [EvidenceItem("metadata", meta={k: v for k, v in li.__dict__.items()})]
        if icon_bytes:
            evidence.append(EvidenceItem("image", data=icon_bytes, content_type=icon_type,
                                         meta={"url": li.icon_url, "logo_match_score": logo_score}))
        file_sha, manifest, signers = None, {}, SignerInfo()
        if li.download_url:
            r = try_fetch(li.download_url, max_bytes=s.fetch_max_apk_bytes)
            if not (r and r.status == 200 and r.content):
                self.report.failed(DOWNLOAD, f"{li.download_url}: file could not be downloaded", failed=1)
            else:
                self.report.ok(DOWNLOAD, downloaded=1)
            if r and r.status == 200 and r.content:
                file_sha = sha256(r.content)
                manifest = read_manifest(r.content)
                signers = read_signers(r.content)
                evidence.append(EvidenceItem("file", data=r.content, content_type="application/vnd.android.package-archive",
                                             name=(urlsplit(li.download_url).path.rsplit("/", 1)[-1] or "app.apk"),
                                             meta={"url": li.download_url, "sha256": file_sha, "manifest": manifest,
                                                   "signers": signers.__dict__,
                                                   "warning": "Untrusted file. Do not install or open."}))
                pkg = pkg or (manifest.get("package") or "").lower()

        # D-26 signer verdict: None = not checked (no file or no official signer on record)
        signer_match: bool | None = None
        if signers.signed and ctx.official_signers:
            signer_match = bool(set(signers.fingerprints) & set(ctx.official_signers))
            if signer_match:
                return None  # signed with the company's key: the genuine app, whatever the mirror calls it
        publisher_mismatch = (not official_dev) or signer_match is False
        repackaged = official_pkg and signer_match is False

        signals = Signals(brand_exact_in_domain=pkg_brand or repackaged, typo_similarity=similarity,
                          official_logo=logo_match, publisher_mismatch=publisher_mismatch)
        details = {
            "App Name": li.title,
            "Package Name": pkg or None,
            "Similarity Score": round(similarity),
            "Source": li.listing_url,
            "Logo Match": logo_match,
            "Version": li.version or manifest.get("version"),
            "Developer": li.developer,
            "SHA256": file_sha,
            "Logo Match Score": round(logo_score) if logo_score else None,
            "Package Similarity": round(pkg_sim) if pkg else None,
            "Name Similarity": round(name_sim),
            "Official Package": official_pkg,
            "Suspicious Developer": not official_dev,
            "Repository": li.site,
            "Manifest": json.dumps(manifest) if manifest else None,
            "Signed By": "; ".join(signers.subjects) or None,
            "Signer SHA-256": ", ".join(signers.fingerprints) or None,
            "Signature Schemes": ", ".join(signers.schemes) or None,
            "Signer Matches Official": signer_match,
            "Store Signer": li.store_signer,
            "Discovered Via": li.discovered_via,
        }
        if repackaged:
            why = "official package re-signed with a different key"
        elif official_pkg:
            why = "copy of the official package"
        else:
            why = "look-alike app"
        return Detection(entity_key=f"{li.site}:{pkg or li.listing_url}", title=f"Fake APK ({why}): {li.title}",
                       signals=signals, details=details, similarity=similarity, source_url=li.listing_url,
                       evidence=evidence, state={"logo_match": logo_match, "signer_mismatch": signer_match is False
                                                 if signer_match is not None else None},
                       analysed=bool(logo_match or repackaged or file_sha))  # D-33: name match only = Candidate
