"""Rogue mobile app monitoring on Google Play and the Apple App Store (§3.3, ROG-01…06, D-13, D-41).

Searches both stores for every brand keyword and product term (Google Play in English and Hindi), ignores apps from
approved publishers, flags apps that use the brand name, product terms or logo, then reads each flagged app's detail
page (developer e-mail, website, address, installs, version, update date, full description), checks the
description for fake contact details and scam wording, takes a screenshot of the store page, and tracks each
listing's state over time (new / updated / removed — ROG-05) in app_listings.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from urllib.parse import urlencode

import structlog
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.core.browser import capture
from app.core.evidence import EvidenceItem
from app.core.fetch import try_fetch
from app.core.findings import mark_state
from app.core.scoring import Signals
from app.core.similarity import best_similarity
from app.db.models import AppListing, ModuleName
from app.modules.base import BrandContext, Detection, ScanReport
from app.modules.common import image_match, literal_brand_in
from app.modules.social_media.analysis import SCORED_CONTACTS, contact_details, scam_phrases, strong_phrases

log = structlog.get_logger(__name__)

STORE = "Google Play"
APPLE = "Apple App Store"
PLAY = "Google Play search"
APPLE_SEARCH = "Apple App Store search"
DETAILS = "Store detail pages"
CAPTURE = "Browser capture (app stores)"
FREEMAIL = ("gmail.com", "yahoo.com", "yahoo.co.in", "hotmail.com", "outlook.com", "rediffmail.com", "proton.me",
            "protonmail.com", "icloud.com", "aol.com", "mail.com", "yandex.com", "zoho.com", "gmx.com")
KEY_PREFIX = {STORE: "play", APPLE: "appstore"}
LOOKALIKE_MIN = 90


class LivePlaySource:
    """google-play-scraper talks only to play.google.com (a fixed, trusted endpoint), so it is the one
    documented exception to routing through the safe fetcher; icons are still fetched safely."""

    def search(self, ctx: BrandContext, report: ScanReport) -> list[dict]:
        import google_play_scraper

        s = get_settings()
        out: dict[str, dict] = {}
        terms = list(dict.fromkeys(ctx.terms + ctx.product_terms))[:8]
        failures = attempts = 0
        for term in terms:
            for lang in s.play_store_langs:
                attempts += 1
                for attempt in range(3):  # transient network errors (e.g. IPv6 route flaps) are retried
                    try:
                        for r in google_play_scraper.search(term, lang=lang, country=s.play_store_country,
                                                            n_hits=s.play_store_hits):
                            if r.get("appId"):
                                r.setdefault("url", f"https://play.google.com/store/apps/details?id={r['appId']}")
                                out.setdefault(r["appId"], r)
                        report.ok(PLAY, terms=1)
                        break
                    except Exception as exc:  # noqa: BLE001
                        if attempt == 2:
                            failures += 1
                            report.failed(PLAY, f"search failed for '{term}' ({lang}): {type(exc).__name__}: {exc}",
                                          failed=1)
                        else:
                            time.sleep(3 * (attempt + 1))
        if attempts and failures == attempts:
            log.info("play_search_all_failed", attempts=attempts)
        return list(out.values())

    def details(self, app_id: str) -> dict:
        import google_play_scraper

        s = get_settings()
        return google_play_scraper.app(app_id, lang="en", country=s.play_store_country)


class LiveAppleSource:
    """Apple's free, official iTunes Search API (no key). Results are normalised to the Play field names."""

    def search(self, ctx: BrandContext, report: ScanReport) -> list[dict]:
        s = get_settings()
        out: dict[str, dict] = {}
        for term in list(dict.fromkeys(ctx.terms + ctx.product_terms))[:6]:
            r = try_fetch("https://itunes.apple.com/search?" + urlencode({
                "term": term, "country": s.play_store_country, "entity": "software", "limit": 50}))
            if not (r and r.status == 200):
                report.unavailable(APPLE_SEARCH, f"search '{term}': {'no response' if not r else f'HTTP {r.status}'}")
                continue
            try:
                results = json.loads(r.content).get("results", [])
            except ValueError:
                report.failed(APPLE_SEARCH, f"search '{term}': unreadable response")
                continue
            report.ok(APPLE_SEARCH, terms=1, results=len(results))
            for a in results:
                bundle = a.get("bundleId")
                if not bundle:
                    continue
                out.setdefault(bundle, {
                    "store": APPLE, "appId": bundle, "title": a.get("trackName", ""),
                    "developer": a.get("sellerName") or a.get("artistName"), "description": a.get("description"),
                    "summary": "", "icon": a.get("artworkUrl512") or a.get("artworkUrl100"),
                    "url": a.get("trackViewUrl"), "version": a.get("version"),
                    "updated": a.get("currentVersionReleaseDate"), "released": a.get("releaseDate"),
                    "score": a.get("averageUserRating"), "ratings": a.get("userRatingCount"),
                    "developerWebsite": a.get("sellerUrl"), "genre": a.get("primaryGenreName"),
                    "price": a.get("formattedPrice"), "installs": None, "details_loaded": True})
        return list(out.values())


class RogueAppModule:
    name = ModuleName.rogue_app

    def __init__(self, source=None, apple_source=None, capture_fn: Callable | None = None) -> None:
        self._source = source
        live = source is None
        # live runs search both stores and screenshot flagged listings; injected (test) sources stay offline
        self._apple = apple_source if apple_source is not None else (LiveAppleSource() if live else None)
        self._capture = capture_fn if capture_fn is not None else (capture if live else None)
        self.stats: dict = {}
        self.report = ScanReport()

    def run(self, ctx: BrandContext, db: Session) -> Iterator[Detection]:
        source = self._source or LivePlaySource()
        play = [dict(r, store=r.get("store", STORE)) for r in source.search(ctx, self.report)]
        apple = self._apple.search(ctx, self.report) if self._apple else []
        comps = self.report.as_list()
        play_failed = any(c["name"] == PLAY and c["status"] != "ok" for c in comps)
        if not any(c["name"] in (PLAY, APPLE_SEARCH) and c["status"] == "ok" for c in comps):
            # neither store could be searched: this run cannot claim "no rogue apps" (D-31)
            self.report.failed("App store searches", "no app store could be searched", fatal=True)
        self.stats.update(apps_checked=len(play) + len(apple), play_apps=len(play), apple_apps=len(apple), flagged=0,
                          apps_new=0, apps_updated=0, apps_removed=0, details_read=0)
        seen: dict[str, set[str]] = {STORE: set(), APPLE: set()}
        for app in play + apple:
            pkg = app.get("appId")
            if not pkg:
                continue
            seen[app["store"]].add(pkg)
            try:
                finding = self.analyse(ctx, db, app, source)
            except Exception as exc:  # noqa: BLE001
                self.report.failed("Listing analysis", f"{pkg}: {type(exc).__name__}: {exc}", failed=1)
                continue
            if finding:
                self.stats["flagged"] += 1
                yield finding
        # Only judge removals when every search of that store worked; a failed search would make apps look "removed"
        if play and not play_failed:
            self._mark_removed(ctx, db, STORE, seen[STORE])
            self.report.ok("Removal check")
        elif play:
            self.stats["removal_check"] = "skipped (a store search failed this run)"
            self.report.skipped("Removal check", "a store search failed this run, so missing apps are not "
                                                 "marked removed")
        apple_failed = any(c["name"] == APPLE_SEARCH and c["status"] != "ok" for c in self.report.as_list())
        if apple and not apple_failed:
            self._mark_removed(ctx, db, APPLE, seen[APPLE])

    def _track(self, ctx: BrandContext, db: Session, app: dict) -> str:
        now = datetime.now(UTC)
        store = app.get("store", STORE)
        row = db.scalar(select(AppListing).where(AppListing.brand_id == ctx.id, AppListing.store == store,
                                                 AppListing.package == app["appId"]))
        version, updated = str(app.get("version") or ""), str(app.get("updated") or "")
        if row is None:
            db.add(AppListing(brand_id=ctx.id, store=store, package=app["appId"], title=app.get("title", ""),
                              publisher=app.get("developer"), installs=app.get("installs"), version=version,
                              updated=updated, state="new", first_seen=now, last_seen=now))
            self.stats["apps_new"] += 1
            return "New"
        changed = (version and row.version != version) or (updated and row.updated != updated)
        state = "updated" if changed or row.state == "removed" else "unchanged"
        row.title, row.publisher = app.get("title", row.title), app.get("developer") or row.publisher
        row.installs = app.get("installs") or row.installs
        row.version, row.updated = version or row.version, updated or row.updated
        row.state, row.last_seen = state, now
        if state == "updated":
            self.stats["apps_updated"] += 1
        return {"updated": "Updated", "unchanged": "Unchanged"}[state]

    def _mark_removed(self, ctx: BrandContext, db: Session, store: str, seen: set[str]) -> None:
        rows = db.scalars(select(AppListing).where(AppListing.brand_id == ctx.id, AppListing.store == store,
                                                   AppListing.state != "removed")).all()
        for row in rows:
            if row.package in seen:
                continue
            row.state = "removed"
            self.stats["apps_removed"] += 1
            mark_state(db, ctx.id, ModuleName.rogue_app, f"{KEY_PREFIX[store]}:{row.package}", {"listed": False},
                       f"App no longer listed on {store}", kind="app_status")
        db.flush()

    def _details(self, app: dict, source) -> dict:
        """Full store page for a flagged Google Play app (developer contact, installs, version, description)."""
        if app.get("details_loaded") or not hasattr(source, "details"):
            return app
        try:
            d = source.details(app["appId"]) or {}
            self.report.ok(DETAILS, read=1)
            self.stats["details_read"] += 1
            return {**app, **{k: v for k, v in d.items() if v not in (None, "", [])}, "details_loaded": True}
        except Exception as exc:  # noqa: BLE001 - search data is still used; recorded, never hidden
            self.report.failed(DETAILS, f"{app['appId']}: {type(exc).__name__}: {str(exc)[:120]}", failed=1)
            return app

    def analyse(self, ctx: BrandContext, db: Session, app: dict, source=None) -> Detection | None:
        s = get_settings()
        store = app.get("store", STORE)
        publisher = (app.get("developer") or "").strip()
        if publisher.lower() in {p.lower() for p in ctx.official_publishers} \
                or app["appId"].lower() in ctx.official_packages:
            self._track(ctx, db, app)
            return None  # approved publisher / official app (ROG-03)
        title = app.get("title") or ""
        # Relevance from the listing's identity only: long descriptions mention addresses and partners
        # ("Navi Mumbai", "pay with Paytm, Navi…"), which made unrelated apps look like the brand (live, 2026-10-12)
        identity = " ".join(str(app.get(k) or "") for k in ("title", "summary", "developer"))
        identity += " " + str(app.get("appId") or "").replace(".", " ")
        rel = ctx.relevance(identity, name=title)  # D-25: short abbreviations need context
        logo_score, icon, icon_type = image_match(app.get("icon"), ctx.logo_hashes)
        logo_match = logo_score >= s.logo_match_threshold
        # Store listings: the brand's core name must appear, or the title must be a very close look-alike of a long
        # brand name. Fuzzy matches of multi-word product terms ("UPI Payments" ~ "Navi UPI") are not enough.
        core = re.sub(r"[^a-z0-9]", "", min(ctx.terms[:3] or [ctx.name], key=len).lower())
        flat_identity = re.sub(r"[^a-z0-9]", "", identity.lower())
        long_terms = [t for t in ctx.strong_terms if len(re.sub(r"[^a-z0-9]", "", t)) >= 8 and " " not in t.strip()]
        lookalike = bool(long_terms) and best_similarity(title, long_terms)[0] >= LOOKALIKE_MIN
        brand_present = bool(core) and core in flat_identity
        if not ((rel.relevant and (brand_present or lookalike)) or logo_match):
            self._track(ctx, db, app)
            return None  # not using the brand (ROG-04)

        app = self._details(app, source or self._source)
        status = self._track(ctx, db, app)
        text = " ".join(str(app.get(k) or "") for k in ("title", "summary", "description"))
        contacts = {k: v for k, v in contact_details(text).items() if k in SCORED_CONTACTS}
        phrases = scam_phrases(text)
        strong = strong_phrases(phrases)
        dev_email = (app.get("developerEmail") or "").strip()
        freemail = bool(dev_email) and dev_email.lower().rsplit("@", 1)[-1] in FREEMAIL

        terms_used = rel.terms_used
        similarity = 100.0 if rel.strong_hits and literal_brand_in(title, rel.strong_hits) else rel.similarity
        exact = literal_brand_in(title, ctx.strong_terms) or bool(rel.weak_hits and rel.context_hits
                                                                   and literal_brand_in(title, rel.weak_hits))
        signals = Signals(brand_exact_in_domain=exact, typo_similarity=similarity, official_logo=logo_match,
                          publisher_mismatch=True, scam_contact_details=bool(contacts), scam_language=bool(strong))
        updated = app.get("updated")
        details = {
            "Store": store,
            "App Name": title,
            "Publisher": publisher or None,
            "Official Publisher Match": False,
            "Install Count": app.get("installs"),
            "Package Name": app["appId"],
            "App Status": status,
            "Similarity Score": round(similarity),
            "Logo Match": logo_match,
            "Brand Terms Used": terms_used,
            "Store URL": app.get("url"),
            "Last Updated": datetime.fromtimestamp(int(updated), UTC).date().isoformat()
            if str(updated or "").isdigit() else (str(updated)[:10] if updated else None),
            "Version": app.get("version"),
            "Rating": app.get("score"),
            "Ratings Count": app.get("ratings"),
            "Released": app.get("released"),
            "Developer Email": dev_email or None,
            "Developer Uses Free E-mail": freemail if dev_email else None,
            "Developer Website": app.get("developerWebsite"),
            "Developer Address": app.get("developerAddress"),
            "Privacy Policy": app.get("privacyPolicy"),
            "Category": app.get("genre"),
            "Scam Contacts": [f"{k}: {v}" for k, vs in contacts.items() for v in vs],
            "Scam Phrases": phrases,
            "Description Excerpt": (app.get("description") or "")[:600],
        }
        evidence = [EvidenceItem("metadata", meta={k: v for k, v in app.items()
                                                   if isinstance(v, str | int | float | bool) and k != "descriptionHTML"})]
        if icon:
            evidence.append(EvidenceItem("image", data=icon, content_type=icon_type,
                                         meta={"url": app.get("icon"), "logo_match_score": logo_score}))
        if self._capture and app.get("url"):
            try:
                cap = self._capture(app["url"], full_page=False)
                if cap.screenshot:
                    evidence.append(EvidenceItem("screenshot", data=cap.screenshot, content_type="image/png",
                                                 meta={"url": app["url"], "final_url": cap.final_url,
                                                       "status": cap.status}))
                    self.report.ok(CAPTURE, captured=1)
                else:
                    self.report.failed(CAPTURE, f"{app['url']}: {cap.error or 'no screenshot'}"[:200], failed=1)
            except Exception as exc:  # noqa: BLE001
                self.report.failed(CAPTURE, f"{app['url']}: {type(exc).__name__}: {str(exc)[:120]}", failed=1)
        why = [w for w, on in (("fake contact details", contacts), ("scam wording", strong),
                               ("developer uses free e-mail", freemail), ("copies the logo", logo_match)) if on]
        return Detection(
            entity_key=f"{KEY_PREFIX.get(store, 'play')}:{app['appId']}",
            title=f"Unauthorized app on {store}: {title}" + (f" ({', '.join(why)})" if why else ""),
            signals=signals, details=details, similarity=similarity, source_url=app.get("url"), evidence=evidence,
            state={"listed": True, "logo_match": logo_match},
            analysed=exact or logo_match or bool(contacts) or bool(strong),  # D-33: similarity alone = Candidate
        )
