"""Threat intelligence for look-alike domains (D-46): is the domain already listed as phishing / malware?

Three independent sources, the same ones the email module uses for links (app/modules/email/intel.py):
- OpenPhish community feed (no key): any listed URL on the domain or one of its subdomains;
- urlscan.io (URLSCAN_API_KEY): one of the latest public scans of the domain has a malicious verdict;
- URLhaus (URLHAUS_AUTH_KEY): the host is listed for malware distribution.
No key → that source is `not_checked`, never "clean". Only >= 2 distinct sources count as corroborated.
"""

from __future__ import annotations

import json
from urllib.parse import quote, urlsplit

from app.config import get_settings
from app.core.fetch import FetchError, fetch
from app.modules.email import intel
from app.modules.email.model import ToolVerdict

SOURCES = {"openphish": "OpenPhish", "urlscan": "urlscan.io", "urlhaus": "URLhaus"}
KEYS = {"urlscan": "URLSCAN_API_KEY", "urlhaus": "URLHAUS_AUTH_KEY"}
MAX_EXAMPLES = 5
URLSCAN_SCANS = 3  # latest public scans of a domain whose verdicts are read


def _on_domain(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


def openphish_domain(domain: str) -> ToolVerdict:
    feed = intel._openphish_set()
    if not feed:
        return ToolVerdict("openphish", status="not_checked", details={"reason": "feed unavailable"},
                           checked_at=intel._now())
    urls = sorted(u for u in feed if _on_domain((urlsplit(u).hostname or "").lower(), domain))
    return ToolVerdict("openphish", status="ok", malicious=bool(urls),
                       details={"urls": urls[:MAX_EXAMPLES], "listed": len(urls)} if urls else {},
                       checked_at=intel._now())


def urlscan_domain(domain: str) -> ToolVerdict:
    key = get_settings().urlscan_api_key
    if not key:
        return ToolVerdict("urlscan", status="not_checked", checked_at=intel._now())

    def call() -> ToolVerdict:
        # Free plans cannot search on verdicts, so: the domain's latest public scans, then each scan's verdict
        headers = {"API-Key": key}
        q = quote(f'page.domain:"{domain}"')
        try:
            r = fetch(f"https://urlscan.io/api/v1/search/?q={q}&size={URLSCAN_SCANS}", headers=headers)
            if r.status != 200:
                return ToolVerdict("urlscan", status="not_checked", details={"http": r.status},
                                   checked_at=intel._now())
            scans = []
            for x in json.loads(r.content or b"{}").get("results", [])[:URLSCAN_SCANS]:
                uuid = x.get("_id") or (x.get("task") or {}).get("uuid")
                res = fetch(f"https://urlscan.io/api/v1/result/{quote(str(uuid))}/", headers=headers)
                if res.status != 200:
                    continue  # result not stored (yet): this scan says nothing
                overall = (json.loads(res.content or b"{}").get("verdicts") or {}).get("overall") or {}
                scans.append({"url": (x.get("page") or {}).get("url"), "scanned": (x.get("task") or {}).get("time"),
                              "malicious": bool(overall.get("malicious")), "score": overall.get("score"),
                              "uuid": uuid})
        except FetchError as exc:
            return ToolVerdict("urlscan", status="not_checked", details={"reason": str(exc)[:120]},
                               checked_at=intel._now())
        bad = [x for x in scans if x["malicious"]]
        return ToolVerdict("urlscan", status="ok", malicious=bool(bad),
                           details={"scans": (bad or scans)[:MAX_EXAMPLES]} if scans else {}, checked_at=intel._now())

    return intel._cached("urlscan_domain", domain, call)


def urlhaus_host(domain: str) -> ToolVerdict:
    key = get_settings().urlhaus_auth_key
    if not key:
        return ToolVerdict("urlhaus", status="not_checked", checked_at=intel._now())

    def call() -> ToolVerdict:
        try:
            r = fetch("https://urlhaus-api.abuse.ch/v1/host/", method="POST", content=f"host={quote(domain)}".encode(),
                      headers={"Auth-Key": key, "Content-Type": "application/x-www-form-urlencoded"})
        except FetchError as exc:
            return ToolVerdict("urlhaus", status="not_checked", details={"reason": str(exc)[:120]},
                               checked_at=intel._now())
        try:
            data = json.loads(r.content or b"{}")
        except ValueError:
            data = {}
        if r.status != 200:  # e.g. 403 {"query_status": "unknown_auth_key"}
            return ToolVerdict("urlhaus", status="not_checked",
                               details={"http": r.status, "reason": data.get("query_status")}, checked_at=intel._now())
        if data.get("query_status") not in ("ok", "no_results"):
            return ToolVerdict("urlhaus", status="not_checked", details={"reason": data.get("query_status")},
                               checked_at=intel._now())
        listed = data.get("query_status") == "ok"
        details = {"url_count": data.get("url_count"), "first_seen": data.get("firstseen"),
                   "urls": [u.get("url") for u in (data.get("urls") or [])[:MAX_EXAMPLES]]} if listed else {}
        return ToolVerdict("urlhaus", status="ok", malicious=listed, details=details, checked_at=intel._now())

    return intel._cached("urlhaus_host", domain, call)


def domain_reputation(domain: str) -> list[ToolVerdict]:
    return [openphish_domain(domain), urlscan_domain(domain), urlhaus_host(domain)]


def summary(verdicts: list[ToolVerdict]) -> str:
    """One line for analysts: who lists it, and what could not be checked."""
    listed = [SOURCES[v.tool] for v in verdicts if v.malicious]
    checked = [SOURCES[v.tool] for v in verdicts if v.status == "ok"]
    unchecked = [SOURCES[v.tool] for v in verdicts if v.status != "ok"]
    if listed:
        text = f"Listed by {', '.join(listed)}"
    elif checked:
        text = f"Not listed by {', '.join(checked)}"
    else:
        text = "Not checked"
    return text + (f" (not checked: {', '.join(unchecked)})" if unchecked and (listed or checked) else "")
