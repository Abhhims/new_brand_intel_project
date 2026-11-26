"""Every external tool and service the platform depends on, whether it is configured, and how it last ran (RDA-03).

Only integrations that exist in the code are listed. "Last result" comes from real evidence of a run: the newest
scan component with a matching name, or — for the email tools — the newest analysed email. An integration that has
never run reports `None` (unknown), never "ok".
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.core import search
from app.db.models import EmailMessage, ScanRun


@dataclass(frozen=True)
class Integration:
    id: str
    name: str
    category: str
    modules: tuple[str, ...]
    configured: Callable[[Settings], bool]
    how_to_configure: str
    components: tuple[str, ...] = ()  # scan component names (prefix match) that report this integration
    email_tool: str | None = None     # tool id in EmailMessage.auth["not_checked"]


def _always(_: Settings) -> bool:
    return True


REGISTRY: tuple[Integration, ...] = (
    Integration("web_search", "Web search", "Discovery", ("Fake APK", "Social", "Social media", "Documents"),
                lambda s: bool(s.brave_search_api_key or s.serpapi_api_key or s.free_search_fallback),
                "Set BRAVE_SEARCH_API_KEY (recommended) or SERPAPI_API_KEY; FREE_SEARCH_FALLBACK=true uses "
                "DuckDuckGo, which rate-limits", components=("Web search",)),
    Integration("crtsh", "Certificate Transparency (crt.sh)", "Discovery", ("Domains",), _always,
                "No key needed (public service)", components=("Certificate Transparency",)),
    Integration("dns", "DNS resolvers (1.1.1.1, 8.8.8.8, 9.9.9.9)", "Discovery", ("Domains", "Email posture"),
                _always, "No key needed", components=("DNS resolution", "DNS TXT lookups")),
    Integration("rdap", "WHOIS / RDAP", "Discovery", ("Domains",), _always, "No key needed (registry RDAP servers)",
                components=("WHOIS/RDAP",)),
    Integration("google_play", "Google Play (google-play-scraper)", "Discovery", ("Rogue apps",), _always,
                "No key needed", components=("Google Play search",)),
    Integration("apple_app_store", "Apple App Store (iTunes Search API)", "Discovery", ("Rogue apps",), _always,
                "No key needed (Apple's free official search API)", components=("Apple App Store search",)),
    Integration("aptoide", "Aptoide store API", "Discovery", ("Fake APK",), _always,
                "No key needed (public API)", components=("Aptoide store search",)),
    Integration("apkmirror", "APKMirror search", "Discovery", ("Fake APK",), _always,
                "No key needed", components=("APKMirror search",)),
    Integration("common_crawl", "Common Crawl (web archive index)", "Discovery", ("Fake APK", "Domains"),
                lambda s: bool(s.common_crawl_enabled),
                "No key needed. COMMON_CRAWL_ENABLED, COMMON_CRAWL_COLLECTIONS, COMMON_CRAWL_BUDGET_SECONDS",
                components=("Common Crawl index", "Common Crawl hostnames")),
    Integration("phishing_feeds", "Phishing feeds (PhishTank, OpenPhish, Phishing.Database, Phishing Army, "
                "Phishunt)", "Discovery", ("Domains",), _always, "No key needed (public feeds)",
                components=("Phishing feeds",)),
    Integration("urlscan_search", "urlscan.io hostname search", "Discovery", ("Domains",),
                lambda s: bool(s.urlscan_api_key), "Set URLSCAN_API_KEY", components=("urlscan.io search",)),
    Integration("certstream", "CertStream (live new certificates)", "Discovery", ("Domains",),
                lambda s: bool(s.certstream_url),
                "No key needed. Start: docker compose --profile app --profile certstream up -d",
                components=("CertStream",)),
    Integration("telegram_api", "Telegram search API (Telethon)", "Discovery", ("Social",),
                lambda s: bool(s.telegram_api_id and s.telegram_api_hash and s.telegram_session),
                "Set TELEGRAM_API_ID, TELEGRAM_API_HASH and TELEGRAM_SESSION (python -m scripts.telegram_login)",
                components=("Telegram API",)),
    Integration("telegram_public", "Telegram public pages (t.me)", "Discovery", ("Social",),
                lambda s: bool(s.telegram_public_fallback), "TELEGRAM_PUBLIC_FALLBACK=true",
                components=("Telegram public pages",)),
    Integration("youtube", "YouTube Data API", "Social media", ("Social media",), lambda s: bool(s.youtube_api_key),
                "Set YOUTUBE_API_KEY (Google Cloud console, YouTube Data API v3; free 10,000 units/day)",
                components=("YouTube API",)),
    Integration("meta_ads", "Meta Ad Library API", "Social media", ("Social media",),
                lambda s: bool(s.meta_ad_library_token or s.meta_graph_token),
                "Set META_AD_LIBRARY_TOKEN (facebook.com/ads/library/api, identity verification). Returns commercial "
                "ads only when shown in the EU/UK; political/issue ads worldwide. META_AD_COUNTRIES sets countries",
                components=("Meta Ad Library",)),
    Integration("facebook_pages", "Facebook Pages search (Graph API)", "Social media", ("Social media",),
                lambda s: bool(s.meta_graph_token or (s.meta_app_id and s.meta_app_secret)),
                "Set META_APP_ID and META_APP_SECRET (developers.facebook.com > your app > Settings > Basic). The "
                "app needs the 'Page Public Content Access' feature approved in App Review",
                components=("Facebook Pages API",)),
    Integration("threads", "Threads keyword search API", "Social media", ("Social media",),
                lambda s: bool(s.threads_access_token),
                "Set THREADS_ACCESS_TOKEN (Meta app with threads_keyword_search approval)",
                components=("Threads API",)),
    Integration("x_api", "X (Twitter) API", "Social media", ("Social media",), lambda s: bool(s.x_bearer_token),
                "Set X_BEARER_TOKEN (developer.x.com, paid pay-per-use)", components=("X API",)),
    Integration("telegram_search", "Telegram post search (Telethon)", "Social media", ("Social media",),
                lambda s: bool(s.telegram_api_id and s.telegram_api_hash and s.telegram_session),
                "Uses the TELEGRAM_* keys (see Telegram search API)", components=("Telegram post search",)),
    *(Integration(f"apify_{key}", f"Apify - {label}", "Social media", modules,
                  lambda s, k=key: bool(s.apify_token) and k in s.apify_platforms,
                  f"Set APIFY_TOKEN (console.apify.com > Settings > API & Integrations; paid per result) and keep "
                  f"'{key}' in APIFY_PLATFORMS. Actor: APIFY_ACTOR_{key.upper()}", components=components)
      for key, label, modules, components in (
          ("instagram", "Instagram posts & profiles", ("Social media", "Social"), ("Apify Instagram",)),
          ("tiktok", "TikTok videos & profiles", ("Social media", "Social"), ("Apify TikTok",)),
          ("facebook", "Facebook post search", ("Social media", "Social"), ("Apify Facebook posts",)),
          ("meta_ads", "Meta Ad Library", ("Social media", "Social"), ("Apify Meta ads",)),
          ("x", "X (Twitter) search", ("Social media", "Social"), ("Apify X",)),
          ("linkedin", "LinkedIn post search", ("Social media", "Social"), ("Apify LinkedIn",)))),
    Integration("browser", "Headless browser (Playwright / Chromium)", "Analysis", ("Domains", "Logo", "Social"),
                _always, "Runs in the browser-worker container",
                components=("Website probe & browser capture", "Browser capture")),
    Integration("rspamd", "Rspamd", "Email analysis", ("Phishing email",), lambda s: bool(s.rspamd_url),
                "RSPAMD_URL (rspamd container)", email_tool="rspamd"),
    Integration("clamav", "ClamAV", "Email analysis", ("Phishing email",), lambda s: bool(s.clamav_enabled),
                "CLAMAV_ENABLED, CLAMAV_HOST, CLAMAV_PORT (clamav container)", email_tool="clamav"),
    Integration("yara", "YARA rules", "Email analysis", ("Phishing email",), lambda s: bool(s.yara_rules_dir),
                "YARA_RULES_DIR", email_tool="yara"),
    Integration("urlhaus", "URLhaus (abuse.ch)", "Threat intelligence", ("Phishing email", "Domains"),
                lambda s: bool(s.urlhaus_auth_key), "Set URLHAUS_AUTH_KEY (free abuse.ch account)",
                email_tool="urlhaus"),
    Integration("openphish", "OpenPhish feed", "Threat intelligence", ("Phishing email", "Domains"),
                lambda s: bool(s.openphish_feed_url), "OPENPHISH_FEED_URL (public feed by default)",
                email_tool="openphish"),
    Integration("urlscan", "urlscan.io", "Threat intelligence", ("Phishing email", "Domains"),
                lambda s: bool(s.urlscan_api_key), "Set URLSCAN_API_KEY", email_tool="urlscan"),
    Integration("abuseipdb", "AbuseIPDB", "Threat intelligence", ("Phishing email",),
                lambda s: bool(s.abuseipdb_api_key), "Set ABUSEIPDB_API_KEY", email_tool="abuseipdb"),
    Integration("imap_reports", "Reporting mailbox (IMAP)", "Email intake", ("Phishing email",),
                lambda s: bool(s.imap_host and s.imap_user and s.imap_password),
                "Set IMAP_HOST, IMAP_USER, IMAP_PASSWORD"),
    Integration("dmarc_mailbox", "DMARC report mailbox (IMAP)", "Email intake", ("DMARC reports",),
                lambda s: bool(s.dmarc_imap_host and s.dmarc_imap_user and s.dmarc_imap_password),
                "Set DMARC_IMAP_HOST, DMARC_IMAP_USER, DMARC_IMAP_PASSWORD"),
    Integration("ms_graph", "Microsoft 365 mailbox (Graph)", "Email intake", ("Phishing email",),
                lambda s: bool(s.ms_graph_tenant and s.ms_graph_client_id and s.ms_graph_client_secret),
                "Set MS_GRAPH_TENANT, MS_GRAPH_CLIENT_ID, MS_GRAPH_CLIENT_SECRET, MS_GRAPH_USER"),
    Integration("gmail", "Gmail mailbox", "Email intake", ("Phishing email",),
                lambda s: bool(s.gmail_service_account_json and s.gmail_delegated_user),
                "Set GMAIL_SERVICE_ACCOUNT_JSON and GMAIL_DELEGATED_USER"),
)

RECENT_RUNS = 200  # how far back to look for the latest component of each integration


def _latest_components(db: Session) -> list[tuple[datetime | None, dict]]:
    runs = db.scalars(select(ScanRun).where(ScanRun.finished_at.is_not(None))
                      .order_by(ScanRun.finished_at.desc()).limit(RECENT_RUNS)).all()
    return [(r.finished_at, c) for r in runs for c in (r.components or [])]


def status_list(db: Session) -> list[dict]:
    s = get_settings()
    components = _latest_components(db)
    email = db.scalar(select(EmailMessage).where(EmailMessage.status == "analysed")
                      .order_by(EmailMessage.analysed_at.desc().nulls_last(), EmailMessage.received_at.desc()).limit(1))
    out = []
    for i in REGISTRY:
        last_status = last_message = last_at = None
        match = next(((at, c) for at, c in components if any(c["name"].startswith(p) for p in i.components)), None)
        if match:
            last_at, c = match
            last_status, last_message = c["status"], c.get("message") or None
        elif i.email_tool and email is not None:
            missed = [n for n in (email.auth or {}).get("not_checked", []) if n.get("tool") == i.email_tool]
            last_status = "unavailable" if missed else "ok"
            last_message = f"not checked: {missed[0].get('target')}" if missed else None
            last_at = email.analysed_at or email.received_at
        name = f"{i.name} - {search.provider_name()}" if i.id == "web_search" else i.name
        out.append({"id": i.id, "name": name, "category": i.category, "modules": list(i.modules),
                    "configured": i.configured(s), "how_to_configure": i.how_to_configure,
                    "last_status": last_status, "last_message": last_message, "last_checked_at": last_at})
    return out
