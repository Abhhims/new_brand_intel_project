"""Application settings, loaded from environment variables / .env (see deploy/.env.example)."""

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env", "../.env", "../deploy/.env"), extra="ignore", env_ignore_empty=True
    )

    env: str = "development"  # development | test | production

    # Database / queue
    database_url: str = "postgresql+psycopg://brandintel:brandintel@localhost:5432/brandintel"
    redis_url: str = "redis://localhost:6379/0"

    # Object storage (MinIO / S3)
    s3_endpoint_url: str = "http://localhost:9000"
    s3_public_endpoint_url: str | None = None  # URL browsers use for presigned links, if different
    s3_access_key: str = "brandintel"
    s3_secret_key: str = "brandintel-secret"
    s3_bucket: str = "evidence"
    s3_region: str = "us-east-1"

    # Auth
    jwt_secret: str = "change-me-in-production"
    jwt_expire_minutes: int = 12 * 60
    bootstrap_admin_email: str = "admin@beyondcloud.local"
    bootstrap_admin_password: str = "ChangeMe!2026"

    # Web
    cors_origins: list[str] = ["http://localhost:3000"]

    # Safe fetcher
    fetch_timeout_seconds: float = 15.0
    fetch_max_bytes: int = 25 * 1024 * 1024
    fetch_max_apk_bytes: int = 150 * 1024 * 1024
    fetch_max_redirects: int = 5
    fetch_rate_per_host_per_minute: int = 30
    fetch_user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/153.0 Safari/537.36 BeyondCloudBrandIntel/1.0"
    )
    # Hosts that may resolve to private IPs (test fixtures website only). Never set in production.
    fetch_allow_private_hosts: list[str] = Field(default_factory=list)

    # Email analysis engines (isolated containers / in-process)
    rspamd_url: str = "http://rspamd:11333"
    clamav_host: str = "clamav"
    clamav_port: int = 3310
    clamav_enabled: bool = True
    yara_rules_dir: str = "rules/yara"
    # Email threat intelligence (all optional; no key -> that source is "not checked")
    urlhaus_auth_key: str | None = None
    urlscan_api_key: str | None = None
    abuseipdb_api_key: str | None = None
    openphish_feed_url: str = "https://openphish.com/feed.txt"

    # External sources
    brave_search_api_key: str | None = None
    serpapi_api_key: str | None = None
    # Without an API key, read DuckDuckGo's public results page, paced (see app/core/search.py, D-23)
    free_search_fallback: bool = True
    free_search_interval_seconds: float = 12.0
    # Without Telegram API credentials, check public t.me pages instead (D-23)
    telegram_public_fallback: bool = True
    telegram_api_id: int | None = None
    telegram_api_hash: str | None = None
    telegram_session: str | None = None  # StringSession, created once by scripts/telegram_login.py

    # Common Crawl as an extra APK source (D-42): slow, rate-limited public index — paced and time-boxed
    common_crawl_enabled: bool = True
    common_crawl_collections: int = 2        # newest monthly crawls to look in
    common_crawl_pace_seconds: float = 2.0
    common_crawl_budget_seconds: int = 240   # per brand and scan
    common_crawl_domain_budget_seconds: int = 300  # domain scan: hosting-platform hostnames from the index
    common_crawl_domain_max_pages: int = 400       # index pages per platform (each scan continues where cached)
    certstream_url: str = "ws://certstream:8080/domains-only"  # live certificate stream (certwatch service)
    certstream_retention_days: int = 90

    # Domain scans: website captures in parallel, and a time budget below the worker's 60-minute hard limit.
    # Domains not reached are reported and checked first on the next scan.
    domain_check_workers: int = 3
    domain_scan_budget_seconds: int = 45 * 60
    domain_discovery_max_hosts: int = 1500      # per extra discovery source (urlscan, feeds, search) and scan (D-51)
    urlscan_discovery_pages: int = 5            # 1,000 results per page

    # App stores (rogue apps, D-41): Google Play search languages/country and results per search
    play_store_langs: list[str] = ["en", "hi"]
    play_store_country: str = "in"
    play_store_hits: int = 30

    # Social media brand-misuse monitor (all optional; a source without a key reports "not configured")
    youtube_api_key: str | None = None          # YouTube Data API v3 (Google Cloud API key)
    meta_ad_library_token: str | None = None    # Meta Ad Library API access token (identity-verified account)
    meta_ad_countries: list[str] = ["IN"]       # ad_reached_countries for the Ad Library search
    # Facebook Pages search (Graph API). App ID + secret form an app access token; the app needs Meta's
    # "Page Public Content Access" feature. META_GRAPH_TOKEN (optional) overrides the app token.
    meta_app_id: str | None = None
    meta_app_secret: str | None = None
    meta_graph_token: str | None = None
    threads_access_token: str | None = None     # Threads API token with threads_keyword_search
    x_bearer_token: str | None = None           # X API v2 bearer token (paid, pay-per-use)
    social_media_lookback_days: int = 730       # only content published in the last N days (2 years)
    social_media_scam_lookback_days: int = 730  # scam-focused searches ("<brand> customer care number"…) look further back
    # Scam-focused searches per brand ("{brand}" is replaced by each brand name/term); each YouTube search = 100 units
    social_media_scam_queries: list[str] = ["{brand} customer care number", "{brand} helpline number",
                                            "{brand} kyc update", "{brand} loan fraud", "{brand} refund"]
    social_media_max_items: int = 60            # per scan and brand; each one gets a screenshot
    social_media_analysis_minutes: int = 40     # stop analysing after this, so the scan always ends and is saved
    # Apify actors (paid scrapers, D-43) for platforms without a usable official search API. Optional: without
    # APIFY_TOKEN every Apify source reports "not configured" and the official APIs + web search run as before.
    apify_token: str | None = None
    # instagram | tiktok | facebook | meta_ads | x | linkedin (YouTube always uses its official API)
    apify_platforms: list[str] = ["instagram", "tiktok", "facebook", "meta_ads", "x", "linkedin"]
    apify_items_per_query: int = 20             # results per search, per platform (Apify charges per result)
    apify_scam_queries: int = 3                 # how many of SOCIAL_MEDIA_SCAM_QUERIES also run on Apify
    apify_max_charge_usd: float = 0.5           # spending cap per actor run
    apify_run_timeout_seconds: int = 300        # a run still going after this is aborted; its results so far are kept
    apify_cache_minutes: int = 180              # identical searches (content + impersonation modules) run once
    apify_actor_instagram: str = "apify/instagram-scraper"                # account search (impersonation)
    apify_actor_instagram_posts: str = "apify/instagram-hashtag-scraper"  # keyword post search
    apify_actor_tiktok: str = "clockworks/tiktok-scraper"
    apify_actor_facebook: str = "scraper_one/facebook-posts-search"
    apify_actor_meta_ads: str = "apify/facebook-ads-scraper"
    apify_actor_x: str = "apidojo/tweet-scraper"
    apify_actor_linkedin: str = "harvestapi/linkedin-post-search"

    # Email intake (D-28). Reporting mailbox (forwarded phishing) and DMARC mailbox (aggregate reports).
    imap_host: str | None = None
    imap_port: int = 993
    imap_user: str | None = None
    imap_password: str | None = None
    imap_mailbox: str = "INBOX"
    dmarc_imap_host: str | None = None
    dmarc_imap_port: int = 993
    dmarc_imap_user: str | None = None
    dmarc_imap_password: str | None = None
    dmarc_imap_mailbox: str = "INBOX"
    # Microsoft 365 / Google Workspace intake (optional)
    ms_graph_tenant: str | None = None
    ms_graph_client_id: str | None = None
    ms_graph_client_secret: str | None = None
    ms_graph_user: str | None = None
    ms_graph_folder: str = "Inbox"
    gmail_service_account_json: str | None = None
    gmail_delegated_user: str | None = None
    gmail_label: str = "INBOX"
    # Posture scan cadence and DMARC mailbox polling
    email_posture_enabled: bool = True

    # Detection tuning
    typo_tlds: list[str] = ["com", "in", "net", "org", "co", "io", "uk", "us", "ae", "sg", "au"]
    logo_match_threshold: int = 85
    phishing_similarity_threshold: int = 80



INSECURE_DEFAULTS = {"jwt_secret": "change-me-in-production", "bootstrap_admin_password": "ChangeMe!2026",
                     "s3_secret_key": "brandintel-secret"}


def check_production(s: Settings) -> None:
    """Refuse to start in production with default secrets or a short JWT key."""
    if s.env != "production":
        return
    bad = [k for k, v in INSECURE_DEFAULTS.items() if getattr(s, k) == v]
    if len(s.jwt_secret) < 32:
        bad.append("jwt_secret (must be at least 32 characters)")
    if s.fetch_allow_private_hosts:
        bad.append("fetch_allow_private_hosts (must be empty in production)")
    if bad:
        raise RuntimeError("Insecure production configuration: " + ", ".join(bad))


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    check_production(s)
    return s
