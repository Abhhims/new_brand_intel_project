# Chapter 11 - Tools Reference

In this chapter:
- Every tool, library and external service the platform uses, grouped by job: infrastructure, web/API,
  discovery, analysis, email, reporting and frontend.
- For each one: what it is, what we use it for, where it lives in the code, why we chose it, what it costs,
  and what happens when it is missing or not configured.
- Libraries that are installed but not used by the code today.
- Tools we deliberately do not use, and why.

## 1. How to read this chapter

Each group has two tables:

- **Table A - What and where:** the tool, what it is in plain words, what we use it for, and the files that
  use it.
- **Table B - Why, cost and failure:** why we chose it (with rejected alternatives and decision IDs from
  `docs/decisions/DECISION-LOG.md`), its cost and licence, and what happens if it is unavailable or not
  configured.

Sources checked for this chapter: `backend/pyproject.toml`, `frontend/package.json`,
`deploy/docker-compose.yml`, `deploy/backend.Dockerfile`, `backend/app/config.py` and the module code.
Licences of Python libraries were read from the installed package metadata on 2026-10-09. "Internal use" means
Beyond Cloud runs the software on its own servers and does not sell or ship it to others.

A word on licences. **Permissive** licences (MIT, BSD, Apache-2.0, ISC, PSF) allow almost any use if the
copyright notice is kept. **Copyleft** licences (GPL, LGPL) also allow internal use freely, but add duties if
the software is distributed to other people. Nothing in this project is distributed today.

**Live status of every integration.** Since SP1 (2026-10-09, D-31) the dashboard's **Integrations** page
(`/integrations`, API `GET /api/v1/integrations`) lists every external tool and service the scans and email
analysis depend on: whether it is configured, how to configure it if not, and its last real result
(Completed, Not configured, Unavailable, Failed, or "Not run yet"). Each scan also lists the same tools as
components on the Scans page. Use those pages to see the current state; this chapter explains the tools.

Configuration keys in this chapter are environment variables, set in `deploy/.env` (copied from
`deploy/.env.example`). Chapter 12 explains them.

## 2. Infrastructure

### Table A - What and where

| Tool | What it is | What we use it for | Where |
|---|---|---|---|
| PostgreSQL 17 (`postgres:17-alpine`) | A relational database | Every record: users, brands, assets, allowlists, scans, findings, observations, alerts, evidence records, finding timeline events, domain checks, app listings, emails, DMARC reports | `deploy/docker-compose.yml` service `postgres`; `backend/app/db/models.py`, `backend/app/db/session.py` |
| psycopg 3 | The Python driver that talks to PostgreSQL | All database connections (`postgresql+psycopg://...`) | `backend/app/config.py` (`DATABASE_URL`), `backend/tests/conftest.py` |
| Redis 7 (`redis:7-alpine`) | An in-memory key-value store | Celery task queue and results; per-host rate limits for the safe fetcher; shared pacing and 15-minute pause of the free search; 24-hour cache of threat-intelligence answers | Service `redis`; `backend/app/workers/celery_app.py`, `backend/app/core/fetch.py`, `backend/app/core/search.py`, `backend/app/modules/email/intel.py` |
| redis (Python client) | The Python library for Redis | Rate limits, caches, search cooldown | Same files as above |
| Celery 5 | A background task system for Python | Runs scans on workers; `beat` starts scheduled scans; retries on infrastructure failure | `backend/app/workers/celery_app.py`, `tasks.py`, `scan.py`; services `worker`, `browser-worker`, `beat` |
| RustFS (`rustfs/rustfs`) | An S3-compatible object store (stores files like Amazon S3) | Evidence files and brand assets in bucket `evidence` | Service `minio` (the name was kept); `backend/app/core/evidence.py` |
| boto3 | Amazon's Python library for S3 | Upload, download and presigned links for evidence | `backend/app/core/evidence.py` |
| nginx (`nginx:alpine`) | A small web server | Serves the **test website** for automated tests only (profile `test`, port 8088). It is not part of the product. | Service `fixtures`; content in `backend/tests/fixtures/site` |
| Docker and Docker Compose | Containers and a tool to run many of them together | The whole platform runs from one Compose file | `deploy/docker-compose.yml`, `deploy/backend.Dockerfile`, `deploy/frontend.Dockerfile` |
| uv | A fast Python package manager | Installs exact versions from `backend/uv.lock` | `deploy/backend.Dockerfile`, `backend/pyproject.toml` |
| structlog | A logging library that writes one JSON object per line | Every log line, with request IDs | `backend/app/logging.py` and almost every module |

### Table B - Why, cost and failure

| Tool | Why chosen / alternatives | Cost and licence | If unavailable or not configured |
|---|---|---|---|
| PostgreSQL | Reliable, free, has JSON columns (JSONB) and arrays, so module output fields need no schema change. MongoDB was proposed for email and rejected (D-28). | Free; PostgreSQL License (permissive) | Nothing works. `GET /health` returns 503 "degraded". |
| psycopg | The current maintained PostgreSQL driver. | Free; LGPL-3.0 (fine for internal use) | - |
| Redis | Standard Celery broker; also fast shared counters for rate limits. | Free to self-host. Redis 7.4 and later are source-available (RSALv2/SSPL), not OSI open source; internal use is allowed. The Python client is MIT. | Scans cannot be queued: a manual scan is recorded as `failed` with "Could not queue scan". Rate limits fall back to per-process counters. Threat-intel answers are not cached. |
| Celery | Mature, retries, time limits, separate queues (`default` and `browser`, D-18). | Free; BSD-3-Clause | No scans run. Each task has a 1-hour limit; stuck runs are closed after 90 minutes. |
| RustFS | MinIO stopped publishing Docker images in 2025, so RustFS replaced it (D-22). Any S3 store (AWS S3, Wasabi, licensed MinIO) works by changing `S3_ENDPOINT_URL` and keys. | Free; Apache-2.0 | Evidence cannot be stored, so findings fail and scans become `partial`. Images do not load in the dashboard. Asset upload fails. |
| boto3 | The standard S3 library; speaks to any S3-compatible store. | Free; Apache-2.0 | - |
| nginx | Tiny and fast for static test pages. | Free; BSD-2-Clause | Module acceptance tests are skipped ("fixtures site not reachable"). The product is not affected. |
| Docker Compose | One file runs everything on any Linux server (D-16). | Docker Engine is free (Apache-2.0). Docker Desktop on Windows/macOS needs a paid subscription for larger companies. | - |
| uv | Fast, reproducible installs from a lock file. | Free; MIT/Apache-2.0 | On Windows with Application Control, uv cannot build source-only packages; a local `backend/wheels/` folder holds pre-built wheels (see `[tool.uv] find-links`). |
| structlog | JSON logs are easy to search and match by `request_id`. | Free; MIT or Apache-2.0 | - |

## 3. Web and API

### Table A - What and where

| Tool | What it is | What we use it for | Where |
|---|---|---|---|
| FastAPI | A Python web framework for building APIs | The REST API under `/api/v1`, with automatic documentation at `/docs` | `backend/app/main.py`, `backend/app/api/*.py` |
| Uvicorn | The web server that runs FastAPI | Serves the API on port 8000 inside the container (8010 on the host) | Compose service `api` command |
| python-multipart | Reads uploaded files in web forms | Logo/asset upload and email upload | `backend/app/api/brands.py`, `backend/app/api/emails.py` |
| SQLAlchemy 2 | An ORM (maps Python classes to database tables) | All database reads and writes | `backend/app/db/models.py`, every API and module |
| Alembic | Database migration tool (versioned schema changes) | Creates and upgrades tables; runs on every API start (`alembic upgrade head`) | `backend/app/alembic/versions/*.py`, `backend/alembic.ini` |
| Pydantic and pydantic-settings | Data validation from type hints | API request/response shapes; settings from environment variables | `backend/app/schemas/api.py`, `backend/app/config.py` |
| argon2-cffi | Argon2 password hashing | Stores passwords safely | `backend/app/core/security.py` |
| PyJWT | JSON Web Token library | Login tokens (12 hours by default) | `backend/app/core/security.py` |
| httpx | An HTTP client library | The only way the platform fetches external URLs (inside the safe fetcher) | `backend/app/core/fetch.py`; Microsoft Graph intake |
| tenacity | Retry helper | Retries with backoff on network errors, 5xx and 429 | `backend/app/core/fetch.py` |

### Table B - Why, cost and failure

| Tool | Why chosen / alternatives | Cost and licence | If unavailable |
|---|---|---|---|
| FastAPI | Fast to write, validates input, publishes OpenAPI docs for DEL-04. | Free; MIT | - |
| Uvicorn | The standard server for FastAPI. | Free; BSD-3-Clause | - |
| python-multipart | Required by FastAPI for form uploads. | Free; Apache-2.0 | Uploads fail. |
| SQLAlchemy | The most used Python ORM; works with PostgreSQL JSONB and arrays. | Free; MIT | - |
| Alembic | Made by the SQLAlchemy authors; migrations are tested on every test run (DEL-03). | Free; MIT | - |
| Pydantic | FastAPI's own validation layer. | Free; MIT | - |
| argon2-cffi | Argon2 is the current recommended password hash (D-15). | Free; MIT | - |
| PyJWT | Simple, widely used. Sessions are stateless (D-15). | Free; MIT | - |
| httpx | Modern client with timeouts and streaming, so the fetcher can stop at the size cap (D-18). | Free; BSD-3-Clause | - |
| tenacity | Small, clear retry rules. | Free; Apache-2.0 | - |

## 4. Discovery (finding suspicious things)

### Table A - What and where

| Tool | What it is | What we use it for | Module(s) | Where |
|---|---|---|---|---|
| dnstwist | A library that generates look-alike domain names | Typo variants: omission, substitution, transposition, homoglyphs, insertion, TLD swaps (TYP-01 to TYP-08) | Typosquat | `backend/app/modules/domains/variants.py` |
| dnspython | A DNS library | NS, A, AAAA, MX and TXT lookups against public resolvers 1.1.1.1, 8.8.8.8, 9.9.9.9 | Typosquat, MX, Phishing, Email posture, Email auth | `backend/app/modules/domains/infra.py`, `backend/app/modules/email/posture.py`, `backend/app/modules/email/auth.py` |
| whoisit (RDAP) | A client for RDAP, the modern JSON replacement for WHOIS | Registrar, creation and expiry dates (TYP-10) | Typosquat | `backend/app/modules/domains/infra.py` (`whois`) |
| crt.sh | A free public search site for Certificate Transparency logs (public lists of every TLS certificate issued) | Finds new domains that contain the brand name and got a certificate (D-11) | Typosquat | `backend/app/modules/domains/infra.py` (`ct_search`) |
| Brave Search API | A paid web-search API with a free tier | Site-restricted searches: APK mirror sites, documents (`filetype:`), X/Facebook/Instagram/LinkedIn profiles, social media posts and videos | Fake APK, Documents, Social, Social media | `backend/app/core/search.py` (`_brave`) |
| SerpAPI | A paid API that returns Google results | Same as Brave; used only if Brave is not set | Fake APK, Documents, Social, Social media | `backend/app/core/search.py` (`_serpapi`) |
| DuckDuckGo HTML page | DuckDuckGo's public results page (no API) | Free fallback search, one query every 12 seconds, pauses 15 minutes when rate-limited (D-23) | Fake APK, Documents, Social, Social media | `backend/app/core/search.py` (`_duckduckgo`) |
| google-play-scraper | A library that reads public Google Play pages | Searches Play for brand keywords and product terms; reads listing details | Rogue App | `backend/app/modules/rogue_app/module.py` |
| Telethon | A Python client for the official Telegram API | Searches public Telegram usernames and channels | Social | `backend/app/modules/social/module.py`, `backend/scripts/telegram_login.py` |
| Telegram public pages (`t.me`) | Public preview pages of Telegram accounts | Checks likely impersonator usernames (brand + support, official, help, care...) without an API account | Social | `backend/app/modules/social/module.py` (`telegram_public`) |
| Telethon `messages.SearchGlobal` | The same Telegram client, used for a global search of public channel **posts** | Finds Telegram channel posts that mention the brand (Chapter 14) | Social media | `backend/app/modules/social_media/sources.py` (`telegram_posts`) |
| YouTube Data API v3 | Google's official API for YouTube | Newest videos and channels that mention the brand: `search.list`, then `videos.list` and `channels.list` for title, description, counts and thumbnail | Social media | `backend/app/modules/social_media/sources.py` (`youtube`) |
| Meta Ad Library API | Meta's official search of ads shown on Facebook and Instagram (`ads_archive`) | Ads that mention the brand | Social media | `backend/app/modules/social_media/sources.py` (`meta_ads`) |
| Threads API (`keyword_search`) | Meta's official Threads API | Recent public Threads posts that mention the brand | Social media | `backend/app/modules/social_media/sources.py` (`threads`) |
| X API v2 (`tweets/search/recent`) | The official X (Twitter) API | Recent X posts (the API covers about the last 7 days) that mention the brand | Social media | `backend/app/modules/social_media/sources.py` (`x_posts`) |
| tldextract | Splits a host name into name and public suffix (uses a bundled offline list) | Finds the "registered domain" of any URL | All | `backend/app/core/similarity.py` |
| idna | Encodes international domain names | Handles Unicode look-alikes (for example Cyrillic letters) | All (through `similarity.py`) | `backend/app/core/similarity.py` |
| rapidfuzz | Fast fuzzy string matching | Similarity score 0-100 for domains, app names, packages, handles (TYP-13) | All | `backend/app/core/similarity.py`, `backend/app/modules/apk/module.py` |

### Table B - Why, cost and failure

| Tool | Why chosen / alternatives | Cost and licence | If unavailable or not configured |
|---|---|---|---|
| dnstwist | The best-known open-source typosquat generator; we add our own affixes (login, secure, kyc...). | Free; Apache-2.0 | - (runs offline) |
| dnspython | Direct queries to public resolvers are faster and more consistent than the operating system's resolver. | Free; ISC | A DNS timeout or SERVFAIL leaves the domain *unresolved*: reported on the "DNS resolution" component and retried next scan, never treated as "not registered" (D-31). Needs outbound port 53. |
| whoisit / RDAP | RDAP returns structured JSON; classic WHOIS text differs per registry. | Free; BSD-3-Clause. RDAP servers are free. | The error is stored in the `whois` field; the alert shows "lookup failed" for Registrar and Created, and the "WHOIS/RDAP" component reports the number of failed lookups (D-31). |
| crt.sh | Free and needs no key. A paid newly-registered-domain feed was considered and left as a future source (D-11). Certstream (live CT stream) is installed but not used. | Free public service, no SLA | Often overloaded (HTTP 502). The "Certificate Transparency (crt.sh)" component shows `failed` and the scan ends `completed_with_errors`; typo variants still run. |
| Brave Search API | Recommended for production: reliable, legal, has a free tier (D-23). | Free tier with a monthly quota; paid plans above it | Without `BRAVE_SEARCH_API_KEY`, SerpAPI or the free fallback is used. |
| SerpAPI | Alternative to Brave with Google results. | Paid (small free trial quota) | Without `SERPAPI_API_KEY`, the free fallback is used. |
| DuckDuckGo fallback | Lets the platform run with no paid keys (D-23). Bing's page was tested and rejected (ignores `site:` and `filetype:`). No CAPTCHA solving or bot evasion, on purpose. | Free, best effort | Turned off with `FREE_SEARCH_FALLBACK=false`. When rate-limited, searches raise "paused": the component "Web search - DuckDuckGo (free, paced)" shows `unavailable` and the scan ends `partially_completed`, or `failed` for Fake APK and Documents when no search worked at all. The provider that ran is named on every scan and on the Integrations page (D-31). |
| google-play-scraper | Google Play has no public search API. Only Google Play is covered in Phase 1 (D-13). | Free; MIT. Reads public pages. | A failed search marks "Google Play search" `failed` (scan `completed_with_errors`, removal check skipped); if every search failed, the scan is `failed`. |
| Telethon | The official Telegram API is free and allows username/keyword search (D-10). | Free; MIT. Needs `TELEGRAM_API_ID`, `TELEGRAM_API_HASH`, `TELEGRAM_SESSION` and a phone number for a monitoring account. | Falls back to public `t.me` pages when not configured (`TELEGRAM_PUBLIC_FALLBACK=true`). The scan shows "Telegram API: Not configured" next to "Telegram public pages", so the narrower check is visible (D-31). Keyword search is then not available. |
| Telethon `messages.SearchGlobal` | Telegram is the only platform with a free official search of public channel posts (D-38). | Free; uses the same `TELEGRAM_*` keys | Without the keys, "Telegram post search" shows `not_configured`; the public `t.me` fallback is not used for posts. |
| YouTube Data API v3 | Official, free, and returns full fields (views, description, thumbnail) without scraping (D-38). | Free quota of 10,000 units a day; a search costs 100 units, a details call 1. About 302 units per brand per scan. Key: `YOUTUBE_API_KEY`. | "YouTube API" shows `not_configured`, and YouTube is searched through web search (`site:youtube.com`) instead. When the quota is used up the component shows `failed` with Google's message. |
| Meta Ad Library API | The only official way to search Facebook and Instagram ads (D-38). Paid scrapers rejected. | Free; needs a Meta account with confirmed identity. Token: `META_AD_LIBRARY_TOKEN`; countries: `META_AD_COUNTRIES`. | "Meta Ad Library" shows `not_configured`; no ads are searched. Known limit: commercial ads are returned only when they were shown in the EU or UK; elsewhere (for example India) only political and issue ads. |
| Threads API (`keyword_search`) | Official Threads search (D-38). | Free; needs a Meta developer app approved for `threads_keyword_search`. Token: `THREADS_ACCESS_TOKEN`. | "Threads API" shows `not_configured`; Threads is still covered by web search (`site:threads.net`). |
| X API v2 recent search | Official X search with full post text, author and counts (D-38). | Paid (pay-per-use credits). Token: `X_BEARER_TOKEN`. | "X API" shows `not_configured`; X posts are then found through web search (`site:x.com OR site:twitter.com`). |
| tldextract | Correct handling of suffixes like `.co.uk`; offline so workers never block. | Free; BSD-3-Clause | - |
| idna | Standard IDNA 2008 implementation. | Free; BSD-3-Clause | - |
| rapidfuzz | Much faster than pure-Python matching, needed for 12,000 variants per domain. | Free; MIT | - |

## 5. Analysis (looking at what was found)

### Table A - What and where

| Tool | What it is | What we use it for | Module(s) | Where |
|---|---|---|---|---|
| Playwright + Chromium | A browser automation library and a real headless browser | Screenshots, page title and text, favicon, page images, rendering inline SVG logos (FND-11) | Phishing, Logo, Social | `backend/app/core/browser.py`; runs only on the `browser-worker` |
| Safe fetcher (our code) | One wrapper around httpx | Timeouts, retries, per-host rate limit, size caps, blocks private and cloud-metadata addresses on every hop (D-18, D-24) | All | `backend/app/core/fetch.py` |
| Pillow | Python image library | Opens and normalises images before hashing | Logo, Phishing, APK, Social, assets | `backend/app/core/imaging.py` |
| ImageHash | Perceptual hashes (pHash, dHash, aHash): fingerprints that stay similar when an image is resized or recompressed | Logo match score 0-100 (LOGO-03, LOGO-04, APK-05, SOC-08) | Logo, Phishing, APK, Social, Rogue App | `backend/app/core/imaging.py` |
| mmh3 | MurmurHash3, a fast hash | Shodan-style favicon hash, compared with the brand favicon (PHI-03, PHI-06) | Phishing | `backend/app/core/imaging.py` (`favicon_hash`) |
| androguard | A library that reads Android APK files | Reads the manifest (name, package, version, icon) and the v2/v3 signing block; never executes or decompiles (OOS-03) | Fake APK | `backend/app/modules/apk/module.py`, `backend/app/modules/apk/signing.py` |
| cryptography | Python's main cryptography library | Reads v1 APK signatures (PKCS#7) and TLS certificates of suspicious sites (PHI-05) | Fake APK, Phishing | `backend/app/modules/apk/signing.py`, `backend/app/core/fetch.py` |
| pdfminer.six | Extracts text from PDF files | Document text (first 50 pages) | Documents | `backend/app/modules/documents/module.py` |
| python-docx | Reads Word `.docx` files | Document text | Documents | same |
| openpyxl | Reads Excel `.xlsx` files | Document text | Documents | same |
| python-pptx | Reads PowerPoint `.pptx` files | Document text | Documents | same |
| python-magic (libmagic) | Detects a file's real type from its first bytes | File type of downloaded documents, not trusting the extension | Documents | `backend/app/modules/documents/module.py` (`sniff_type`) |

### Table B - Why, cost and failure

| Tool | Why chosen / alternatives | Cost and licence | If unavailable |
|---|---|---|---|
| Playwright | Reliable headless Chromium, with request interception so the same address rules apply inside the page (D-18). | Free; Apache-2.0. Each page needs 300-500 MB RAM. | No screenshots. A failed capture is reported on the capture component; a look-alike domain is shown as "Website Live: unknown (capture failed)" and the existing finding keeps its last known state (D-31, D-36). Domain, logo, social and social media scans wait if the browser worker is down. |
| Pillow | The standard image library. | Free; MIT-CMU | - |
| ImageHash | Simple, proven perceptual hashing. | Free; BSD-2-Clause | - |
| mmh3 | Same favicon hash as Shodan, so values can be compared with public tools. | Free; MIT | - |
| androguard | Reads signatures without running the app (D-26). MobSF, apktool and JADX are Phase 2 (D-26). | Free; Apache-2.0 | APK cannot be parsed; listing data is still used. |
| cryptography | Standard, well maintained. | Free; Apache-2.0 or BSD-3-Clause | - |
| pdfminer.six | Pure Python, good text extraction, no macros run. | Free; MIT | Text is empty; only filename and snippet are checked. |
| python-docx, openpyxl, python-pptx | Read Office files without running macros. Old binary `.doc/.xls/.ppt` are classified but their text is not extracted by these libraries. | Free; MIT | Text is empty. |
| python-magic | The real type matters: a `.pdf` link can serve HTML. | Free; MIT. Needs the `libmagic1` system library (installed in the Docker image). | Skipped on Windows; the extension is used instead. |

## 6. Email (phishing-email modules, D-28)

### Table A - What and where

| Tool | What it is | What we use it for | Where |
|---|---|---|---|
| Python `email` (standard library) | Python's built-in email parser | Headers, bodies, attachments of `.eml` files (EML-01) | `backend/app/modules/email/parser.py` |
| extract-msg | Reads Outlook `.msg` files | Converts `.msg` uploads | `backend/app/modules/email/parser.py` |
| Rspamd (`rspamd/rspamd`) | A spam and phishing filtering engine, run as a container | Spam/phishing score of the whole message (EML-06) | Service `rspamd`; `backend/app/modules/email/engines.py` (`rspamd_check`, `/checkv2`) |
| ClamAV (`clamav/clamav:stable`) | An open-source antivirus engine, run as a container | Malware scan of attachments over the clamd INSTREAM protocol (EML-07) | Service `clamav`; `backend/app/modules/email/engines.py` |
| YARA (yara-python) | A pattern-matching engine for malware rules | Bundled rules in `backend/rules/yara/phishing.yar` (EML-08) | `backend/app/modules/email/engines.py` |
| oletools | Tools for Microsoft Office files | Finds VBA macros in attachments | `backend/app/modules/email/attachments.py` |
| URLhaus (abuse.ch) | A free database of malware URLs and file hashes | URL and attachment-hash lookups (EML-09) | `backend/app/modules/email/intel.py` |
| OpenPhish | A phishing URL feed (free community feed) | URL lookups against the feed, refreshed every 6 hours | same |
| urlscan.io | A service that scans and records websites | Searches earlier scans of a URL for a malicious verdict | same |
| AbuseIPDB | A database of reported abusive IP addresses | Reputation of the sender's IP address | same |
| defusedxml | A safe XML parser | Parses DMARC aggregate reports, safe against XML bombs (EML-18) | `backend/app/modules/email/dmarc.py` |
| imaplib (standard library) | IMAP mail client | Reads the reporting mailbox every 5 minutes and the DMARC mailbox hourly (EML-19) | `backend/app/modules/email/intake/imap.py`, `mailbox.py` |
| Microsoft Graph | Microsoft 365 mail API | Optional intake from a Microsoft 365 folder | `backend/app/modules/email/intake/graph.py` |
| Gmail API | Google Workspace mail API | Optional intake from a Gmail label | `backend/app/modules/email/intake/gmail.py` |

### Table B - Why, cost and failure

Rule from D-28: an unreachable or unconfigured source scores 0 and is shown as "not checked". A URL counts as
"known malicious" only when at least two independent sources agree.

| Tool | Why chosen / alternatives | Cost and licence | If unavailable or not configured |
|---|---|---|---|
| Python `email` | Chosen instead of the `mail-parser` package (D-28). | Free; part of Python | - |
| extract-msg | Only practical `.msg` reader in Python. | Free; GPL-3.0 (internal use is fine; review before distributing) | `.msg` files cannot be read. |
| Rspamd | Covers what SpamAssassin does, faster (D-28). | Free; Apache-2.0 | Verdict `not_checked`. |
| ClamAV | Free, widely used malware engine. | Free; GPL-2.0. About 1.5 GB RAM; first start takes about a minute to load signatures. | Verdict `not_checked`. Can be turned off with `CLAMAV_ENABLED=false`. |
| YARA | Standard rule format used by security teams. | Free; BSD-3-Clause / Apache-2.0 | No rule files: `not_checked` ("no rules"). |
| oletools | Standard macro detection. | Free; BSD | Macro check skipped. |
| URLhaus | Replaces PhishTank (D-28). | Free; needs `URLHAUS_AUTH_KEY` from abuse.ch | Without the key: `not_checked`. |
| OpenPhish | Replaces PhishTank (D-28). | Community feed free; commercial feed paid. No key; `OPENPHISH_FEED_URL`. | Feed unreachable: `not_checked`. |
| urlscan.io | Second opinion on URLs. | Free tier with quotas; needs `URLSCAN_API_KEY` | Without the key: `not_checked`. |
| AbuseIPDB | Sender IP reputation. | Free tier with daily limits; needs `ABUSEIPDB_API_KEY` | Without the key: `not_checked`. |
| defusedxml | Chosen instead of parsedmarc, which pulls in Elasticsearch and Kafka (D-28). | Free; PSF licence | - |
| IMAP | Works with almost any mail server. | Free | Without `IMAP_HOST` / `DMARC_IMAP_HOST`, mailbox polling does nothing; uploads still work. |
| Microsoft Graph | Optional adapter. | Needs an app registration with Mail.Read | Without `MS_GRAPH_*`, not used. |
| Gmail API | Optional adapter. | Needs a service account with delegation. The Google client libraries are **not** in `pyproject.toml`; the adapter logs "gmail_service_failed" unless they are installed. | Not used. |

DKIM, SPF and DMARC checks today are done by our own code with dnspython (`auth.py`, `posture.py`), reading
the receiving server's `Authentication-Results` header and the published DNS records. MTA-STS is checked by
looking for the `_mta-sts` TXT record. See section 9 for the email libraries that are installed but not called.

## 7. Reporting

| Tool | What it is | What we use it for | Where | Cost and licence | If unavailable |
|---|---|---|---|---|---|
| WeasyPrint | Converts HTML and CSS to PDF | PDF export of the alert list (DSH-19) | `backend/app/api/exports.py` | Free; BSD. Needs Pango and HarfBuzz system libraries and fonts, installed in `deploy/backend.Dockerfile`. | The API answers 503 "PDF export needs the system libraries in the Docker image" (for example when the API runs natively on Windows). |
| Python `csv` (standard library) | CSV writer | CSV export (DSH-18) | `backend/app/api/exports.py` | Free | - |
| UAT report script (our code) | Turns test results into a report | `docs/reports/UAT-REPORT.md` (DEL-07, D-17) | `backend/scripts/uat_report.py` | - | See Chapter 12. |
| Email accuracy script (our code) | Measures precision and recall on labelled emails | `docs/reports/EMAIL-ACCURACY.md` | `backend/scripts/email_accuracy.py` | - | - |

## 8. Frontend

All are free and MIT-licensed unless noted. Versions come from `frontend/package.json`. The web container is
built on `node:22-alpine`.

| Tool | What it is | What we use it for | Where |
|---|---|---|---|
| Next.js 16 | React framework with routing and a production server | All pages; standalone server on port 3000 | `frontend/src/app`, `deploy/frontend.Dockerfile` |
| React 19 | UI component library | Everything on screen | `frontend/src` |
| TypeScript 5 | JavaScript with types | All frontend code; API types in `frontend/src/lib/api.ts` | `frontend/` (Apache-2.0) |
| TanStack Query 5 | Server data fetching and caching | Every API call; polling of running scans | `frontend/src/lib/queries.ts` and pages |
| TanStack Table | Headless table logic | Alert queue, email list | `frontend/src/app/(app)/alerts/page.tsx`, `emails/page.tsx` |
| Tailwind CSS 4 | Utility-first CSS | All styling, light and dark themes | `frontend/src/app/globals.css` and components |
| shadcn/ui + Base UI | Copy-in accessible components | Buttons, dialogs, selects, tables, tabs | `frontend/src/components/ui/*` |
| Recharts | Chart library | 30-day trend chart | `frontend/src/components/charts.tsx` |
| react-hook-form, zod, @hookform/resolvers | Forms and validation | Brand form, user forms, login | `frontend/src/components/brand-form.tsx`, users page |
| lucide-react | Icon set | All icons | Everywhere (ISC licence) |
| sonner | Toast notifications | Success and error messages | `frontend/src/components/ui/sonner.tsx` |
| next-themes | Theme switching | Light / dark / system | `frontend/src/components/providers.tsx` |
| class-variance-authority, tw-animate-css | Styling helpers | Component variants and animations | `frontend/src/components/ui/*` |
| ESLint | Code checker | `npm run lint` | `frontend/` |

Why this stack: see Chapter 10, section 2. If the web container is down, the API still works and can be used
directly through `/docs`.

## 9. Installed but not used by the code today

These packages are listed in `backend/pyproject.toml` and installed in the image, but no file in
`backend/app` or `backend/scripts` imports them (checked on 2026-10-09). They cost disk space only. They are
candidates for removal or for future work.

| Package | What it could do | Status |
|---|---|---|
| dkimpy | Verify DKIM signatures cryptographically | Not called. `auth.py` mentions it in a comment, but `dkim_verified` is always empty. DKIM results come from the receiving server's header. |
| pyspf | Evaluate SPF records | Not called. SPF is read from the header and checked by our own TXT parsing. |
| checkdmarc | Validate SPF and DMARC records | Not called. Posture checks are our own code in `posture.py`. |
| certstream | Live stream of new TLS certificates | Not called. crt.sh search is used instead. |
| opencv-python-headless | Computer vision (for example template matching) | Not called. Logo matching uses ImageHash. |
| beautifulsoup4, selectolax | HTML parsing | Not called. Web pages are read through the browser (Playwright) and regular expressions; email HTML uses Python's built-in `html.parser`. |
| pypdf | PDF reading | Not called. pdfminer.six is used. |
| jellyfish, confusable-homoglyphs | String distance, Unicode look-alike tables | Not called. rapidfuzz and our own homoglyph table in `similarity.py` are used. |
| email-validator | Email address validation | Not called directly. |
| asyncpg | Async PostgreSQL driver | Not used. The app uses psycopg with synchronous sessions. |

## 10. Tools we deliberately do not use, and why

| Tool | What it is | Why we do not use it |
|---|---|---|
| VirusTotal | Multi-engine file and URL scanning service | Its free public API forbids commercial use. A paid licence, or Google Web Risk, can be added later (D-28). |
| PhishTank | Community phishing URL database | Registration for new API keys is closed. Replaced by OpenPhish and URLhaus (D-28). |
| MongoDB | Document database | Proposed in the email stack. PostgreSQL already stores flexible fields in JSONB; one database is simpler to run and back up (D-28). |
| SpamAssassin | Classic spam filter | Rspamd covers the same checks and is faster (D-28). |
| MinIO | S3-compatible object store | Stopped publishing Docker images in 2025. Replaced by RustFS; any S3 store can be configured (D-22). |
| mail-parser, parsedmarc | Email and DMARC parsing packages | The standard library parser is enough; parsedmarc pulls in Elasticsearch and Kafka (D-28). |
| MobSF, apktool, JADX | APK static analysis and decompilers | Reverse engineering is out of scope in Phase 1 (OOS-03). MobSF static scan is recorded for Phase 2 (D-26). Dynamic analysis (emulators) is never run on the monitoring platform. |
| Nuclei | An **active vulnerability scanner** that sends attack-style requests | It probes targets for weaknesses. Running it against third-party sites we do not own is not appropriate and may be unlawful. The platform only observes what any visitor can see. |
| Subfinder, Amass | Subdomain enumeration tools | They list subdomains of a known domain. That overlaps with the DNS resolution of typo variants and the Certificate Transparency search the platform already does, and it targets the attacker's subdomains rather than finding new look-alikes. |
| Bing results page | Free search fallback candidate | Tested and rejected: ignores `site:` and `filetype:` (D-23). |
| CAPTCHA solvers, fingerprint spoofing | Ways around search-engine bot protection | Breaks the providers' terms and is unreliable (D-23). |
| Bright Data and other paid scrapers | Direct social platform access | Not used. Since D-43 (2026-10-14) **Apify** is used, optionally (`APIFY_TOKEN`), for Instagram, TikTok, Facebook posts, Meta ads, X and LinkedIn, next to the official APIs and web search (Chapters 06 and 14). |

## Key takeaways

- The platform is built almost entirely on free, permissively licensed software. The notable exceptions are
  Redis (source-available from 7.4), extract-msg (GPL-3.0), ClamAV (GPL-2.0) and psycopg (LGPL-3.0); all are
  fine for internal use.
- Only a few things need keys, and all are optional: a search API (Brave recommended), Telegram API
  credentials, the social media APIs of Chapter 14 (YouTube, Meta Ad Library, Threads, X), and URLhaus, urlscan.io and AbuseIPDB keys for email threat intelligence.
- Every missing email engine or feed is shown as "not checked" and scores zero. Since SP1 (D-31) discovery and
  analysis failures (DNS timeouts, failed captures, RDAP errors, the Telegram fallback, rate-limited search)
  are reported as scan components, and the Integrations page shows every tool's configuration and last
  result.
- Ten Python packages are installed but not imported, including dkimpy, pyspf and checkdmarc.
- Some well-known tools are left out on purpose: VirusTotal (licence), PhishTank (closed), Nuclei (active
  scanning of third parties), and Subfinder/Amass (overlap with existing DNS and CT discovery).
