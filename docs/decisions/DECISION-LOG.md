# Decision Log — explained for demos

Every choice that was not spelled out in the requirements is recorded here, in plain language,
with **what we decided**, **why**, and **how to say it in a demo**. Requirement IDs refer to
`docs/requirements/01-requirements-register.md`.

Decided by: project owner delegated choices to the build team on 2026-10-06 ("go by your preference,
but achieve the requirements and document it").

---

## D-01 · Timeline is 15 days, not 30
- **Decision:** All Phase-1 requirements are delivered in 15 days. The 4-week plan is compressed into 5 stages (see the design spec §10).
- **Why:** Owner's instruction. Scope is unchanged; the build is done by one developer working with Claude Code, which writes and tests most of the code.
- **Demo line:** "The proposal budgeted 30 days for a 3-person team; we delivered the same scope in 15 using AI-assisted development, with every requirement traced to a test."

## D-02 · Risk level comes from the points model; MX tier shown separately (CONFLICT-02)
- **Decision:** The alert's Risk Level always comes from the §6 points table. The §3.1 MX rule (No MX = Low, MX = Medium, MX + live site = High) is shown as its own field, **Email Risk**.
- **Why:** The two rules disagree — §6 gives MX only +15. One alert can't have two risk levels, so the points model (which covers every module) wins, and the MX rule is still visible.
- **Demo line:** "Every alert uses one consistent score. On domain alerts you also see an Email Risk tier, which tells you whether the domain can send phishing email."

## D-03 · Module-specific level ranges (CONFLICT-04)
- **Decision:** Compute the normal 0–100 score, then keep the level inside the range that module's spec allows: APK, Rogue app, Logo → Medium/High; Social → Low/Medium/High; Documents → Medium/High/Critical; Domains → all four.
- **Why:** §3 lists allowed levels per module. Clamping keeps the global model and honours each module's table.
- **Demo line:** "A fake app is never 'Low' — any unauthorized use of the brand in an app store is at least Medium."

## D-04 · "Suspected Phishing" rule (GAP-01)
- **Decision:** A domain is marked **Suspected Phishing** when similarity ≥ 80 **and** the site is live **and** (login/payment keywords are found **or** the favicon matches the brand's favicon **or** the official logo is found).
- **Why:** The requirement says "exceeds threshold" but gives no number. 80 matches the §6 typo-similarity rule; requiring a live site plus a phishing signal avoids flagging parked domains.
- **Demo line:** "A look-alike name alone isn't phishing. We flag it when it's live and shows a login form, our favicon or our logo."

## D-05 · Typo similarity "> 80%" is strict; exact match and typo similarity stack (GAP-03, GAP-04)
- **Decision:** Exactly 80 does not earn the +25. A domain containing the exact brand name can earn both +40 and +25.
- **Why:** Read literally from §6. Every boundary is unit-tested.

## D-06 · Scoring rules added for documents (GAP-02)
- **Decision:** Sensitive documents score: brand keyword +30, official domain or brand email domain found +20, sensitive filename/content pattern (confidential, internal, salary, customer, …) +30, 5 or more email addresses +20. Level clamped to Medium/High/Critical.
- **Exposure Confidence:** Low = brand only in search snippet/filename; Medium = file downloaded and brand found in content; High = Medium plus sensitive pattern or emails.
- **Why:** §6 has no rules for documents, but §3.5 asks for a risk level. These rules use only the detection logic already listed in §3.5.

## D-07 · Workflow has 5 statuses (CONFLICT-03)
- **Decision:** New → Under Review → Confirmed / False Positive → Closed. Every change is stored with who, when, and an optional note.
- **Why:** §4 lists 5 statuses; the dev plan omits False Positive. Measuring false positives is a QA requirement (§8), so we keep it.

## D-08 · Who builds it
- **Decision:** One developer plus Claude Code. Backend, frontend and QA tasks are interleaved per day instead of run by three people.

## D-09 · Demo brand: a fictional brand, plus optional live brands
- **Decision:** A fictional demo brand, **"Zentrova Bank"**, ships with official logo, favicon, domains, app packages, publishers and social handles. All 10 acceptance criteria are proven against it with simulated sources. Real Beyond Cloud client brands can be added through the UI at any time; the live sources then run for them.
- **Why:** Acceptance criteria ask for *simulated* fake APKs and social accounts. A fictional brand makes the demo repeatable and avoids probing a real client's infrastructure during testing.
- **Demo line:** "Everything you see for Zentrova is reproducible on demand. Adding a real brand takes two minutes — let me show you."

## D-10 · Social media sources (GAP-06)
- **Decision:** Each platform uses a pluggable source:
  - **Telegram:** live, via the official Telegram API (needs an API ID/hash — supplied later).
  - **X, Facebook, Instagram, LinkedIn:** live discovery through a web-search API restricted to each site (e.g. `site:instagram.com "zentrova"`), then public profile data from the result.
  - **Simulated source:** for acceptance tests and demos.
- **Why:** X's API is paid; Facebook, Instagram and LinkedIn have no public search API and forbid scraping. Search-engine discovery finds public profiles legally; a paid provider can be plugged in later without code changes elsewhere.
- **Demo line:** "We don't scrape behind logins. We find impersonators the way an attacker's victims would — through public search."

## D-11 · Newly registered domains (GAP-05)
- **Decision:** Two free sources: (1) every generated typo variant is resolved daily via DNS/WHOIS, so any newly registered variant appears the next day; (2) Certificate Transparency logs (crt.sh) are searched for certificates containing the brand name — new phishing sites almost always get a certificate. A paid newly-registered-domain feed can be added as another source.
- **Why:** No feed was specified and none is free. These two cover the common case at zero cost.

## D-12 · APK sources
- **Decision:** APK discovery uses web search restricted to public APK sites (APKPure, APKMirror, APKCombo, Uptodown…) and reads the public listing page (name, package, version, developer, icon). If a direct download is available, the file is fetched into evidence storage to compute its SHA256 and read the manifest/icon. **The APK is never executed or decompiled** (reverse engineering is out of scope, OOS-03).
- **Why:** These sites have no official API; public listing pages are what any user sees.

## D-13 · App stores
- **Decision:** Google Play only in Phase 1 (GAP-07). The store layer is pluggable, so others can be added in Phase 2.

## D-14 · Alerts are delivered in the dashboard only (GAP-08)
- **Decision:** No email/Slack notifications in Phase 1.
- **Why:** Not required by §9; keeps 15 days realistic. A webhook hook point is left for Phase 2.

## D-15 · Login: local accounts with two roles (GAP-09)
- **Decision:** Email + password (Argon2-hashed), JWT sessions. Roles: **Admin** (manage brands, users) and **Analyst** (review alerts, run scans, export).

## D-16 · Hosting: Docker Compose
- **Decision:** The whole platform runs from one Docker Compose file: API, workers, scheduler, PostgreSQL, Redis, MinIO (object storage) and the web app. Staging and production are the same file on any Linux server or cloud VM.
- **Why:** No hosting was specified. Compose runs anywhere; MinIO speaks the S3 protocol, so moving to AWS S3 later is a configuration change.

## D-17 · Reports
- **Decision:** (1) A short daily progress report against the requirements register (`docs/reports/daily/`). (2) The final Test/UAT report is generated from automated tests tagged with requirement IDs, so it shows pass/fail for every requirement.

## D-18 · Safety rules for touching suspicious sites
- **Decision:** All outbound requests go through one safe fetcher (timeouts, retries, per-host rate limits, blocks internal network addresses, size caps). Screenshots run in an isolated browser worker. Downloaded files are stored, hashed and never opened or run.
- **Why:** The platform deliberately visits malicious sites; it must not become a way into our own network.
- **Note for production use:** confirm Beyond Cloud is authorised by each monitored brand to perform this monitoring.

## D-19 · One alert per suspicious domain, staged
- **Decision:** The Typosquat, MX and Active Phishing modules share one alert per domain. The alert's module shows the furthest stage reached: **Typosquat** (look-alike registered) → **MX** (can send email) → **Phishing** (website live). The alert keeps all fields from the §3.1 output table at every stage, and each stage change is written to the alert history.
- **Why:** Three alerts for one domain would triple analyst work and inflate counts. Analysts still filter by each module type.
- **Demo line:** "This domain started as a registered look-alike, gained a mail server on Tuesday, and went live with a login page on Thursday — you can see that whole story in one alert."

## D-20 · "Exact brand match" applies to each module's identifier
- **Decision:** The §6 rule "Brand name exact match in domain (+40)" is applied to the identifier each module watches: the **domain** (Typosquat/MX/Phishing), the **package name or app title** (Fake APK, Rogue app) and the **username/handle** (Social). Look-alike spellings (e.g. `zentr0va`) do not count as exact; they score through typo similarity instead.
- **Why:** §6 is the single scoring model for every module (§11 "consistent risk scoring model"), but only names domains. Without this, an account literally named `@zentrova_support` would score the same as a random look-alike.
- **Demo line:** "Using our exact name is the strongest signal everywhere — in a domain, an app package or a social handle."

## D-21 · Evidence is stored once
- **Decision:** When a daily re-scan sees the same thing again, identical evidence (same file hash or same metadata) is not stored a second time; new screenshots or changed pages are added to the timeline.
- **Why:** Keeps storage and the evidence gallery meaningful over months of daily scans.

## D-22 · Object storage: RustFS instead of MinIO
- **Decision:** The S3-compatible evidence store in Docker Compose is **RustFS**. MinIO stopped publishing Docker images in 2025. The application only speaks the S3 protocol, so AWS S3, Azure (via S3 gateway), Wasabi or a licensed MinIO can be swapped in through `S3_ENDPOINT_URL` / keys in `.env` with no code change.

## D-23 · Working without paid search / Telegram API keys
- **Decision:** When no search API key is configured, discovery falls back to DuckDuckGo's public results page, one query at a time, and **pauses for 15 minutes the first time it is rate-limited**. When no Telegram API credentials are configured, the social module checks likely impersonator usernames (brand name + support/official/help/care/… ) on Telegram's **public t.me pages**, which show name, subscribers, description and photo without logging in.
- **Tested and rejected:** Bing's public results page (ignores `site:` and `filetype:`, so results are off-topic).
- **Not done, on purpose:** no CAPTCHA solving, browser fingerprint spoofing or other ways around a search engine's bot protection — that breaks their terms and is unreliable.
- **Consequence:** without a key, Fake APK, Sensitive Documents and X/Facebook/Instagram/LinkedIn discovery is best-effort (a few searches per scan before the free source pauses). **A Brave Search API key (free tier) makes them reliable** and is recommended for production. Telegram works fully without credentials for brand-name variants; the official API additionally searches by keyword.
- **Demo line:** "Out of the box it runs without paid accounts; add a free search key and every module runs at full coverage."

## D-24 · Networks that use NAT64
- **Decision:** The safe fetcher treats IPv6 addresses in the NAT64 range `64:ff9b::/96` as the IPv4 address they carry, so public sites on IPv6-only/NAT64 networks are reachable while private and metadata addresses inside that range stay blocked.
- **Why:** Found during the first live scan: on this office network every public site resolves through NAT64, and the fetcher was wrongly blocking real phishing sites as "internal".

## D-25 · Short brand abbreviations need context
- **Decision:** Brand words are split by strength. **Distinctive names** (6+ letters, e.g. `kodachadri`, `chitkart`, `mykcpl`) count on their own, and close misspellings of names with 8+ letters count too. **Short abbreviations** (e.g. `KCPL`) count only as an exact word **and** only together with context — another brand word (`chits`, `kodachadri`) or the official logo. Applies to Google Play, APK, social and document modules.
- **Why:** Found in the first live scan of Kodachadri Chits: "KCPL" also means Kansas City Public Library, Kirloskar, and more — 14 Play Store alerts, all unrelated. "KCPL Chits Helper" is still caught; "Kanawha County Public Library" is not.
- **Also:** the company's own name no longer triggers sensitive-document words (e.g. "private" in "Private Limited"), and documents on the brand's own domains are marked **Hosted On Official Domain**, so analysts can tell published files from leaks.
- **Demo line:** "The system knows the difference between our name and someone else's abbreviation that happens to look the same."

## D-26 · Fake APKs are verified by signing certificate; MobSF is Phase 2
- **Decision (owner, 2026-10-07):** Add signing-certificate verification now; keep deeper analysis (MobSF static scan, apktool, JADX, YARA) for Phase 2; never run dynamic analysis (emulator) on the monitoring platform.
- **How it works:** the brand's official **app signing certificate SHA-256** (Play Console → App integrity → App signing key certificate) is stored in the allowlist. Every APK downloaded from a mirror has its signer read — v2/v3/v3.1 block via Androguard, v1 `META-INF` signature via `cryptography` — without decompiling or running anything (within OOS-03).
  - signer matches → genuine app re-hosted on a mirror → **no alert**, whatever the listing calls itself;
  - signer differs → counts as **official publisher mismatch** (+25);
  - official package name + different signer → **"official package re-signed with a different key"** (repackaged/modded app), also scored as an exact brand match.
- **Why:** names, icons and even package names can be copied; the signature cannot. It is the strongest single fake-app signal and needs no reverse engineering.
- **Phase 2 (recorded, not built):** MobSF in its own isolated container, static scan only, fed the APKs already stored as evidence — permissions, trackers, malware indicators, embedded URLs. Requires changing the OOS-03 scope decision.
- **Phase 2, also recorded (owner, 2026-10-07):** MobSF static security scan of the **company's own official APK** (vulnerabilities, hard-coded secrets, weak crypto, risky permissions, security score) shown on the brand page. Kept for Phase 2 by the owner; needs ~2 GB disk and 1–2 GB RAM.
- **Demo line:** "A fake app can copy our name and logo, but not our signature — that's how we tell the real app on a mirror site from a modded copy."

## D-27 · Real data only in the product; demo data only inside automated tests
- **Decision (owner, 2026-10-07):** The product shows only data scanned from live sources. Demo mode is disabled
  (`ALLOW_DEMO_MODE=false`): the brand form has no demo switch, the API rejects `demo_mode=true`, scans refuse to run
  a demo-mode brand, `seed_demo` refuses to run, and the fixtures test website no longer starts with the platform
  (Compose profile `test`). The simulated "Zentrova Bank" data is used **only** by the automated acceptance tests,
  which run against their own database (`brandintel_test`) and bucket (`evidence-test`).
- **Accounts:** the only account is the administrator; analysts are created by the admin (no self-registration).
  Test accounts and the bootstrap placeholder admin were removed; 14 Play Store alerts produced by the abbreviation
  bug (fixed in D-25) were deleted.
- **Why:** owner requirement — every alert must be legitimate, produced by the real scanning tools.

## D-28 · Phishing email monitoring (new module)
- **Decision (owner, 2026-10-08, approved spec):** Add phishing-email monitoring as a separate module strongly linked to phishing-website monitoring. Four capabilities: (A) analyse reported/uploaded emails; (B) check the brand's own domains' email security (SPF/DMARC/DKIM/MTA-STS); (C) flag look-alike domains that are email-ready; (D) monitor DMARC aggregate reports for spoofing.
- **Tools (owner-chosen, no single point of truth):** Rspamd + ClamAV + YARA (isolated containers / in-process), plus threat intel URLhaus + OpenPhish + urlscan.io + AbuseIPDB. Python email parser, dkimpy/pyspf/checkdmarc, oletools. Every link also runs through the existing website pipeline.
- **Precision safeguards:** deterministic points table; a URL is "known malicious" only with **≥2 independent sources** (corroboration); an unreachable source scores 0 and is shown as "not checked"; official senders that pass DMARC are never scored as impersonators; accuracy measured on a labelled set (`scripts/email_accuracy.py` → `docs/reports/EMAIL-ACCURACY.md`).
- **Deviations from the proposed stack (recorded):** PostgreSQL + Next.js kept (not MongoDB/React); SpamAssassin dropped (Rspamd covers it); VirusTotal **not used** (its free API forbids commercial use — a paid licence or Web Risk can be added); PhishTank replaced by OpenPhish/URLhaus (no new PhishTank keys); stdlib `email` instead of mail-parser; a small defusedxml DMARC parser instead of parsedmarc (which pulls in Elasticsearch/Kafka). Graph/Gmail intake are optional adapters.
- **No "zero error" claim:** no phishing detector is error-free; the platform makes every decision explainable and measures its accuracy instead.
- **Demo line:** "A reported email is checked by five independent engines and four reputation feeds; we only call a link malicious when at least two agree, and we always show you what we couldn't check."

## D-29 · High/Critical needs brand evidence on the live page
- **Decision (owner, 2026-10-08):** A live look-alike website only reaches **High or Critical** when the page itself
  shows the brand — official logo or favicon, the brand name / keywords / product terms (short abbreviations only
  with context, D-25), or a link or mention of an official website or email domain. Otherwise it is capped at
  **Medium (59)**. **Parked / for-sale pages** (domain marketplaces, parking landers, "domain is for sale" text) are
  capped at **Low (29)**. "Suspected Phishing" also requires brand evidence and a non-parked page.
- **Why:** the first live scans of Kodachadri Chits and Specigo scored legitimate, unrelated businesses Critical
  (e.g. `specio.com` = look-alike spelling + mail server + SPF + HTTPS + the word "login" = 80) and parked
  hugedomains.com pages as "Suspected phishing". Those points describe the *domain*, not the *content*.
- **How:** the RSK points table is unchanged; the cap is applied inside the one scoring function
  (`core/scoring.py` `SCORE_CAPS`), the un-capped total stays visible as `raw_score`, and every capped alert shows a
  **Score Cap** reason. Domains with no website are not capped (the domain name is the only evidence there).
- **Trade-off:** a phishing kit that shows no brand text, logo or link at all scores Medium until its content
  changes; it is re-checked on every scan and rises automatically (and re-opens if it was closed).
- **Demo line:** "A look-alike name alone doesn't make a site Critical — the page has to actually pretend to be us."

## D-30 · Test data lives with the tests, outside the product
- **Decision (owner, 2026-10-09):** The fictional test brand and simulated sources moved from the top-level
  `fixtures/` to `backend/tests/fixtures/`. The product containers no longer mount them and the backend image
  excludes `backend/tests`; only the `test`-profile website serves them. The app UI no longer shows the test brand
  as example text.
- **Why:** owner saw the test brand around the project and wanted the product to contain only real, scanned data.
  The test data is kept (not deleted) because the automated acceptance tests and the UAT report depend on it.
- **Demo line:** "Everything in the product is real scan data; the made-up brand exists only inside the test suite."

## D-31 · Honest scan states and per-component results
- **Decision (owner-approved spec, 2026-10-09, SP1):** A scan run is `queued`, `running`, `completed`,
  `partially_completed` (some sources not configured / unavailable), `completed_with_errors` (some lookups failed
  part-way), `failed` (nothing could be checked) or `cancelled` (interrupted). Every run stores which **components**
  ran (`scan_runs.components`): e.g. "DNS resolution ✓", "Telegram API ⚠ Not configured", "Web search - DuckDuckGo
  ⚠ Unavailable (rate-limited)". The run state is derived from the components by one function.
- **Unknown is never "no":** a DNS timeout/SERVFAIL is *unresolved* (not "unregistered"); a page that answered but
  could not be captured is "unknown (capture failed)" (not "offline") and an existing alert is left untouched; WHOIS,
  TLS, download and Telegram-credential problems are reported, not hidden. A failed email analysis is marked
  `failed` with its reason instead of staying `queued`.
- **Integrations page** (`GET /api/v1/integrations`): every tool the code uses, whether it is configured, and how it
  last ran — `Not run yet` until there is real evidence, never assumed OK.
- **Dashboard:** "No threats detected." only after a scan has completed, with the number of scan parts that could not
  run; "No scans have run yet" otherwise; every page shows an error panel (with Retry) when the API fails.
- **Why:** owner requirements RDA-01…04, 17, 19, 21 — "Unable to scan — tool unavailable" must never look like
  "Scan successful".
- **Demo line:** "When a source is down, the platform says so — a quiet dashboard means 'checked and clean', never
  'couldn't check'."

## D-32 · No demo mode in the product
- **Decision (owner-approved spec, 2026-10-09, SP1):** `brands.demo_mode`, `ALLOW_DEMO_MODE`, `FIXTURES_DIR` and
  `FIXTURES_BASE_URL` are removed from the product; the brand API rejects a `demo_mode` field. The simulated sources
  and the fictional test brand live only in `backend/tests/support/` and `backend/tests/fixtures/` and are injected
  into the real module runners by the tests. The migration refuses to run while a demo brand exists.
- **DEL-08** ("sample monitoring data: demo brand + fixtures + seed script") is satisfied **inside the test suite
  only** (`backend/tests/support/seed_test_brand.py`); the owner's addendum (RDA-04) overrides it for the product.
- **Kept:** `FETCH_ALLOW_PRIVATE_HOSTS` — empty by default, refused in production; it only lets tests reach the local
  test website.
- **Demo line:** "There is no switch that can put fake data in front of an analyst — test data cannot reach the
  product."

## D-33 · Candidate → Finding → Alert (SP2)
- **Decision (owner-approved spec, 2026-10-09):** every detection is stored as a **finding** (one per entity per brand)
  in stage **Candidate** (discovered, weak — e.g. registered look-alike with no website and no MX, name-only app/APK
  match, bare search hit, document that could not be downloaded) or **Finding** (analysed, with evidence). Each module
  decides via `Detection.analysed`. A Finding never goes back to Candidate.
- **Demo line:** "Discovery is not an alert. We only alert after we've looked."

## D-34 · Alert rule
- **Decision:** an alert is raised only for stage Finding with risk at or above the brand's **"Alert from"** level
  (`brands.alert_min_level`, default Medium). SP3 adds a confidence condition to the same rule.

## D-35 · Analyst decisions
- **Decision:** New, Investigating, Confirmed Threat, False Positive, Legitimate, Ignored, Resolved — stored on the
  finding with who/when/note. A note is required for False Positive, Legitimate and Ignored. "Reopened" is a timeline
  event (decided finding back to New). Legitimate can add the entity to the brand allowlist. Bulk decisions are
  all-or-nothing.

## D-36 · Re-scans and meaningful changes
- **Decision:** every sighting is an **observation**; the engine diffs comparable facts (live, login form, logo, MX,
  APK signer mismatch, app listed, stage, risk level up) and writes them to the timeline. A new alert is raised on first
  crossing of the rule, or on a meaningful change. After False Positive / Legitimate / Ignored / Resolved, alerts are
  suppressed until a meaningful change re-opens the finding. Unknown values (failed capture) are never compared.

## D-37 · Phase 1 alerts migrated with the same IDs
- **Decision:** the migration renames `alerts` → `findings` (same IDs), creates one migrated observation and one alert
  record per finding (also same ID, so old links work), maps statuses (Under Review → Investigating, Confirmed →
  Confirmed Threat, Closed → Resolved) and turns `alert_events` into the finding timeline.

## D-38 · Social media brand-misuse monitor
- **Decision (owner, 2026-10-09):** new module `social_media` for posts, videos, ads and channels across YouTube,
  Facebook, Instagram, X, Threads, Meta ads, Pinterest, TikTok, LinkedIn and Telegram. Official APIs when a key is set
  (YouTube Data API, Meta Ad Library, Threads keyword search, X API, Telethon), site-restricted web search otherwise;
  no paid scrapers (reversed by D-43: Apify); evidence = link + thumbnail + screenshot (no video download). Accounts on X/Facebook/Instagram/
  LinkedIn/Telegram stay in the impersonation module to avoid double findings.
- **Scoring:** brand mention 20 (Low — recorded, not alerted), logo 20, fake contact details (phone/WhatsApp/Telegram/
  UPI) 30, scam wording 20, paid ad 10.
- **Facebook Pages (added 2026-10-09):** with META_APP_ID/META_APP_SECRET the module searches Facebook Pages
  (Graph API pages/search) and reads their details and recent posts; needs Meta's Page Public Content Access.
- **Tuned 2026-10-10 (live test, brand Navi):** YouTube also runs scam-shaped searches (`SOCIAL_MEDIA_SCAM_QUERIES`:
  "<brand> customer care number", "helpline number", "kyc update", "loan fraud", "refund"; most relevant first, last
  `SOCIAL_MEDIA_SCAM_LOOKBACK_DAYS`=365, 50 results each, region IN) — found 171 relevant videos instead of 26. A short
  brand name with fake contacts or strong scam wording counts as relevant. Only phone / WhatsApp / UPI count as fake
  contacts (Telegram links are usually the creator's channel, shown as "Other Links"); only strong scam wording
  ("customer care", "helpline", "KYC update", "guaranteed returns", "processing fee"…) scores — "refund", "cashback",
  "loan" are shown but not scored. Cost: about 750 YouTube quota units per brand per scan.
- **Known limit:** the Meta Ad Library API returns commercial ads only when they were shown in the EU/UK; for India it
  returns political/issue ads. Stated on the Integrations page.
- **Demo line:** "Every misuse comes with the screenshot, the link and the exact phone number or UPI ID being pushed."

## D-39 · Owner controls automatic scans (cost)
- **Decision (owner, 2026-10-10):** a master switch (Settings → Automatic scans, admin only) plus, per brand,
  on/off, frequency (daily / every 3 days / weekly) and which scanners run automatically. **Default OFF** for new
  and existing brands. Scheduled jobs (02:00 UTC daily check, domains re-check every 6 h for daily brands) queue
  scans only for brands that are on and due. "Run scan now" is never affected.
- **Demo line:** "Nothing spends API quota unless you switch it on — per brand, per scanner, per frequency."

## D-40 · APK stores searched directly
- **Decision (2026-10-10):** besides web search, the Fake APK module now searches the stores themselves: Aptoide's
  public JSON API (gives each build's signing-certificate owner and SHA-1 and a direct APK link) and APKMirror's
  search page. Found live: every DuckDuckGo-only APK scan had failed (rate-limited), so nothing was searched.
- **Known limit:** from the development network APKPure, APKCombo and APKMonk refuse connections (network-level
  block); they are covered only through web search with an API key, or from a server on another network.

## D-41 · App stores: Google Play detail pages and the Apple App Store
- **Decision (owner, 2026-10-12, options A + B):** Google Play is searched in English and Hindi (`PLAY_STORE_LANGS`,
  `PLAY_STORE_COUNTRY`, `PLAY_STORE_HITS`); each flagged app's detail page is read (developer e-mail, website,
  address, installs, version, update date, privacy policy, full description) and its store page screenshotted. The
  description is checked for fake contact details and strong scam wording; a developer using a free e-mail address is
  shown. The **Apple App Store** is searched with Apple's free official iTunes Search API; removals are tracked per
  store. ROG-02 (other stores) is no longer deferred.
- **Precision rules (from the live Navi test):** whether an app is "about the brand" is decided from its title,
  subtitle, developer and package only — never the long description (it mentions addresses like "Navi Mumbai" and
  partner apps). The brand's core name must appear, or the title must be a ≥ 90 % look-alike of a long brand name, or
  the icon must match the logo. Placeholder UPI IDs (name@…, yourname@…) are ignored.
- **Demo line:** "Every look-alike app on both stores, with the developer's real contact details and a screenshot."

## D-42 · Common Crawl and a wider APK site list
- **Decision (owner, 2026-10-12):** the Fake APK module also looks up Common Crawl's URL index for archived listing
  pages whose URL starts with the brand slug on APK sites (apkpure.com/.net, apkcombo.com, m.apkpure.com,
  apkfab.com, apksupport.org), in the newest `COMMON_CRAWL_COLLECTIONS` (2) monthly crawls, paced
  (`COMMON_CRAWL_PACE_SECONDS`) and time-boxed (`COMMON_CRAWL_BUDGET_SECONDS`=240 per brand), cached 30 days. Archived
  HTML is read from Common Crawl's WARC files, so sites blocked on the network are still read; archived download
  links are never followed. Search results are accepted from ~25 known APK sites (softonic, apponic, apkpure.net…).
- **Live result (Navi):** 12 lookups, no archived Navi listing pages — Common Crawl samples each site, so its yield
  is low; SerpAPI (Google) is the main discovery source. `COMMON_CRAWL_ENABLED=false` switches it off.

## D-43 · Apify for social platforms without a usable official search API
- **Decision (owner, 2026-10-14):** reverses the "no paid scrapers" part of D-38. With `APIFY_TOKEN` set, Apify
  actors search **Instagram** (hashtag posts/reels + account search), **TikTok** (videos + account search),
  **Facebook** posts (keyword search), the **Meta Ad Library** (all ads incl. commercial ads in India, which the
  official API does not return), **X** and **LinkedIn** posts. They run *next to* the official APIs and web search,
  never instead of them; **YouTube keeps its official API**. The authors of those posts and ads and the Instagram/
  TikTok account searches also feed the impersonation module (real bio, followers and avatar instead of a search
  snippet), and TikTok is a new impersonation platform.
- **Actors (configurable, `APIFY_ACTOR_*`):** apify/instagram-hashtag-scraper (keyword post search; the main
  scraper's search goes through Google and returned nothing in the live test), apify/instagram-scraper (accounts), clockworks/tiktok-scraper,
  scraper_one/facebook-posts-search, apify/facebook-ads-scraper, apidojo/tweet-scraper, harvestapi/linkedin-post-search.
  Searches: the brand terms (last `SOCIAL_MEDIA_LOOKBACK_DAYS`) plus the first `APIFY_SCAM_QUERIES` (3) scam searches
  (last `SOCIAL_MEDIA_SCAM_LOOKBACK_DAYS`).
- **Cost control:** `APIFY_ITEMS_PER_QUERY` (20) results per search and platform, `APIFY_MAX_CHARGE_USD` (0.5) cap per
  run, runs aborted after `APIFY_RUN_TIMEOUT_SECONDS` (300, results so far kept), identical searches cached
  `APIFY_CACHE_MINUTES` (180) so both modules share one run; `APIFY_PLATFORMS` switches platforms off. Automatic
  scans stay under D-39.
- **Honest status (D-31):** each platform is its own scan component ("Apify Instagram", …) and Integrations entry:
  not configured / skipped / failed (with the actor's error) — never an empty "nothing found". The same post found by
  Apify and web search is reported once (URL de-duplication).
- **Known limits:** these platforms' terms forbid scraping (owner accepted the risk); community actors can break when a
  platform changes — the run is then reported as failed and web search still runs.
- **Demo line:** "Instagram, TikTok, Facebook, X and LinkedIn scanned with likes, views and the real account behind
  every scam post."

## D-44 · A null MX ("0 .") is not an email-enabled domain
- **Problem:** many registered look-alikes (e.g. banknavi.com, bnavi.com) publish the RFC 7505 *null MX* `0 .`, which
  means "this domain accepts no email". It was counted as an MX record, so these domains landed in MX Record
  Monitoring, got +15 (`mx_present`) and some reached Critical.
- **Decision:** the DNS lookup drops MX records without a mail host; `MX Enabled`, `Email Risk` and the score now
  reflect only real mail servers. Existing findings are re-scored on the next scan (stage never moves back, D-19).

## D-45 · Evidence before severity: fixes from the first live Navi audit (2026-10-15)
Audit of the live data (1 brand, 685 findings, 498 alerts, **no analyst labels yet** — every finding was New, so
precision/recall cannot be measured; see "Still open"). Four verified false-positive causes, each fixed at its root:
- **Domains with no website were uncapped** — the name + an MX record reached Critical (90) with nothing
  pretending to be the brand. Now `no_website` caps them at **High (79)**: Critical needs the page to show the brand.
- **Unrelated live sites were Medium alerts** (59 of them: shops, job sites, `ivan-benavides.com`). The
  `no_brand_evidence` cap is now **Low (29)**; a page that asks for a login or payment without brand content stays
  **Medium** (`no_brand_login_form`), so a brand-less credential page is not hidden.
- **Social media: any phone number or any "helpline" wording was Critical** (101 YouTube items, incl. a jeweller in
  "Navi Mumbai"). Now Critical = contact details **and** a support claim or scam wording; a claim without a visible
  number is High (check the video); a number without support wording is Medium. A short brand name (D-25) plus a
  phone number is no longer brand context on its own — it needs scam wording.
- **Findings for assets that later became official stayed open** (`navi.com` was a Critical phishing finding).
  After every scan, open findings whose exact value (or a subdomain of an official domain) is on the allowlist are
  closed as Legitimate with a timeline note (`close_authorized`). Exact match only — never by IP, host or keyword.
- **Reproducible scores:** every stored score carries `"policy": "2026-10-15"` (`SCORING_POLICY`).
- **Applied to stored data** with `python -m scripts.rescore_domains` (re-checks MX, D-44) and
  `python -m scripts.rescore_social`: 73 domain and 100 social levels changed, 1 finding closed as allowlisted,
  3 closed as Ignored (reopenable). Critical: 18 MX + 101 social → 0 domain + 1 social.
- **Still open (next stages):** analyst labels → precision per module; threat-intel corroboration for domains
  (URLhaus/OpenPhish/urlscan already used for email links); a separate confidence score; correlation of shared
  infrastructure (SP3/SP4). Ollama/LLM assistance is deferred until labels exist to measure whether it helps.

## D-46 · Threat intelligence for look-alike domains (2026-10-16)
- **What:** every registered look-alike is checked against **OpenPhish** (public feed, no key; any listed URL on
  the domain or a subdomain), **urlscan.io** (`URLSCAN_API_KEY`; a public scan of the domain with a malicious
  verdict) and **URLhaus** (`URLHAUS_AUTH_KEY`; host listed for malware). Same sources and cache as the email
  module (`app/modules/email/intel.py`); new adapters in `app/modules/domains/reputation.py`.
- **Corroboration rule (same as email):** listed by **≥ 2 distinct sources** → `known_malicious_url` (+40) and the
  `no_website` / `no_brand_*` caps no longer apply (observed malicious behaviour, not just a name); a live listed
  site is Suspected Phishing. **One source** → `single_source_url_hit` (+15), caps stay. A parked page stays Low
  (the listing is stale). AbuseIPDB is **not** used for domains: one IP hosts thousands of unrelated sites.
- **Honest status (D-31):** each source is its own scan component ("Threat intel - OpenPhish", …): ok with
  checked/listed counts, `not_configured` when its key is missing, `failed` when lookups failed — never "not listed".
  The finding shows **Threat Intel** ("Listed by OpenPhish (not checked: urlscan.io, URLhaus)") and keeps every
  verdict with its time as evidence. A domain that becomes listed raises a new alert ("Listed by threat
  intelligence", D-36); a listed domain with no website or MX is a Finding, not a Candidate.
- **Limits:** the OpenPhish community feed holds only a few hundred current URLs, so without the two free keys
  coverage is small. Scoring policy version `2026-10-16`.

## D-47 · Confidence is scored separately from risk (SP3, RDA-08, 2026-10-16)
- **Risk** (0-100, unchanged) = how bad it would be. **Confidence** (0-100; Low < 40, Medium 40-69, High ≥ 70) =
  how sure we are that it is a real brand threat. They are stored side by side (`signals.confidence`, the
  **Confidence** field), never mixed into one number.
- **Factors** (`app/core/confidence.py`, policy `2026-10-16`), each kept with its points and reason:
  base 20; each *independent kind* of evidence (page content, contact details, logo/favicon, verified identity
  mismatch) +15, infrastructure +5, two threat-intel sources +30 (one: +10); two or more kinds agreeing +10;
  name only −10; Finding +10 / Candidate −10; captured screenshot/page/file +10. Unknowns: capture failed −10,
  WHOIS failed −5, threat intel incomplete −5, engines not checked −10, search snippet instead of platform data
  −10. Contradictions: parked −20, live page without brand content −15. APK signer verified +25 / unverified −10.
  Email posture and DMARC are facts read from DNS/reports: 70.
- **One kind counts once**: three scam phrases are one confirmation, not three (no double counting).
- **Use:** sort alerts and findings by "Most certain"; the score panel lists every factor. Stored findings were
  assessed with `python -m scripts.assess_confidence` (no re-fetch, risk and decisions untouched).
- **Not calibrated:** confidence 80 does not mean 80 % probability. Calibration needs analyst labels.

## D-48 · Domain scans finish within a time budget and continue where they stopped (2026-10-16)
- **Problem:** Navi now has ~240 registered look-alikes. Each was captured in a browser one after another (up to
  ~40 s each), so the scan ran into the worker's 60-minute hard limit and was killed (10-13 and 10-16) — no final
  status, and the domains late in the alphabet were never checked.
- **Decision:** website captures run in parallel (`DOMAIN_CHECK_WORKERS`, 3 browsers; everything that touches the
  database stays in one thread). The scan stops starting new domains after `DOMAIN_SCAN_BUDGET_SECONDS` (45 min,
  counted from the start of the scan) and reports "Domain checks: N of M registered domains not checked within the
  time budget" (`unavailable` → the run is **partially completed**, D-31). Domains never checked, or checked
  longest ago, go first, so the next scan continues with the ones that were skipped.
- **2026-10-16, follow-up to D-46 (urlscan.io free plan):** free urlscan plans reject searches on
  `verdicts.malicious` (HTTP 403). The lookup now searches the domain's latest 3 public scans and reads each
  scan's own verdict from its result. A failing source now shows why on the scan (e.g. URLhaus
  `unknown_auth_key`).

## D-49 · Correlation: findings that share a stable identifier are linked (SP4, RDA-14/16, 2026-10-16)
- **What is linked:** every finding stores the identifiers in its own evidence (`finding_indicators`, migration
  `f3a8c2d61e47`): TLS certificate SHA-256 (only when the certificate is issued for that domain), non-official APK
  signer, file SHA-256, scam phone/WhatsApp number (last 10 digits, so `+91 98765…` = `wa.me/9198765…`), UPI ID,
  Telegram contact, developer e-mail and website, a look-alike domain linked from a phishing email, and a mail
  server that is itself one of the brand's look-alike domains. Each link shows the shared value and where it was
  seen; history is kept (first/last seen).
- **What is NOT proof:** shared IP address and favicon are *weak* links — shown, never forming campaigns. A third-
  party mail or parking host (the first live run linked 9 domains through `localhost` and 7 through the parking
  company `above.com`) never links findings: a mail server only counts when its domain is a look-alike finding.
  Values shared by more findings than a per-kind limit are treated as generic and ignored.
- **Campaigns** = findings connected by strong links (union-find) — "probably one operator", never attribution.
  `GET /api/v1/brands/{id}/campaigns`, `GET /api/v1/findings/{id}/related`; the finding and alert pages show a
  **Related findings** panel. A strong link adds +10 confidence ("same operator likely", D-47); risk is unchanged.
- **First live result (Navi):** 3 campaigns, each one YouTube channel reusing one phone number across 2-3 videos
  (e.g. a debt-settlement channel targeting Navi loan defaulters). Stored findings: `python -m scripts.correlate`.
- **Fix found by the database tests:** the D-45 auto-close must never close fake APKs by package name — a
  repackaged APK keeps the official package; only the signer tells it apart (D-26). Live data was not affected.
