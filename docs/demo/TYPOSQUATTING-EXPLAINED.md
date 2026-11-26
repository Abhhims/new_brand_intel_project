# Typosquatting Detection — Complete Explanation

> Demo-prep document. Covers what typosquatting is, how our code finds look-alike domains, which tools it uses and
> why, what data it checks, how risk and confidence are calculated, what it can miss, and which paid tools / APIs
> could make it stronger.
>
> Related: [DEMO-GUIDE.md](DEMO-GUIDE.md)

---

## 0. Tools in simple words (quick look)

### Tools we use today

| Tool | What it is (simple) | What we use it for | Why we use it |
|---|---|---|---|
| **dnstwist** | A spelling-mistake maker | Makes ~7,000 fake versions of the brand domain (zentrva.com, zentrova-kyc.in…) | We can't search all domains, so we guess what attackers would register |
| **Affix word list** | Our list of 28 "scary" words | Adds login, kyc, pay, care, secure… to the brand name | Attackers use these words to look official |
| **crt.sh** | A public search of all SSL certificates | Finds real domains that contain the brand name | Catches domains our guessing can't think of |
| **dnspython** | A tool that asks "does this domain exist?" | Checks all 7,000 guesses quickly | Most guesses don't exist — we keep only the real ones |
| **Public DNS (1.1.1.1, 8.8.8.8, 9.9.9.9)** | Internet's phone book servers | Answer the "does it exist?" questions | Fast, free, reliable |
| **whoisit (RDAP)** | Domain ownership lookup | Who registered it, when, which registrar | A domain made last week is more suspicious |
| **Playwright + Chromium** | A robot web browser | Opens the website and takes a screenshot | Shows exactly what a victim would see |
| **pagecheck (our code)** | A page reader | Looks for login box, OTP/KYC words, brand name, "for sale" text | Tells us if the page is fake login or just parked |
| **imagehash** | A picture comparer | Compares site images with the brand logo | Fake sites copy the real logo |
| **mmh3** | An icon fingerprint | Compares the small browser-tab icon | Copied icon = copied site |
| **rapidfuzz** | A "how similar?" meter (0–100) | Measures how close the fake name is to the brand | Higher similarity = easier to fool people |
| **tldextract / idna** | Domain name splitter / decoder | Reads `login.zentrova-kyc.co.in` correctly; decodes `xn--…` names | Gets the real name right, including foreign letters |
| **SSL check** | Certificate reader | Does the site have HTTPS, who issued it | A padlock makes fake sites look trusted |
| **SPF / DMARC check** | Email-setup reader | Can this fake domain send email? | Email-ready fakes are used for phishing mails |
| **OpenPhish** | Free list of known phishing sites | Is this domain already reported? | Confirms it's bad |
| **urlscan.io** | Website scanning service | Has anyone scanned it and found it malicious? | Second opinion |
| **URLhaus** | Malware site list | Is it spreading malware? | Third opinion (we trust only when 2 agree) |
| **Safe fetcher (our code)** | A safety guard for web calls | Blocks access to our own internal network | Fake sites could try to attack us |
| **Redis** | Short-term memory | Remembers answers for 6–24 hours | No repeated calls, no API bans |
| **Celery + beat** | Job runner + alarm clock | Runs scans daily 2 AM and every 6 hours | Automatic, in the background |
| **Postgres** | Main database | Stores findings and history | Search, filter, track changes |
| **RustFS (S3)** | File storage | Keeps screenshots, HTML, WHOIS files | Proof / evidence for each finding |

### Extra tools we could add later

| Tool | What it is (simple) | What it would give us | Free / Paid |
|---|---|---|---|
| **CertStream** | Live feed of new SSL certificates, second by second | Find a fake site minutes after it gets HTTPS (today: next scan) | Free |
| **ICANN CZDS** | Daily full list of domains for .com, .xyz, .online… | Spot every new domain with the brand name, any spelling | Free (approval needed) |
| **WhoisXML API** | Daily list of all newly registered domains | Catches new fakes on all endings incl. .in | Paid |
| **DomainTools** | Domain investigation platform | Risk score at registration, find the attacker's other domains | Paid (enterprise) |
| **SecurityTrails** | Domain history database | Old DNS/WHOIS records, linked domains | Paid |
| **Silent Push** | Early-warning service | Spots attacker setup before the site goes live | Paid (enterprise) |
| **Censys / Shodan** | Search engines for servers | Find servers using the brand's icon or title | Paid (small free tier) |
| **Google Web Risk** | Google's list of dangerous sites | Much bigger "known bad" list | Pay per use (free quota) |
| **VirusTotal** | 70+ antivirus engines in one place | Many opinions on one domain | Free (limited) / Paid |
| **Spamhaus DBL** | Blocklist of bad domains | Another "known bad" source | Free (small) / Paid |
| **Netcraft, Bolster, PhishLabs, ZeroFox** | Brand protection companies | Detection **and taking the fake site down** | Paid |

---

## 1. What is typosquatting?

An attacker registers a domain that **looks like the brand's real domain**, hoping people will not notice the
difference:

| Real domain | Look-alike | Trick |
|---|---|---|
| zentrova.com | zentrva.com | letter missing |
| zentrova.com | zentorva.com | letters swapped |
| zentrova.com | zent4ova.com | letter replaced |
| zentrova.com | zentrova-kyc.in | attacker word added + other TLD |
| zentrova.com | zеntrova.com | Cyrillic "е" instead of Latin "e" (homoglyph) |
| zentrova.com | zentrova.in | same name, other ending |

These domains are used for **fake login pages (phishing)**, **fake emails**, **fake customer-care pages**, or are
simply **parked / for sale**. Our job: find them early, check what they are doing, and rate how dangerous they are.

### Key point for the demo

> There is **no public list of all registered domains** that we can search by keyword.
> So the system works in two ways:
> 1. **Generate** every look-alike an attacker is likely to register, then **check each one in DNS**.
> 2. **Discover** real domains carrying the brand name from **Certificate Transparency** logs.

---

## 2. Where the brand data comes from (input)

From the brand configuration (Brands page):

| Field | Used for |
|---|---|
| **Allowlist → Domain** (e.g. `zentrova.com`) | The seed for generating look-alikes. Also excluded from results (never flagged). |
| **Keywords** (e.g. `zentrova`) | Certificate Transparency search; similarity comparison; brand-on-page check |
| **Logos / favicon** (Brand assets) | Image match against the look-alike website |
| **Alert minimum level** | Which findings become alerts (default Medium) |

If no official domain is set, the seed is `<first keyword>.com`.

---

## 3. Tools we use — what and why

| # | Tool / API | Type | What it does here | Why this choice | Cost |
|---|---|---|---|---|---|
| 1 | **dnstwist** (Python library) | Open source | Generates look-alike names (only its *generator* — we do our own DNS) | The industry-standard typo generator; covers ~15 attack patterns; maintained; used by many security teams | Free |
| 2 | **Our affix list** (28 words) | Own code | Adds attacker words: login, secure, verify, kyc, pay, bank, support, care, official… | dnstwist's default dictionary is generic; these are the words seen in Indian BFSI phishing | Free |
| 3 | **crt.sh** | Public API | Searches Certificate Transparency logs for any certificate containing the brand name | Finds domains guessing can't (e.g. `my-zentrova-rewards.com`); every HTTPS site must publish its certificate | Free, no key |
| 4 | **dnspython** | Library | Asks DNS whether each candidate exists (NS, A, MX, TXT records) | Fast, direct control of resolvers and timeouts; we can tell "doesn't exist" from "timed out" | Free |
| 5 | **Public DNS resolvers** (Cloudflare 1.1.1.1 / 1.0.0.1, Google 8.8.8.8 / 8.8.4.4, Quad9 9.9.9.9) | Service | Answer the DNS questions | Fast and consistent for thousands of lookups; rotated to spread load | Free |
| 6 | **whoisit** (RDAP) | Library + registry APIs | Registrar, creation date, expiry, status | RDAP is the modern JSON replacement for WHOIS; official registry data, no scraping | Free |
| 7 | **Safe fetcher** (`core/fetch.py`, httpx) | Own code | Port check (443 / 80), TLS certificate read; blocks internal IPs (SSRF) | We visit attacker-controlled hosts — must never be tricked into hitting our own network | Free |
| 8 | **Playwright + Chromium** | Headless browser | Opens the site like a real user: screenshot, HTML, text, title, final URL after redirects, favicon, images, password field | Phishing pages are JavaScript-heavy; a plain HTTP fetch misses them | Free |
| 9 | **pagecheck.py** | Own code | Phishing words, brand on page, official links, parked page detection | Explainable rules an analyst can verify | Free |
| 10 | **imagehash + Pillow** | Library | pHash + dHash compare page images with brand logos (≥ 85 = match) | Survives resizing / recompression of a copied logo | Free |
| 11 | **mmh3** | Library | Favicon hash (same method Shodan uses) | Exact copied favicon = instant match | Free |
| 12 | **rapidfuzz + homoglyph folding** (`core/similarity.py`) | Library + own code | 0–100 similarity between the look-alike and the brand; reads `0`→o, `rn`→m, Cyrillic→Latin | Fast; homoglyph-aware so `zentr0va` = `zentrova` | Free |
| 13 | **tldextract / idna** | Library | Splits `login.zentrova-kyc.co.in` → label `zentrova-kyc`; decodes `xn--…` punycode | Correct handling of multi-part TLDs (`.co.in`) and Unicode domains | Free |
| 14 | **OpenPhish feed** | Threat intel | Is any URL on this domain a known phishing URL? | Free public feed, refreshed every 6 h | Free |
| 15 | **urlscan.io API** | Threat intel | Latest 3 public scans of the domain and their verdicts | Large community scan database | Key (free tier) ✅ set |
| 16 | **URLhaus API** (abuse.ch) | Threat intel | Is the host distributing malware? | Trusted, free | Key (free) ✅ set |
| 17 | **Redis** | Cache | Caches intel results 24 h, OpenPhish feed 6 h; rate limits | Avoids repeat API calls and bans | Free |
| 18 | **Celery + beat** | Scheduler | Runs the scan daily 02:00 + domain re-check every 6 h | Background, retryable, time-limited | Free |
| 19 | **Postgres + RustFS (S3)** | Storage | Findings, `domain_checks` history; screenshots, HTML, WHOIS JSON as evidence | Queryable history + durable evidence files | Free |

**Paid APIs used by this module today: none.** Everything runs on free / open-source tools; urlscan and URLhaus use
free keys.

---

## 4. How the code works — step by step

Files: `backend/app/modules/domains/variants.py`, `module.py`, `infra.py`, `reputation.py`,
`backend/app/modules/pagecheck.py`, `backend/app/core/scoring.py`.

```
Brand config (official domain + keywords)
        │
        ▼
STEP 1  Generate look-alikes ............ dnstwist + 28 affixes + 11 TLDs   (~7,000 names)
STEP 2  Certificate Transparency ........ crt.sh "%keyword%"                 (+ real domains)
        │
        ▼
STEP 3  DNS check (128 parallel) ........ dnspython → 1.1.1.1 / 8.8.8.8 / 9.9.9.9
        │   not registered (NXDOMAIN) → dropped (most of them)
        │   timeout → "unknown", retried next scan
        ▼   registered → continue
STEP 4  WHOIS / RDAP (16 parallel) ...... whoisit, 7-day cache
        │
        ▼
STEP 5  Website probe (3 parallel) ...... port 443/80 → Playwright capture
STEP 6  Page analysis ................... keywords, password box, brand, logo, favicon, parked
STEP 7  TLS + email readiness ........... certificate; SPF / DMARC of the look-alike
STEP 8  Threat intel .................... OpenPhish + urlscan.io + URLhaus
        │
        ▼
STEP 9  Signals → points → caps → level; Suspected-phishing rule; stage
STEP 10 Save: Finding (+ Alert), domain_checks row, evidence files
```

### STEP 1 — Generate look-alikes (`variants.py`)

1. **Exact name on every monitored TLD first**: `zentrova.in, .net, .org, .co, .io, .uk, .us, .ae, .sg, .au`.
   This is the most common squat. TLD list = `TYPO_TLDS` setting
   (`com, in, net, org, co, io, uk, us, ae, sg, au`).
2. **dnstwist fuzzers** on the official domain, with our 28 affix words as the dictionary.
3. **Cross-TLD**: most patterns (omission, replacement, transposition, insertion, affix, hyphenation…) are repeated on
   every monitored TLD. Homoglyph and bit-flip stay on the official TLD only (they are very numerous).
4. **Cap 12,000 names**; if over, homoglyph and bitsquatting are dropped first (lowest yield).
5. **Official domains are removed** — the brand is never flagged against itself.

Real output for `zentrova.com` (run inside the worker):

| Pattern | dnstwist fuzzer(s) | Count | Examples |
|---|---|---:|---|
| TLD variation | tld-swap | 10 | zentrova.in, zentrova.net |
| Character omission | omission | 88 | zentroa.com, zentrva.in |
| Transposition | transposition | 77 | zentorva.com |
| Character substitution | replacement, vowel-swap, bitsquatting | 619 | zent4ova.com, zentrovs.com |
| Character insertion | addition, insertion, repetition, plural | 1,441 | zentrovap.com, zentrrova.com |
| Added prefix / suffix | dictionary, hyphenation, subdomain | 1,315 | payzentrova.com, zentrova-login.in, kyczentrova.com |
| Homoglyph | homoglyph, cyrillic | 3,721 | xn--zntrva-bpc3779c.com (Cyrillic е, о) |
| Other | various | 1 | zentrovacom.com |
| **Total** | | **7,272** | |

### STEP 2 — Certificate Transparency (`infra.ct_search`)

- Every HTTPS certificate issued anywhere is published in public CT logs. crt.sh indexes them.
- Query: `https://crt.sh/?q=%zentrova%&output=json&exclude=expired` → every non-expired certificate whose name
  contains the keyword.
- Each name is reduced to its registered domain (`login.zentrova-rewards.com` → `zentrova-rewards.com`).
- Kept only if **similarity ≥ 70** to the brand and not already generated / official.
- **Why:** catches combinations guessing never produces (`my-zentrova-app.net`, `zentrova-rewards-india.com`).

### STEP 3 — DNS check (`infra.resolve_many`)

- 128 threads, resolvers rotated, timeout 1.5 s per try / 3 s total.
- **NS record first** (one question decides "registered"):
  - **NXDOMAIN** → definitely not registered → dropped. (The vast majority of 7,000+.)
  - **NS found** → registered → then fetch **A** (website IP) and **MX** (mail servers).
  - **Timeout / SERVFAIL** → **unknown**, *never* treated as "not registered"; retried next scan. If *everything*
    times out the scan is marked failed (resolver outage) instead of reporting "nothing found".
- **Null MX** (`0 .`) = "this domain accepts no email" → not counted as email-enabled.

### STEP 4 — WHOIS / RDAP (`prefetch_whois`)

- For registered domains only. Registrar, created, expires, status, name servers.
- 16 in parallel; a successful answer is reused for **7 days** (registration data rarely changes).
- If the lookup fails: shown as "lookup failed" (not hidden), confidence −5.

### STEP 5 — Website probe (`web_probe`)

- No A/AAAA record → no website (no browser time wasted).
- Quick TCP check on **443** then **80** (5 s). Only open ports are opened in the browser.
- **Playwright + Chromium** (browser-worker container) loads the page: screenshot, HTML, visible text, title, final
  URL after redirects, favicon, page images, password field, form actions.
- If a port is open but capture fails → website state **unknown** (not "offline"); an existing finding is left
  unchanged and retried next scan.
- Order: **never-checked domains first**, then those checked longest ago; **3** captures at a time; whole scan
  limited to **45 minutes** — anything left is checked first next time.

### STEP 6 — Page analysis (`pagecheck.analyse`)

| Check | How |
|---|---|
| **Phishing words** | 25 words in title + text: login, sign in, secure, account, verify, payment, password, OTP, card number, CVV, PIN, netbanking, KYC, "update your", suspended, unlock, billing, wallet, credentials, authenticate… |
| **Password box** | `<input type="password">` on the page |
| **Brand on page** | Brand keywords in the page text (the page's own domain name is removed first, so `zentrova-login.com` writing its own name doesn't count) |
| **Official links** | Page references the real `zentrova.com` (common in copied sites) |
| **Favicon** | mmh3 hash equal to the official favicon = 100; else image similarity ≥ 85 |
| **Logo** | Every page image vs. brand logos, pHash + dHash average; best score kept; ≥ 85 = match |
| **Parked page** | Hosted on Sedo / HugeDomains / Dan / Bodis / Afternic / Above…, path `/lander`, or text like "domain is for sale", "buy this domain", "parked domain" |

### STEP 7 — TLS and email readiness

- **TLS**: connects to 443 and reads the certificate (issuer, expiry).
- **SPF / DMARC of the look-alike**: if it publishes SPF it is configured to **send** email → "Email-ready".
- **Email Risk** field: MX + live website = High, MX only = Medium, none = Low.

### STEP 8 — Threat intelligence (`reputation.py`)

| Source | Query | Malicious when |
|---|---|---|
| OpenPhish | Downloaded feed (cached 6 h) | Any listed URL on the domain or a subdomain |
| urlscan.io | `page.domain:"<domain>"`, latest 3 scans, each scan's verdict | Any scan verdict `malicious: true` |
| URLhaus | POST `host=<domain>` | Host listed |

- **Corroboration rule:** only **2 or more** different sources = "known malicious". One source = small score only.
- No key / API down → **"not checked"**, never "clean"; shown on the finding and on the Scans page.

### STEP 9 — Score, stage, suspected phishing → see section 6

### STEP 10 — Save

- **Finding** — one per domain per brand (`entity_key = domain`); updated on every scan, never duplicated.
- **domain_checks** row — full history of each check (DNS, WHOIS, HTTP status, title, SSL, favicon hash).
- **Evidence** in RustFS: DNS records, WHOIS JSON, screenshot, favicon, HTML (≤ 500 KB), matched logo image, SSL
  JSON, threat-intel verdicts.
- **Alert** if level ≥ brand's alert level; re-alerts only on meaningful change.

---

## 5. All data we check per domain (what the analyst sees)

| Field | Source |
|---|---|
| Domain, Fuzzer (pattern), Discovery Source | dnstwist / crt.sh |
| Similarity Score, Closest Brand Term | rapidfuzz + homoglyph folding |
| Registered, A Records, MX Records, NS | dnspython |
| Registrar, Created (expiry, status in evidence) | RDAP (whoisit) |
| Website Live, HTTP Status, Final URL, Page Title, Screenshot | Playwright |
| Keywords Found, Brand Terms On Page, Official Site References, Brand Evidence On Page, Parked Page | pagecheck |
| Favicon Match, Logo Match Score | mmh3 / imagehash |
| SSL Present, SSL Issuer, SSL Expires | TLS check |
| MX Enabled, SPF Record, DMARC Record, Email-ready, Email Risk | dnspython |
| Threat Intel (e.g. "Listed by OpenPhish, URLhaus") | OpenPhish / urlscan / URLhaus |
| Suspected Phishing | rule in section 6.3 |
| Risk score / level / fired rules / cap; Confidence | scoring.py / confidence.py |

---

## 6. How risk is calculated (`core/scoring.py`, policy 2026-10-16)

### 6.1 Points

| Rule | Points | When it fires |
|---|---:|---|
| Brand name exact in domain | **40** | `zentrova` appears in the label (hyphens ignored), e.g. `zentrova-kyc.in` |
| Typo similarity > 80 | **25** | rapidfuzz similarity strictly above 80 (e.g. `zentrva` ≈ 93) |
| MX present | **15** | Domain has mail servers |
| HTTPS | **10** | Live site with a certificate |
| Login / payment keywords | **20** | Phishing words or a password box on the page |
| Official logo | **30** | Logo match ≥ 85 |
| Look-alike can send email | **10** | Publishes SPF |
| Known malicious (2+ intel sources) | **40** | Corroborated listing |
| Single intel source | **15** | Listed by exactly one |

Total capped at **100**.

### 6.2 Evidence caps (stop false alarms)

A **name alone is never Critical**. After adding points:

| Situation | Max score | Max level |
|---|---:|---|
| Parked / for-sale page | 29 | Low |
| Live site with no brand content | 29 | Low |
| Live site, no brand content, but has login / payment form | 59 | Medium |
| No website (registered only, or mail only) | 79 | High |
| **Listed by 2+ threat-intel sources** | no cap | — |
| Live site **showing the brand** | no cap | — |

**Levels:** Critical 80–100 · High 60–79 · Medium 30–59 · Low 0–29.

### 6.3 "Suspected phishing" flag

```
Suspected phishing =
   ( site is live
     AND brand shown on page (brand text / official link / favicon / logo)
     AND not parked
     AND similarity ≥ 80
     AND (login/payment form OR favicon match OR logo match) )
 OR
   ( site is live AND listed by ≥ 2 threat-intel sources )
```

### 6.4 Stage (which module column it appears under)

| Condition | Module | Title |
|---|---|---|
| Website live | **Phishing** | "Live look-alike website" / "Suspected phishing website" / "Parked look-alike domain" |
| No website, has MX | **MX** | "Email-enabled look-alike domain" |
| Only registered | **Typosquat** | "Registered look-alike domain" |

A domain that has **no website, no MX and no intel listing** is stored as a **Candidate** (discovered, not
analysed) rather than a **Finding**. Candidates don't alert; they become Findings when something changes.

### 6.5 Worked examples

| Domain | What we saw | Points | Cap | Result |
|---|---|---|---|---|
| `zentrova-login.com` | Live, Zentrova logo, password box, HTTPS, MX | 40+25+15+10+20+30 = 140 → 100 | none (brand on page) | **100 Critical**, Suspected phishing |
| `zentrva.in` | Registered, MX, no website | 25+15 = 40 | no website (79) not hit | **40 Medium** (MX stage) |
| `zentrova.co` | Registered, nothing else | 40+25 = 65 | — | **65 High**, but **Candidate** (no site/MX) |
| `zentrova.net` | Sedo "domain for sale" page | 40+25+10 = 75 | parked → 29 | **29 Low**, "Parked look-alike domain" |
| `zentorva.com` | Live (HTTPS), unrelated blog, has login form | 25+10+20 = 55 | no brand + login → 59 | **55 Medium** |
| `zentrovap.com` | Live (HTTPS), unrelated blog, has login form | 40+25+10+20 = 95 | no brand + login → 59 | **59 Medium** (capped) |
| `zentrova-kyc.in` | Live (HTTPS), no brand visible, listed by OpenPhish + URLhaus | 40+25+10+40 = 115 → 100 | 2+ intel → no cap | **100 Critical**, Suspected phishing |

### 6.6 Confidence (separate from risk — "how sure are we?")

Starts at 20, then:

| Factor | Points |
|---|---:|
| Content abuse (login / payment form) | +15 |
| Visual match (logo / favicon) | +15 |
| Infrastructure (MX, HTTPS, SPF) | +5 |
| 2+ intel sources | +30 (single source +10) |
| 2+ independent evidence kinds agree | +10 |
| Shares certificate / server with other findings | +10 |
| Analysed (Finding) / Candidate | +10 / −10 |
| Screenshot or page captured | +10 |
| Name match only, nothing else | −10 |
| Capture failed / WHOIS failed / intel partial | −10 / −5 / −5 |
| Parked page | −20 |
| Live page shows no brand | −15 |

High ≥ 70 · Medium 40–69 · Low < 40.

---

## 7. Scheduling and limits

| Item | Value | Setting |
|---|---|---|
| Daily full scan | 02:00 UTC (if auto-scan on for the brand) | Celery beat `daily-full-scan` |
| Domain re-check | Every 6 h at :30 | `domain-recheck` |
| Manual | "Run scan now" button | — |
| TLDs monitored | com, in, net, org, co, io, uk, us, ae, sg, au | `TYPO_TLDS` |
| Max variants | 12,000 | `MAX_VARIANTS` |
| DNS threads | 128 | `LiveInfra.workers` |
| WHOIS threads / cache | 16 / 7 days | `WHOIS_WORKERS`, `WHOIS_CACHE_DAYS` |
| Parallel website captures | 3 | `DOMAIN_CHECK_WORKERS` |
| Scan time budget | 45 min (rest next scan, first) | `DOMAIN_SCAN_BUDGET_SECONDS` |
| CT similarity minimum | 70 | `MIN_CT_SIMILARITY` |
| Phishing similarity threshold | 80 | `PHISHING_SIMILARITY_THRESHOLD` |
| Logo match threshold | 85 | `LOGO_MATCH_THRESHOLD` |

---

## 8. Honest limitations (what can be missed)

| Gap | Example | Why | Fix |
|---|---|---|---|
| Two added words | `zentrova-kyc-update.in` | Generator adds one word; caught only if it has an HTTPS cert (CT) | Add 2-word combos, or an NRD feed |
| TLDs not in list | `zentrova.xyz`, `.online`, `.shop`, `.top`, `.site` | Only 11 TLDs monitored | Add to `TYPO_TLDS` (each adds ~600 names) |
| New domain without HTTPS and unusual spelling | `zntrova-help.co` | No guess matches, no certificate | Newly-registered-domain (NRD) feed |
| Homoglyphs on other TLDs | `zеntrova.in` (Cyrillic) | Homoglyphs only on official TLD to limit volume | Raise cap / selective homoglyphs |
| Subdomain abuse on free hosts | `zentrova.netlify.app`, `zentrova-login.web.app` | Subdomains of other companies' domains aren't generated | CT catches some; add hosted-platform search |
| Real-time | detection within minutes of registration | Daily + 6-hourly cycle, crt.sh is polled not streamed | CertStream (real-time CT) |
| crt.sh reliability | crt.sh often slow / 502 | Free community service | Reported as "failed", retried; paid CT API as backup |

---

## 9. Better / paid tools and APIs (market options)

> Indicative — vendors change products and pricing; confirm with the vendor before committing.

### 9.1 Data feeds — find more domains, earlier

| Tool / API | What it adds | Fits our gap | Pricing model |
|---|---|---|---|
| **WhoisXML API — Newly Registered Domains (NRD) feed / Typosquatting Data Feed / Brand Monitor API** | Daily list of all new registrations (hundreds of thousands/day) across gTLDs + many ccTLDs; keyword & fuzzy matching done for you | Two-word combos, any TLD, any spelling — biggest single improvement | Subscription (API credits or annual feed) |
| **DomainTools Iris / PhishEye / Brand Monitor** | Fuzzy-match on new registrations, Risk Score (predicts maliciousness at registration), deep WHOIS history, pivoting on registrant / NS / IP | Earlier detection + investigation | Enterprise licence |
| **SecurityTrails (Recorded Future)** | Historical DNS, subdomains, WHOIS history, associated domains API | Find attacker's other domains (same IP / NS / registrant) | Paid tiers, free trial |
| **Silent Push** | Pre-emptive "indicators of future attack" — infrastructure being prepared before phishing goes live | Very early warning | Enterprise |
| **ICANN CZDS zone files** | Full zone files for ~1,100 gTLDs (.com, .net, .xyz, .online…), daily | Diff today vs yesterday = free NRD feed for gTLDs | **Free** (per-TLD approval); no ccTLDs like .in |
| **CertStream** (Calidog, open source) | Real-time stream of new CT certificates | Detect within minutes instead of next scan | **Free** (self-host the server for reliability) |
| **Censys / Shodan** | Certificate + host search; find servers with the brand's favicon hash / title | Find phishing kits by favicon mmh3 across the internet | Paid tiers (limited free) |

### 9.2 Reputation / verdict APIs — is it malicious?

| Tool / API | What it adds | Pricing model |
|---|---|---|
| **Google Web Risk API** (Safe Browsing for commercial use) | Google's phishing / malware lists — very wide coverage | Pay per call (free quota) |
| **VirusTotal (Google)** | 70+ engines' verdicts on a domain / URL, passive DNS, related domains | Free (non-commercial, low rate) / Enterprise |
| **urlscan.io Pro** | Live scanning, search on verdicts, brand-impersonation detection, retroactive hunting | Paid plans (we use free) |
| **PhishTank / APWG eCrime Exchange** | Community / industry phishing URL feeds | Free / membership |
| **Spamhaus DBL / Domain Blocklist** | Domains used for spam / phishing / malware | Free low volume / paid datafeed |
| **Netcraft** | Phishing site feed + countermeasures | Paid |

### 9.3 Full brand-protection platforms (detection + takedown service)

| Vendor | Known for |
|---|---|
| **Bolster (CheckPhish)** | AI page analysis, automated takedown |
| **ZeroFox** | Domains + social + dark web, takedowns |
| **Fortra PhishLabs** | Managed takedown service |
| **Netcraft** | Fast takedowns, large phishing feed |
| **Recorded Future Brand Intelligence** | Typosquat monitoring inside a threat-intel platform |
| **BrandShield, Red Points** | Brand / marketplace + domain monitoring |
| **CloudSEK XVigil, Cyble** | Strong India / BFSI focus |
| **Memcyco** | Real-time detection when a user visits a cloned site |

These are what we compete with / complement. Our differentiator: self-hosted, explainable scoring (every point is
visible), honest "not checked" status, evidence stored per finding, and India-focused attacker words.

### 9.4 Recommended upgrade path

| Priority | Add | Cost | Effect |
|---|---|---|---|
| 1 | More TLDs in `TYPO_TLDS` (xyz, online, site, top, shop, info, live, app) | Free (config) | Covers cheap phishing TLDs |
| 2 | **CertStream** listener | Free | Real-time CT detection |
| 3 | **ICANN CZDS** daily zone diff | Free | New gTLD registrations with any spelling |
| 4 | **Google Web Risk** as 4th intel source | Low, pay-per-use | Much wider "known bad" coverage |
| 5 | **WhoisXML NRD / Typosquatting feed** | Paid subscription | Covers ccTLDs (.in) and every combination |
| 6 | **DomainTools / SecurityTrails** | Paid | Investigation & pivoting (same attacker's other domains) |
| 7 | Takedown partner (Netcraft / Bolster / PhishLabs) | Paid | Close the loop: detect → remove |

---

## 10. Demo talking points

1. "We generate ~7,000 look-alikes per domain with **dnstwist** plus attacker words like *kyc*, *login*, *care*, and
   also pull real domains from **Certificate Transparency**."
2. "Each one is checked in **DNS** — most don't exist; we keep only registered ones. A timeout is never treated as
   'not registered'."
3. "For registered ones we get **WHOIS**, open the website in a **real browser**, take a screenshot, and check for
   login forms, our **logo** and **favicon**, and whether it's just **parked**."
4. "We ask **OpenPhish, urlscan.io and URLhaus** if it's already known — and we only trust it when **two** agree."
5. "Risk is **points + evidence caps**: a name alone can't be Critical; a parked page is always Low; a live page with
   our logo and a password box is Critical. Every point is shown on the finding."
6. "Confidence is separate: it tells the analyst how sure we are, and drops when something couldn't be checked."
7. "Everything free/open-source today; the upgrade path is NRD feeds, CertStream and Google Web Risk."
