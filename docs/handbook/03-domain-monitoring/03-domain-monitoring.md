# Chapter 03: Domain Monitoring (Typosquat, MX and Active Phishing)

## In this chapter

- How the platform finds look-alike domains of a brand, such as `exampelbank.com` for Example Bank.
- How it checks whether those domains can send email (MX, SPF, DMARC) and whether they host a live website.
- How one pipeline covers three requirement modules (Typosquat, MX, Active Phishing) and produces one finding per domain.
- How the risk score, the "Email Risk" tier and the "Suspected Phishing" flag are worked out, with examples.
- What the pipeline does not do yet.

## 1. What this module detects and why it matters

### Plain words

A **domain** is a website name, such as `examplebank.com`. Anyone can register a new domain for a few dollars.
Attackers register names that look like a real brand's domain. This is called **typosquatting**: the name relies
on a typing mistake or a quick glance. Examples for Example Bank:

| Look-alike | Trick used |
|---|---|
| `exampelbank.com` | Two letters swapped (transposition) |
| `examplebnk.in` | One letter left out (omission), different country ending |
| `examp1ebank.com` | The digit 1 instead of the letter l (homoglyph) |
| `examplebank-login.com` | Extra word added (affix) |
| `examplebank.net` | Same name, different ending (TLD swap) |

A **TLD** (top-level domain) is the ending of a domain: `.com`, `.in`, `.net` and so on.

The pipeline answers three questions about every look-alike, in order:

1. **Is it registered?** (Typosquat stage.) Someone owns it.
2. **Can it handle email?** (MX stage.) It has a mail server, so it can receive replies to phishing email and is
   often set up to send email too.
3. **Is a website live on it?** (Phishing stage.) If yes, the page is captured and checked for login forms,
   the brand's logo and favicon, and brand text.

### Why it matters: an attack story

On Monday an attacker registers `examplebank-secure.com`. On Tuesday they add a mail server. On Wednesday they
put up a copy of the Example Bank login page, with the real logo, and send emails saying "Your account is
suspended, log in to verify". Customers who type their password on that page lose their money.

The platform resolves every generated look-alike daily. It sees the domain on Monday as **Registered look-alike
domain** (Typosquat). After the next scan with the mail server present it becomes an **Email-enabled look-alike
domain** (MX). When the login page goes up it becomes **Suspected phishing website** (Phishing), with a
screenshot as evidence. All of this is one finding with a history, not three (decision D-19).

## 2. Requirements it covers

IDs come from `docs/requirements/01-requirements-register.md`.

| Area | IDs | Summary |
|---|---|---|
| Typosquat | TYP-01 to TYP-08 | Generate variants: omission, substitution, transposition, homoglyph, prefix/suffix, insertion, TLD variation, many TLDs |
| Typosquat | TYP-09 | Newly registered domains (daily resolution plus Certificate Transparency, D-11) |
| Typosquat | TYP-10, TYP-11 | WHOIS and DNS lookups |
| Typosquat | TYP-12, TYP-13 | Daily discovery, similarity score 0 to 100 |
| MX | MX-01 to MX-04 | Resolve and store MX records, "MX Enabled", MX risk tiers (shown as "Email Risk", D-02) |
| Active phishing | PHI-01 to PHI-09 | Live check, title, favicon hash, screenshot, SSL certificate, favicon compare, keywords, Suspected Phishing (D-04), output columns |
| Email readiness | EML-17 | Look-alike flagged when it publishes SPF (it can send email) |
| Scoring | RSK-01 to RSK-06, RSK-09, RSK-10 | Points table and levels |
| Browser | FND-11 | Headless browser for screenshots |
| Acceptance | AC-01, AC-02, AC-03, OBJ-01, OBJ-02 | Proven by acceptance tests (section 11) |

## 3. How it works

### The three stages share one finding

The requirements describe three modules: Typosquat, MX Record Monitoring and Active Phishing Detection.
In the code they are one runner, called `domains` (`backend/app/modules/registry.py`, `RUNNERS`). Asking for any
of the three runs the whole pipeline.

Each finding carries a **stage**:

- `phishing` if a website answered,
- otherwise `mx` if the domain has MX records,
- otherwise `typosquat`.

`record_detection` in `backend/app/core/findings.py` looks for an existing finding for the same domain in any of
the three modules. If one exists it is updated, not duplicated. The stage only moves forward: a phishing site that
goes offline stays a phishing finding. Each stage change is written to the finding timeline as a "stage" event.

### Candidate or Finding? (SP2, D-33)

A registered look-alike with **no website captured and no MX record** is stored as a **Candidate**: it was
discovered, but there is nothing to look at yet, so it never raises an alert. As soon as a website is captured or
an MX record appears, it becomes a **Finding** (`analysed = is_live or MX` in `DomainModule.check_domain`). A
Finding raises an alert only when its risk level is at or above the brand's **"Alert from"** level (default
Medium, D-34).

Each scan stores an **observation** with the comparable facts `live`, `login_form`, `logo_match` and `mx`. The
engine compares them with the previous observation. A fact that turns from false to true ("Website went live",
"Login/payment form detected", "Official logo detected", "Domain can now receive email") is a **meaningful
change**: it goes on the timeline and can raise a new alert, even after an analyst decision (D-36). When the
capture failed, the module sends `live`, `login_form` and `logo_match` as unknown (`None`); unknown values are
never compared, so a failed capture never reads as "went offline".

### Step by step

1. **Scheduling.** Celery beat (the scheduler) starts a scan for every active brand daily at 02:00, and runs the
   `domains` runner again every 6 hours at minute 30 (`backend/app/workers/celery_app.py`). The domains runner
   goes to the `browser` queue, which is served by the isolated browser worker (D-18).
2. **Generate variants.** `generate_variants` (`variants.py`) takes each official domain (for example
   `examplebank.com`) and produces look-alikes with dnstwist plus our affix word list, across 11 TLDs. Maximum
   12,000 per scan. For `examplebank.com` this gives about 8,900 names.
3. **Add Certificate Transparency hits.** For each brand keyword, `ct_search` asks crt.sh for certificates whose
   name contains the keyword. A domain found there is kept only if its name is at least 70 percent similar to the
   brand (`MIN_CT_SIMILARITY`).
4. **Resolve DNS.** `resolve_many` checks every candidate with 128 threads. One NS lookup decides "registered".
   Only registered names get A and MX lookups. Names that answer NXDOMAIN ("no such domain") are dropped. A
   name whose lookup **timed out or got SERVFAIL** is *unresolved*: it is not treated as unregistered, it is
   counted on the "DNS resolution" scan component (which then shows `failed`), and it is retried on the next
   scan (D-31).
5. **WHOIS/RDAP.** `prefetch_whois` gets registration data for registered domains, reusing a successful result
   from the last 7 days (the WHOIS cache) and looking up the rest 16 at a time.
6. **Per domain (`check_domain`):**
   1. Compute name similarity and exact brand match.
   2. Find web ports that accept a connection (443, then 80). Capture the first one that answers with Playwright.
      If a port answered but the capture failed, the website state is **unknown**: the finding shows "Website
      Live: unknown (capture failed)", the website facts are recorded as unknown (so nothing on an existing
      finding changes except "last seen"), and the domain is retried on the next scan (D-31).
   3. If live: analyse the page (`pagecheck.analyse`) and read the TLS certificate.
   4. Look up SPF and DMARC TXT records (email readiness).
   5. Build signals, decide Suspected Phishing, pick the stage and title.
   6. Save a `DomainCheck` row (history) and return a `Detection` with details, evidence, state facts and the
      `analysed` flag.
7. **Score and store.** The scan worker passes each detection to `record_detection`, which scores it
   (`core/scoring.py`), applies D-29 caps, stores the finding (Candidate or Finding), an observation and new
   evidence, writes timeline events, and raises an alert only when the alert rule is met.
8. **Logo follow-up.** If the logo scan was queued in the same batch, it starts after the domain scan and crawls
   the live sites just found (Chapter 08).

### Flow diagram

```
 Brand: official domains + keywords
              |
              v
 +---------------------------+     +-------------------------------+
 | generate_variants         |     | ct_search (crt.sh)            |
 | dnstwist + affixes x TLDs |     | keep if similarity >= 70      |
 +-------------+-------------+     +---------------+---------------+
               |                                   |
               +----------------+------------------+
                                v
                 +-----------------------------+
                 | resolve_many (DNS, 128 thr) |
                 | NS -> registered? A, MX     |
                 +--------------+--------------+
                NXDOMAIN (dropped) | registered
           timeout/SERVFAIL: retry v
                 +-----------------------------+
                 | prefetch_whois (RDAP)       |
                 | 7-day cache, 16 parallel    |
                 +--------------+--------------+
                                v
                 +-----------------------------+
                 | check_domain (each domain)  |
                 |  similarity, exact match    |
                 |  port 443/80 open?          |
                 |   yes -> Playwright capture |
                 |          pagecheck.analyse  |
                 |          TLS certificate    |
                 |  SPF / DMARC TXT lookup     |
                 +--------------+--------------+
                                v
          stage = phishing (live) | mx (has MX) | typosquat
                                v
                 +-----------------------------+
                 | record_detection            |
                 |  score + D-29 cap           |
                 |  one finding per domain     |
                 |  observation + timeline     |
                 |  evidence de-duplicated     |
                 |  alert if Finding and risk  |
                 |  >= brand "Alert from"      |
                 +-----------------------------+
```

## 4. Tools and libraries used

The decision log records few explicit alternatives for these libraries. Where none is recorded, the table says so.

| Tool | What it is | What we use it for | Why this tool (alternatives) | Where in the code |
|---|---|---|---|---|
| dnstwist | Open-source typosquat generator (Python) | Producing look-alike names with its "fuzzers" | Covers every TYP pattern in one library. Design spec section 4.1. No rejected alternative recorded | `backend/app/modules/domains/variants.py` |
| dnspython | DNS client library | NS, A, MX lookups; TXT lookups for SPF/DMARC | Lets us query public resolvers directly, in parallel. No alternative recorded | `backend/app/modules/domains/infra.py`, `backend/app/modules/email/posture.py` (`_resolve_txt`) |
| whoisit | RDAP client library | Registrar, creation and expiry dates | RDAP returns structured JSON. Classic port-43 WHOIS is not used. No alternative recorded | `infra.py` (`LiveInfra.whois`) |
| crt.sh | Free public search site over Certificate Transparency logs | Finding new domains with certificates containing the brand name | Free; a paid newly-registered-domain feed was not chosen (D-11). A `certstream` live listener was planned in the design spec but is not built | `infra.py` (`ct_search`) |
| Playwright + Chromium | Browser automation; headless Chrome | Opening the page, screenshot, text, HTML, image list, password field | Named in the source requirements ("Headless browser (Playwright)"); FND-11. Runs isolated (D-18) | `backend/app/core/browser.py` |
| httpx (safe fetcher) | HTTP client, wrapped in our safety layer | crt.sh queries, favicon and image downloads, port and TLS checks | Every outbound request must pass destination checks, rate limits and size caps (D-18, D-24) | `backend/app/core/fetch.py` |
| Python `ssl` + `cryptography` | Standard TLS library; X.509 parser | Reading the server certificate | Standard tools. Design spec section 4.3 | `fetch.py` (`fetch_certificate`) |
| RapidFuzz | Fast string similarity library | Similarity score 0 to 100 between domain label and brand | Design spec section 4.1. A homoglyph table is in our own code; the `confusable-homoglyphs` package is installed but not used | `backend/app/core/similarity.py` |
| tldextract, idna | Public-suffix parser; international domain decoder | Splitting `login.examplebank.co.in` into its parts; decoding `xn--` names | Offline suffix list, so workers never wait for a download | `similarity.py` |
| ImageHash + Pillow | Perceptual image hashing; image library | Comparing page images and favicons with the official logo | Design spec section 4.3. Shared with logo, APK and social modules | `backend/app/core/imaging.py` |
| mmh3 | MurmurHash3 implementation | Shodan-style favicon hash | The common industry favicon fingerprint (PHI-03) | `imaging.py` (`favicon_hash`) |
| Celery + Redis | Task queue | Scheduling, running scans on the browser worker | Design spec; FND-07 | `backend/app/workers/` |

## 5. How each tool works, explained simply

### dnstwist: generating variants

dnstwist takes a domain such as `examplebank.com` and runs a set of small rules called **fuzzers**. Each fuzzer
makes one kind of change:

| Fuzzer | Example output | Category shown to analysts |
|---|---|---|
| omission | `exampebank.com` | Character omission |
| replacement, bitsquatting, vowel-swap | `exanplebank.com` | Character substitution |
| transposition | `exampelbank.com` | Transposition |
| homoglyph | `examp1ebank.com` | Homoglyph |
| dictionary, hyphenation, subdomain | `examplebanklogin.com`, `example-bank.com` | Added prefix/suffix |
| addition, insertion, repetition, plural | `examplebankk.com` | Character insertion |
| tld-swap | `examplebank.in` | TLD variation |

We pass dnstwist our own list of 28 attacker words (`AFFIXES`: login, secure, verify, kyc, rewards and more) and
our TLD list. We then copy the common fuzzer results onto every monitored TLD. The exact brand name on every TLD
goes first. Homoglyph and bitsquatting results are very numerous, so they are put last and dropped first when the
list is over 12,000.

### DNS and MX lookups

**DNS** (Domain Name System) is the internet's phone book. You ask a **resolver** about a name and get
**records** back:

| Record | Meaning | Used for |
|---|---|---|
| NS | Which name servers are in charge of the domain | Deciding "registered" |
| A | The IPv4 address of the web server | Deciding whether a website can exist |
| MX | Which mail server accepts email for the domain | "MX Enabled", Email Risk |
| TXT | Free text; holds SPF and DMARC policies | Email readiness |

A registered domain has NS records. An unregistered one returns **NXDOMAIN** ("no such domain") quickly. Most
variants are unregistered, so asking only for NS first makes the scan about six times faster
(`docs/guides/OPERATIONS.md`). Queries go straight to public resolvers (1.1.1.1, 8.8.8.8, 9.9.9.9 and others)
with a 1.5-second timeout per try and 3 seconds in total.

**SPF** (Sender Policy Framework) is a TXT record starting `v=spf1` that lists who may send email for the domain.
**DMARC** is a TXT record at `_dmarc.<domain>` starting `v=DMARC1`. A look-alike that publishes SPF is
configured to send email. The code calls this "email-ready" (EML-17, `domain_can_send`).

### RDAP / WHOIS

**WHOIS** is the public register of who registered a domain and when. **RDAP** is its modern version: the same
data as JSON over HTTPS. whoisit first downloads the official "bootstrap" list that says which RDAP server serves
each TLD, then asks that server. We keep the registrar, creation date, expiry date, status and name servers. RDAP
coverage varies by TLD; on failure we store the error text, the alert shows "lookup failed" for Registrar and
Created, and the "WHOIS/RDAP" scan component reports how many lookups failed.

### Certificate Transparency

A website with HTTPS needs a **certificate**, issued by a certificate authority. Every public certificate is
written to public, append-only **Certificate Transparency (CT) logs**. crt.sh is a free website that searches
those logs. A query for `%examplebank%` returns every unexpired certificate whose name contains `examplebank`,
for example `secure-examplebank-banking.in`. New phishing sites almost always get a certificate, so this finds
names our fuzzers never generated (D-11).

### Playwright page capture

Playwright drives a real Chromium browser without a window ("headless"). For each live URL `capture` does this:

1. Checks the URL against the safe-fetcher rules (no internal addresses).
2. Opens a fresh browser: 1366 x 900 window, downloads refused, service workers blocked, certificate errors
   ignored (phishing sites often have bad certificates).
3. Checks every request the page makes with the same rules; blocked requests are aborted.
4. Loads the page (30-second limit), then waits up to 8 more seconds for the network to go quiet.
5. Takes a full-page PNG screenshot.
6. Runs a small script in the page to collect icon links, image URLs (including CSS backgrounds), up to 10 SVG
   drawings, form targets, whether there is a password box, and the visible text.
7. Reads the HTML, title and final URL (after any redirects).
8. Renders visible SVGs to PNG, then closes the browser.
9. Outside the browser, downloads the favicon (declared icons first, then `/favicon.ico`) and up to 40 images,
   each at most 2 MB, through the safe fetcher.

### Name similarity

`similarity` turns both names into plain Latin letters first: it decodes international names, replaces look-alike
characters (a Cyrillic letter that looks like "a", digit "0" for "o", "rn" for "m") and removes accents. It then takes the best of two
RapidFuzz scores:

- **ratio**: how many edits separate the two strings, scaled to 0 to 100. `exampelbank` vs `examplebank` = 90.91.
- **partial ratio**: whether the brand appears almost intact inside a longer name. Only counted if 85 or more.
  `examplebank-login` scores 100.

Because of the homoglyph folding, `examp1ebank` scores 100.

### Favicon hash (mmh3) and perceptual hash

A **favicon** is the small icon in a browser tab. The **mmh3 favicon hash** takes the raw icon bytes, encodes
them as base64 text and runs the MurmurHash3 function over it. The result is one number, the same one the
Shodan search engine uses. Equal numbers mean byte-identical icons. We compare it with the hashes of the favicons
uploaded for the brand.

If the bytes differ (for example the attacker re-saved the icon), a **perceptual hash** is used. pHash and dHash
shrink the picture to a tiny grey grid and record a 64-bit pattern of light and dark. Similar pictures give
similar patterns. The match score is the share of equal bits, averaged over pHash and dHash, from 0 to 100. A
score of 85 or more (`LOGO_MATCH_THRESHOLD`) counts as a match. Chapter 08 explains this in more detail.

### Threat intelligence: is the domain already known as bad? (D-46)

Other people may already have reported a look-alike. Every registered look-alike is checked against three
independent sources (`backend/app/modules/domains/reputation.py`):

| Source | Key | Counts as listed when |
|---|---|---|
| OpenPhish community feed | none (public) | any URL in the feed is on the domain or one of its subdomains |
| urlscan.io | `URLSCAN_API_KEY` (free account) | a public scan of the domain has a malicious verdict |
| URLhaus (abuse.ch) | `URLHAUS_AUTH_KEY` (free account) | the host is listed for malware distribution |

**One source is a hint, two are evidence.** Listed by one source adds 15 points (`single_source_url_hit`) and
the caps below still apply. Listed by two or more *different* sources adds 40 (`known_malicious_url`) and lifts
the "no website" and "no brand content" caps, because someone has seen the domain doing harm. A parked page stays
Low: the listing is old. The finding shows **Threat Intel**, for example "Listed by OpenPhish (not checked:
urlscan.io, URLhaus)", and the verdicts are kept as evidence with the time of the check. A source without its key
shows "Not configured" on the scan, never "not listed". AbuseIPDB (IP reputation) is not used for domains: one
shared-hosting IP serves thousands of unrelated sites.

## 6. Code map

| File | Responsibility |
|---|---|
| `backend/app/modules/domains/module.py` | `DomainModule`: the whole pipeline, stage, details, evidence |
| `backend/app/modules/domains/variants.py` | Variant generation, affix list, fuzzer-to-category names |
| `backend/app/modules/domains/infra.py` | `LiveInfra` (DNS, RDAP, crt.sh, ports, TLS); `DnsInfo.status` is `resolved`, `nxdomain` or `unknown` |
| `backend/tests/support/fixture_sources.py` | `FixtureInfra`: simulated DNS/RDAP/CT/TLS for the automated tests only (D-32) |
| `backend/app/modules/pagecheck.py` | Page analysis: keywords, favicon, logo, brand evidence, parked page |
| `backend/app/core/browser.py` | Playwright capture |
| `backend/app/core/fetch.py` | Safe fetcher, `port_open`, `fetch_certificate` |
| `backend/app/core/similarity.py` | Domain parsing, homoglyph folding, similarity |
| `backend/app/core/imaging.py` | pHash/dHash, match score, mmh3 favicon hash |
| `backend/app/modules/email/posture.py` | `_resolve_txt`, `domain_can_send` |
| `backend/app/core/scoring.py` | Points, levels, D-29 caps, `email_risk` |
| `backend/app/core/findings.py` | `record_detection`: one finding per domain, stage, observations, timeline, evidence storage, alert rule |
| `backend/app/workers/scan.py`, `tasks.py`, `celery_app.py` | Running, queueing and scheduling scans |
| `backend/app/modules/registry.py` | Output fields, module labels, runner mapping |

Key functions in call order:

1. `tasks.run_scan` then `scan.execute_scan`
2. `DomainModule.run`
3. `DomainModule.candidates` (calls `generate_variants`, `infra.ct_search`, `best_similarity`)
4. `infra.resolve_many` (calls `_resolve_one`, `_records`)
5. `DomainModule.prefetch_whois` (calls `infra.whois`)
6. `DomainModule.check_domain` for each registered domain:
   `best_similarity` -> `infra.web_urls` (`port_open`) -> `capture` -> `pagecheck.analyse` -> `infra.tls`
   (`fetch_certificate`) -> `_email_records` -> `domain_can_send` -> `Signals(...)` -> `_page_evidence`
7. `findings.record_detection` (calls `scoring.score`, `_store_evidence`, `meets_rule`)

## 7. Signals and the risk score

Chapter 02 explains the scoring model in full. Here is how this pipeline feeds it.

### Points

| Signal | Points | When it fires in this pipeline |
|---|---|---|
| `brand_exact_in_domain` (RSK-01) | 40 | A brand keyword, without spaces, appears in the domain label (hyphens ignored) |
| `typo_similarity_gt_80` (RSK-02) | 25 | Similarity strictly above 80 (D-05) |
| `mx_present` (RSK-03) | 15 | The domain has MX records |
| `https` (RSK-04) | 10 | Website live and a TLS certificate was read on port 443 |
| `login_payment_keywords` (RSK-05) | 20 | Website live and a phishing keyword or a password box was found |
| `official_logo` (RSK-06) | 30 | Website live and a page image matches an official logo at 85 or more |
| `lookalike_can_send` | 10 | The domain publishes an SPF record |

The total is capped at 100. Levels: 0 to 29 Low, 30 to 59 Medium, 60 to 79 High, 80 to 100 Critical (RSK-09).
All four levels are allowed for domain alerts (D-03). A favicon match earns no points by itself; it counts as
brand evidence and as a Suspected Phishing signal.

### D-29 caps for live websites

The points describe the domain name. D-29 also asks whether the page itself pretends to be the brand.
Only when the website is live:

| Situation | Cap | Highest level |
|---|---|---|
| Page is parked or for sale | 29 | Low |
| Page shows no brand evidence | 29 | Low |
| Page shows no brand evidence but has a login/payment form | 59 | Medium |
| Page shows brand evidence | none | Critical |
| No website (mail only, or nothing answered) | 79 | High |

Since 2026-10-15 (D-45) a look-alike domain is only Critical when its page shows the brand, and an MX record
`0 .` (a "null MX": the domain says it accepts no email) no longer counts as email-enabled (D-44).

**Brand evidence** means at least one of: a brand term in the page text (short abbreviations only with context,
D-25), a reference to an official domain or email domain, a favicon match, or a logo match. The page's own domain
name is removed from the text first, so `examplebank.org` saying "Welcome to examplebank.org" is not evidence.

**Parked** means the final URL is on a domain marketplace or parking service (for example sedo.com, dan.com,
hugedomains.com), the path is `/lander`, or the text says something like "domain is for sale".

A domain with no website is never capped: its name is the only evidence. The uncapped total is kept as
`raw_score`, and the alert shows the reason in **Score Cap**.

### Suspected Phishing (D-04 and D-29)

All of these must be true:

1. The website is live.
2. The page shows brand evidence.
3. The page is not parked.
4. Similarity is 80 or more (`PHISHING_SIMILARITY_THRESHOLD`; note: 80 or more, not strictly more).
5. At least one of: phishing keywords or a password box, a favicon match, or a logo match.

The alert title then becomes "Suspected phishing website: <domain>".

### Email Risk (D-02, MX-04)

A separate field, not part of the score: MX and a live website = High; MX only = Medium; no MX = Low.

### Worked examples

**A. `exampelbank.com`: registered, MX, SPF, no website.**

| Rule | Points |
|---|---|
| Similarity 90.91 > 80 | 25 |
| MX present | 15 |
| SPF published | 10 |
| Total | 50, Medium |

Stage MX. Title "Email-enabled look-alike domain". Email Risk Medium. No cap (no website).

**B. `examplebank.org`: live site of an unrelated bakery, HTTPS, has a "Log in" link.**

| Rule | Points |
|---|---|
| Exact brand in domain | 40 |
| Similarity 100 | 25 |
| HTTPS | 10 |
| Login keyword | 20 |
| Raw total | 95 |
| Cap: no brand evidence (D-45; login form seen) | 59, Medium |

Not Suspected Phishing (no brand evidence). The acceptance test `zentrova.org` checks this same case.

**C. `examplebank-login.com`: live copy of the login page with the logo, MX, SPF, HTTPS.**
40 + 25 + 15 + 10 + 20 + 30 + 10 = 150, capped at 100. Critical, no D-29 cap, Suspected Phishing true,
Email Risk High.

## 8. Output fields shown to analysts

`OUTPUT_FIELDS` in `registry.py` lists these columns for all three stages, in this order. The alert page shows
them first (the Screenshot field is hidden there because the screenshot appears in the evidence gallery). The
CSV and PDF exports use exactly this list.

| Field | Meaning |
|---|---|
| Domain | The look-alike domain |
| Similarity Score | 0 to 100 closeness to the nearest brand term |
| MX Enabled | True if MX records exist |
| Website Live | True if the browser got an HTTP response; "unknown (capture failed)" if a port answered but the page could not be captured |
| SSL Present | True if live and a certificate was read on port 443 |
| Screenshot | True if a screenshot was taken |
| Risk Level | Low, Medium, High or Critical, from the score (added by `record_detection`) |
| Email Risk | MX tier: Low, Medium, High (D-02) |
| Suspected Phishing | The D-04/D-29 flag |
| Fuzzer | Category of trick, for example "Transposition" or "Certificate Transparency" |
| Registered | Always true (unregistered names make no finding) |
| Registrar | From RDAP; "lookup failed" if the RDAP lookup failed |
| Created | Registration date from RDAP; "lookup failed" if the RDAP lookup failed |
| MX Records | For example `10 mail.exampelbank.com` |
| A Records | IPv4 addresses |
| Page Title | Browser tab title |
| HTTP Status | For example 200 |
| Final URL | Where the page ended up after redirects |
| Favicon Match | True if the favicon matches the brand's (mmh3 or perceptual) |
| Keywords Found | Phishing words seen, for example "login", "otp" |
| SSL Issuer | Certificate issuer organisation or name |
| SSL Expires | Certificate end date |
| Logo Match Score | Best page-image match to an official logo, 0 to 100 |
| Brand Evidence On Page | D-29 result; empty when there is no website |
| Brand Terms On Page | Brand words found in the page text |
| Official Site References | Official domains or email domains mentioned or linked |
| Parked Page | True for parked or for-sale pages |
| Score Cap | Reason text if a D-29 cap lowered the score (added by `record_detection`) |
| Discovery Source | "Certificate Transparency" or "Typosquat generation (<category>)" |

The finding also carries fields outside this list. The finding and alert pages show them after the main fields; exports do
not include them: **SPF Record**, **DMARC Record**, **Email-ready** (SPF present or MX present) and
**Closest Brand Term**.

## 9. Evidence stored

Files go to S3-compatible object storage (RustFS, D-22). Identical files or metadata already stored for the
finding are skipped (D-21), so re-scans only add what changed. Each new item is linked to the finding and to the
observation (scan) that captured it.

| Evidence kind | Content | When |
|---|---|---|
| dns | A, MX, NS records (metadata only) | Always |
| whois | RDAP result as a JSON file | Always (may contain an error) |
| screenshot | Full-page PNG, with URL, status, title, password box, form targets | Live site |
| favicon | Icon file, with its URL, mmh3 hash and match score | Live site with a favicon |
| html | Page HTML, first 500,000 characters | Live site |
| image | The page image that best matched the logo, with its score | Live site with a logo score above 0 |
| ssl | Certificate facts as JSON: subject, issuer, SAN names, dates, expired, self-signed, protocol | Live site |

Each scan also writes a `domain_checks` row: records, WHOIS, HTTP status, final URL, title, certificate facts and
favicon hash, with a timestamp (MX-02). The logo module reads these rows.

## 10. Settings and configuration

Environment variables (`backend/app/config.py`):

| Variable | Default | Effect |
|---|---|---|
| `TYPO_TLDS` | com, in, net, org, co, io, uk, us, ae, sg, au | TLDs used for variants (TYP-08) |
| `PHISHING_SIMILARITY_THRESHOLD` | 80 | Minimum similarity for Suspected Phishing |
| `LOGO_MATCH_THRESHOLD` | 85 | Minimum image score for a logo or favicon match |
| `FETCH_TIMEOUT_SECONDS` | 15 | Safe-fetcher and TLS connection timeout |
| `FETCH_MAX_BYTES` | 25 MB | Largest download (crt.sh uses its own 20 MB limit) |
| `FETCH_MAX_REDIRECTS` | 5 | Redirects the safe fetcher follows |
| `FETCH_RATE_PER_HOST_PER_MINUTE` | 30 | Politeness limit per host |
| `FETCH_USER_AGENT` | Chrome-like string ending in `BeyondCloudBrandIntel/1.0` | Browser and fetcher identity |
| `FETCH_ALLOW_PRIVATE_HOSTS` | empty | Test website only; refused in production |

Fixed in code: 12,000 variants (`MAX_VARIANTS`), 70 CT similarity, 7-day WHOIS cache, 16 RDAP threads,
128 DNS threads, resolver list and timeouts, 30-second page load, 40 images of 2 MB each. Official domains,
keywords, logos and favicons are set per brand in the dashboard (see `docs/guides/BRAND-CONFIGURATION.md`).

## 11. How it is tested

Tests carry `@pytest.mark.req(...)` markers with requirement IDs; the UAT report is built from them. Acceptance
tests run the real pipeline against a fictional test brand (Zentrova Bank) with `FixtureInfra` data (injected
by `backend/tests/support/fixture_sources.py`) and a local test website, using a real browser, database and
storage.

| Test | Markers | What it proves |
|---|---|---|
| `test_ac01_typosquat_variants_detected` | AC-01, TYP-01 to TYP-08, TYP-12, OBJ-01 | Every pattern generates variants; more than 1,000 variants; `zentorva.in` alert is "Transposition" |
| `test_newly_registered_domain_from_certificate_transparency` | TYP-09 to TYP-11, TYP-13, D-11 | A CT-only domain is found; WHOIS and A records stored |
| `test_ac02_mx_records_resolved_and_stored` | AC-02, MX-01 to MX-04 | MX stored; Email Risk Medium, High and Low cases |
| `test_ac03_live_phishing_domain_screenshot_and_score` | AC-03, PHI-01 to PHI-09, OBJ-02, FND-11, FND-12 | Screenshot, favicon, SSL, HTML evidence; favicon match; Suspected Phishing; Critical |
| `test_unrelated_live_site_is_not_suspected_phishing` | PHI-08, D-04 | Live page without signals is not flagged |
| `test_unrelated_live_site_capped_at_medium` | D-29, RSK-09 | Raw 65 capped to Medium with a Score Cap reason |
| `test_parked_lookalike_scores_low` | D-29, RSK-09 | Parked page is Low and not phishing |
| `test_branded_phishing_page_reports_brand_evidence` | D-29 | Brand evidence true, no cap |
| `test_rescan_updates_instead_of_duplicating` | D-19, D-21 | Re-scan updates, evidence not duplicated (run on the APK module) |
| `test_scan_runs_recorded` | FND-07, FND-13, RDA-17 | Every run stores its components; the domains run is `completed` with Variant generation, DNS resolution, WHOIS/RDAP and capture components |

Unit tests: `tests/unit/test_pagecheck.py` (D-29, PHI-08), `test_similarity.py` (TYP-13),
`test_scoring.py` (RSK-01 to RSK-10, D-29), `test_lookalike_email.py` (EML-17), `test_fetch.py` (FND-12, FND-13),
`test_domain_reporting.py` (RDA-03, RDA-17, RDA-21: a DNS timeout is unresolved, not unregistered; a capture
failure is "unknown" and leaves an existing finding unchanged; CT and WHOIS failures are reported).
All in `backend/tests/`.

## 12. Known limitations and missing capabilities

| Limitation | Effect |
|---|---|
| Only NS, A and MX are resolved and stored | No AAAA (IPv6), CNAME or TXT history in `domain_checks`. AAAA is only asked when there is no A record, to decide if a website can exist |
| A DNS timeout or server failure leaves the domain unresolved for that scan | It is reported (DNS resolution component) and retried next scan, but a newly registered domain with slow name servers is only found once a lookup succeeds. Fixed in SP1: it is no longer read as "unregistered" (D-31) |
| A failed capture leaves the website state unknown | Shown as "Website Live: unknown (capture failed)"; an existing finding is kept as it is. A new phishing site that blocks our browser stays at Typosquat or MX (or a Candidate) until a capture succeeds. Fixed in SP1: it is no longer read as "not live" (D-31) |
| Only the bare domain is probed | `www.` and other subdomains are not checked separately |
| Redirect chain not kept in the browser path | Only the start URL and final URL are stored, not the hops in between |
| Threat intelligence coverage depends on keys | Without `URLSCAN_API_KEY` and `URLHAUS_AUTH_KEY` only the OpenPhish community feed (a few hundred current URLs) is checked (D-46) |
| WHOIS data is not scored | Domain age is shown but earns no points; `young_domain` exists only for email |
| No cross-domain correlation | Domains sharing an IP, certificate, name server or favicon hash are not grouped |
| crt.sh is a single free service | When it is down, the scan ends `completed_with_errors` (the "Certificate Transparency (crt.sh)" component shows `failed`) and CT discovery waits for the next scan |
| No real-time CT stream | `certstream` is installed but not used, so CT discovery happens only at scan time |
| Variant list capped at 12,000 | Homoglyph and bitsquatting variants may be cut for long brand names |
| Keyword detection is English word matching | Phishing pages in other languages may show no keywords |
| Phishing kits with no brand text, logo or link | Capped at Medium when they ask for a login or payment, Low otherwise, unless two threat-intel sources list them (D-29, D-45, D-46) |
| The 6-hourly re-check runs the full pipeline | It does not focus on known live domains only. Since D-48 captures run three at a time and a scan stops after 45 minutes; the domains it did not reach are listed on the scan ("Domain checks", partially completed) and go first on the next scan |
| Stages never move backwards | A site that goes offline still shows as Phishing (by design, D-19) |

## Key takeaways

- One runner, `domains`, covers Typosquat, MX and Active Phishing. Each domain has one finding whose stage only moves forward (D-19); it alerts only as a Finding at or above the brand's "Alert from" level.
- Candidates come from dnstwist variants across 11 TLDs plus Certificate Transparency hits; DNS decides which are registered.
- Live sites are captured in an isolated headless browser and checked for keywords, password boxes, favicon, logo and brand text.
- The score comes from the shared points table; D-29 caps parked pages at Low and pages without brand evidence at Medium.
- Email Risk (MX tier) is a separate field. SPF on a look-alike adds 10 points and marks it email-ready.
- Every part of the pipeline is a scan component; a DNS timeout is "unresolved" and a failed capture is "unknown", never "no" (D-31).
- Gaps remain: limited DNS record types, no threat intel or correlation for domains.
