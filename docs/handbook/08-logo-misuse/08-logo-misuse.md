# Chapter 08: Logo Misuse on Websites

## In this chapter

- How the platform finds the brand's official logo on websites that do not belong to the brand.
- Which websites it visits, how it pulls every image off a page, and how it compares images with perceptual hashes.
- How a match becomes an alert, how it is scored, and what evidence is kept.
- What the module cannot do yet.

## 1. What this module detects and why it matters

### Plain words

A **logo** is the picture that identifies a brand. Customers trust a page that shows it. Attackers know this.
They copy the official logo onto fake login pages, fake "customer care" sites and fake offer pages.

This module visits suspicious websites, collects every image on the page and checks whether any of them is
Example Bank's official logo. If one is, it raises an alert with a screenshot of the page and the matching image.

It compares pictures by their visual content, not by file name or exact bytes. A logo that was resized,
re-saved as JPEG or given a white border still matches.

### Why it matters: an attack story

An attacker registers `examplebnk-rewards.in` and builds a page saying "Example Bank Rewards: claim your
cashback". The page shows the Example Bank logo, saved from the real website and shrunk slightly. There is no
login form yet. The attacker plans to add one after the campaign starts.

The domain pipeline (Chapter 03) finds the domain and captures the page. The logo module then crawls that page,
extracts the images, and finds one that matches the official logo with a score of 93 out of 100. It raises a
**Brand Logo on Websites** alert, "Official logo used on examplebnk-rewards.in", with the screenshot. An analyst
can start a takedown before the login form is added.

## 2. Requirements it covers

| ID | Requirement |
|---|---|
| LOGO-01 | Crawl discovered suspicious domains and websites |
| LOGO-02 | Extract images from pages |
| LOGO-03 | Compute perceptual hash (pHash) |
| LOGO-04 | Match against stored official brand logos |
| LOGO-05 | Capture screenshot evidence when matched |
| LOGO-06 | Output: Website, Page URL, Logo Match Score 0 to 100, Screenshot, Risk Level (Medium/High) |
| FND-05 | Official logo upload (the reference images) |
| FND-11 | Headless browser for screenshots |
| RSK-04, RSK-05, RSK-06 | HTTPS, login/payment keywords, official logo points |
| AC-08, OBJ-06 | Acceptance: official logo detected on a test website |

IDs come from `docs/requirements/01-requirements-register.md`.

## 3. How it works

### Before any scan: storing the official logo

An administrator uploads the official logo (and optionally app icons and favicons) on the brand page. `add_asset`
in `backend/app/core/assets.py` checks that the file is a readable image, stores it in object storage and saves
its pHash and dHash fingerprints in the `brand_assets` table. When a scan starts, `BrandContext.from_brand`
(`backend/app/modules/base.py`) loads the fingerprints of all **logo** and **app icon** assets into
`logo_hashes`. Favicons are kept separately and are not used by this module.

### Step by step

1. **Queueing.** The logo runner goes to the `browser` queue (D-18). When the logo and domain scans are queued
   together, the logo scan waits and starts only after the domain scan has finished (`enqueue_runs` in
   `backend/app/workers/tasks.py`). That way it sees the live sites the domain scan just found.
2. **Check the reference.** If the brand has no logo or app icon uploaded, there is nothing to compare against.
   The module stops, reports **"Official logo assets: Not configured"** ("No official logo uploaded for this
   brand - upload one under Brands > Assets") and the scan ends `failed`, because it cannot claim "no logo
   misuse" (D-31). Otherwise "Official logo assets" and "Target websites" are reported as Completed with their
   counts.
3. **Pick targets (`targets`).** It reads the `final_url` of every `domain_checks` row for the brand from the last
   7 days. A row has a final URL only when the domain pipeline reached a live website. Duplicate URLs are removed.
   URLs on the brand's own official domains (and their subdomains) are removed. At most 200 targets. In automated
   tests, extra test-website URLs are injected through the `extra_targets` constructor parameter
   (`backend/tests/support/fixture_sources.py`); the product has no other target source.
4. **Capture each page.** `capture(url, collect_images=True)` opens the page in the headless browser and collects
   the screenshot, title, text, HTML, image URLs, CSS background images and inline SVG drawings. Up to 40 images
   (2 MB each) are downloaded through the safe fetcher; up to 10 visible SVGs are rendered to PNG.
5. **Report failed captures.** If the browser crashed or got no HTTP response, the page is skipped and counted
   as failed on the "Browser capture" component with the URL and reason, so the scan ends
   `completed_with_errors` instead of looking clean (D-31).
6. **Compare images (`pagecheck.analyse`).** For each image: compute pHash and dHash, compare with every official
   logo fingerprint, keep the best score and remember which image gave it.
7. **Decide.** If the best score is below `LOGO_MATCH_THRESHOLD` (85), nothing happens. Otherwise a `Detection`
   is built with a screenshot, the matched image and the output fields.
8. **Score and store.** `record_detection` (`backend/app/core/findings.py`) scores it, keeps the level within
   Medium to High (D-03), creates or updates the finding keyed by the page's final URL, records an observation
   for this scan, stores new evidence, and raises an alert when the alert rule is met.

### Candidate or Finding? (SP2, D-33)

The logo module only reports pages it has actually rendered and compared, so every result is a **Finding**,
never a Candidate. Logo scores are clamped to Medium or High, so with the default "Alert from" level (Medium)
every new logo finding raises an alert; a brand set to "High" only gets alerts for High ones (D-34).

Each observation records the facts `live` (always true for a rendered page), `login_form` and `logo_match`. If a
later scan finds a login or payment form on the page ("Login/payment form detected"), or the risk level rises,
that is a **meaningful change**: it goes on the timeline and can raise a new alert, even after an analyst
decision (D-36).

### Flow diagram

```
 Admin uploads official logo --> add_asset --> pHash + dHash in brand_assets
                                                        |
 Domain scan finishes                                   v
        |                                    BrandContext.logo_hashes
        v                                               |
 +-----------------------------+                        |
 | LogoModule.targets          |                        |
 | final_url from domain_checks|                        |
 | (last 7 days), drop official|                        |
 | domains, max 200            |                        |
 +--------------+--------------+                        |
                v                                       |
 +-----------------------------+                        |
 | capture (Playwright)        |                        |
 | screenshot, <img>, CSS      |                        |
 | backgrounds, SVG -> PNG     |                        |
 | up to 40 images, 2 MB each  |                        |
 +--------------+--------------+                        |
                v                                       |
 +-----------------------------+                        |
 | pagecheck.analyse           |<-----------------------+
 | hashes_for(each image)      |
 | best_match vs official logos|
 +--------------+--------------+
                v
        best score >= 85 ?
          no  -> nothing recorded
          yes -> Detection (screenshot + matched image)
                v
 +-----------------------------+
 | record_detection            |
 | score, clamp Medium..High   |
 | one finding per page URL    |
 | observation + timeline      |
 | alert if risk >= "Alert     |
 | from" level                 |
 +-----------------------------+
```

## 4. Tools and libraries used

| Tool | What it is | What we use it for | Why this tool (alternatives) | Where in the code |
|---|---|---|---|---|
| Playwright + Chromium | Browser automation; headless Chrome | Rendering the page, screenshot, listing images, rendering SVGs | Named in the source requirements; FND-11. Isolated worker (D-18). No alternative recorded | `backend/app/core/browser.py` |
| httpx (safe fetcher) | HTTP client inside our safety layer | Downloading each image | All outbound requests must pass destination checks, size caps and rate limits (D-18) | `backend/app/core/fetch.py` (`try_fetch`) |
| Pillow | Python image library | Opening PNG, JPG, GIF, WEBP, ICO, BMP; flattening transparency; cropping borders | Standard library for images in Python | `backend/app/core/imaging.py` |
| ImageHash | Perceptual hashing library | pHash and dHash fingerprints and their bit distance | Required by LOGO-03 (pHash); design spec section 4. No alternative recorded. OpenCV is installed but not used for logo matching | `imaging.py` (`hashes_for`, `match_score`, `best_match`) |
| SQLAlchemy / PostgreSQL | Database layer | Reading `domain_checks` targets; storing findings | Platform standard | `backend/app/modules/logo/module.py` |
| S3-compatible storage (RustFS) | Object storage | Screenshot and matched-image files | D-22 | `backend/app/core/evidence.py` |

## 5. How each tool works internally, explained simply

### How the browser finds images

Playwright opens the page like a normal visitor. A small script then runs inside the page and collects:

- every `<img>` element's address (the version actually shown on screen),
- every element whose style has a **background image** (logos are often drawn this way),
- up to 10 **SVG** drawings (vector logos written as code, not as image files).

Visible SVGs are screenshotted one by one into small PNG images, because hashing needs pixels. Image files are
then downloaded outside the browser through the safe fetcher. Images embedded in the page as `data:` text are
decoded directly.

### How perceptual hashing works

A normal file hash (such as SHA-256) changes completely if a single pixel changes. A **perceptual hash** is
designed to stay almost the same when a picture looks the same. Before hashing, `hashes_for` prepares the image:

1. Opens it, takes the first frame (for GIF and ICO files).
2. Puts transparent parts on a white background.
3. Crops away any plain border (`_trim`), so a padded logo matches the bare logo.
4. Rejects images smaller than 8 pixels on a side.

Then two fingerprints are made, each 64 bits long:

| Hash | How it is made, simply |
|---|---|
| pHash (perceptual) | Shrink to a small grey square, split into patterns of light and dark (a frequency transform, like JPEG uses), and record for 64 patterns whether each is above or below the middle value |
| dHash (difference) | Shrink to 9 x 8 grey pixels and record, for each pair of neighbours, whether the left pixel is brighter than the right |

### How two images are compared

The **Hamming distance** is the number of bits that differ between two hashes, from 0 (identical) to 64.
`match_score` turns it into a 0 to 100 score:

```
pHash agreement = 1 - (pHash distance / 64)
dHash agreement = 1 - (dHash distance / 64)
score           = average of the two x 100
```

Example: pHash differs in 4 bits, dHash in 5 bits. Agreement is 0.9375 and 0.921875. The score is 92.97, which
is above 85, so it is a match. `best_match` compares each page image with every official logo and app icon and
keeps the highest score.

## 6. Code map

| File | Responsibility |
|---|---|
| `backend/app/modules/logo/module.py` | `LogoModule`: target list, run loop, finding, details, evidence |
| `backend/app/modules/pagecheck.py` | `analyse`: logo score, matched image (also keywords, favicon, brand terms) |
| `backend/app/core/browser.py` | `capture`: page render, screenshot, image and SVG collection |
| `backend/app/core/imaging.py` | `hashes_for`, `match_score`, `best_match` |
| `backend/app/core/assets.py` | `add_asset`: fingerprints of uploaded official logos |
| `backend/app/modules/base.py` | `BrandContext.logo_hashes`, `Detection` |
| `backend/app/core/scoring.py` | Points and the Medium to High range for logo alerts |
| `backend/app/core/findings.py` | `record_detection`: findings, observations, alert rule and evidence de-duplication |
| `backend/app/workers/tasks.py`, `scan.py` | Queueing after the domain scan; running the scan |
| `backend/app/modules/registry.py` | Output fields and the `logo` runner |

Key functions in call order:

1. `tasks.enqueue_runs` (logo follows domains) then `tasks.run_scan` and `scan.execute_scan`
2. `LogoModule.run`
3. `LogoModule.targets`
4. `browser.capture` for each target
5. `pagecheck.analyse` (calls `imaging.hashes_for` and `imaging.best_match` per image)
6. Build `EvidenceItem` list, `Signals` and `details`, yield `Detection`
7. `findings.record_detection` (calls `scoring.score`, `_store_evidence` and `meets_rule`)

## 7. Signals and the risk score

The module sets three signals:

| Signal | Points | When |
|---|---|---|
| `official_logo` (RSK-06) | 30 | Always true for a logo alert |
| `https` (RSK-04) | 10 | The final page URL starts with `https://` |
| `login_payment_keywords` (RSK-05) | 20 | The page has a phishing keyword (login, verify, OTP and so on) or a password box |

Logo alerts may only be Medium or High (D-03). The score is pulled into the range 30 to 79. The D-29 brand-evidence
caps do not apply to this module: a matching logo is itself brand evidence.

### Worked examples

| Page | Points | Score | Level |
|---|---|---|---|
| `http://examplebnk-rewards.in/` with the logo, no keywords | 30 | 30 | Medium |
| Same page over HTTPS | 30 + 10 | 40 | Medium |
| HTTPS page with the logo and a "Verify your account" form | 30 + 10 + 20 | 60 | High |

The highest possible total is 60, so a logo alert is never Critical. The same website usually also has a domain
alert (Chapter 03), which can reach Critical. The two alerts are separate.

## 8. Output fields shown to analysts

`OUTPUT_FIELDS[ModuleName.logo]` in `backend/app/modules/registry.py`:

| Field | Meaning |
|---|---|
| Website | Host name of the final page, for example `examplebnk-rewards.in` |
| Page URL | Full final URL after redirects; also the finding's identity |
| Logo Match Score | Best image match, rounded, 85 to 100 |
| Screenshot | True if a screenshot was taken (the image itself is in the evidence gallery) |
| Risk Level | Medium or High, added by `record_detection` |
| Matched Image URL | Address of the page image that matched (`data-uri` or `...#svgN` for inline images) |
| Official Asset | Listed in the output columns but not filled by the code today; it stays empty |

Two more fields are stored and shown after these on the finding and alert pages, but are not exported: **Page Title** and
**Keywords Found**.

## 9. Evidence stored

| Evidence kind | Content |
|---|---|
| screenshot | Full-page PNG of the page, with its URL and title |
| image | The matched image file, with its URL and logo match score |

Evidence goes to object storage. On a re-scan, a file with the same SHA-256 is not stored again (D-21). A changed
page adds a new screenshot, linked to the finding and to the observation (scan) that captured it.

## 10. Settings and configuration

| Variable | Default | Effect |
|---|---|---|
| `LOGO_MATCH_THRESHOLD` | 85 | Minimum score for a match; also used by the domain pipeline for logo and favicon matches |
| `FETCH_TIMEOUT_SECONDS`, `FETCH_MAX_BYTES`, `FETCH_RATE_PER_HOST_PER_MINUTE`, `FETCH_USER_AGENT` | 15 s, 25 MB, 30, Chrome-like | Safe-fetcher behaviour for image downloads |

Fixed in code: 7-day look-back (`LOOKBACK_DAYS`), 200 targets (`MAX_TARGETS`), 40 images, 2 MB per image,
10 SVGs, 30-second page load. The reference logos are uploaded per brand under Brands, Assets.

## 11. How it is tested

| Test | Markers | What it proves |
|---|---|---|
| `test_ac08_official_logo_on_test_website` (`backend/tests/modules/test_acceptance.py`) | AC-08, LOGO-01 to LOGO-06, OBJ-06 | The test page `/partner/` gets an alert with score 85 or more, a screenshot and a Medium or High level; the page `/innocent/` gets no alert |
| `test_logo_follows_domain_scan`, `test_logo_alone_runs_immediately`, `test_follow_up_queued_after_scan` (`backend/tests/unit/test_tasks.py`) | FND-07, LOGO-01 | The logo scan is chained after the domain scan, or runs at once when queued alone |
| `test_module_level_clamp` (`backend/tests/unit/test_scoring.py`) | RSK-01 to RSK-10 (file-level marker) | Logo alerts stay within Medium and High |
| `test_logo_without_official_logo_is_not_configured_and_fails` (`backend/tests/unit/test_runner_reporting.py`) | RDA-03, RDA-17, RDA-21 | Without an official logo the run reports "Official logo assets: Not configured" and ends `failed` |

The acceptance test runs the real browser, database and storage against a local test website.

## 12. Known limitations and missing capabilities

| Limitation | Effect |
|---|---|
| In the product, targets come only from the domain pipeline | Only live look-alike domains from the last 7 days are crawled. Pages on unrelated domains (for example a hacked blog or a free website builder) are never visited |
| Only the landing page is checked | Links are not followed, so a logo on `/login` or a second page is missed |
| Whole-image comparison | A logo inside a larger banner or screenshot does not match. There is no feature matching (OpenCV is installed but unused) |
| Logos drawn as text, CSS or canvas | Not found; only image files, background images and SVGs are compared |
| Recoloured, inverted, rotated or heavily cropped logos | Hash distance grows and the score may fall below 85 |
| Image limits | Only the first 40 images (2 MB each) and 10 visible SVGs per page |
| Favicons are not checked here | Favicon matching happens only in the domain pipeline |
| A failed capture skips the page for that scan | It is reported on the "Browser capture" component (fixed in SP1: no longer silent, D-31), but the page is only checked again on the next scan |
| The page is captured twice | Once by the domain scan and once by the logo scan, which costs browser time |
| Logo finding and domain finding are not linked | Two separate findings for one site; no correlation by shared logo, IP or certificate |
| "Official Asset" output field is empty | Analysts cannot see which uploaded logo matched |
| Parked pages are still crawled | They rarely contain the logo, but they use browser time |
| Highest level is High | A logo alert alone never reaches Critical |

## Key takeaways

- The module crawls the live look-alike sites found by the domain pipeline in the last 7 days, skipping official domains.
- Every image, CSS background and visible SVG on the page is fingerprinted with pHash and dHash.
- The match score is the average bit agreement of both hashes; 85 or more is a match.
- A match creates a Medium or High alert (30 points, plus HTTPS and keyword points) with a screenshot and the matched image.
- Main gaps: only one page per site, only domain-pipeline targets, whole-image matching, and no link to the domain alert.
