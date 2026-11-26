# Chapter 05 - Rogue Mobile App Monitoring

In this chapter:
- What a rogue app is, and why an app inside Google Play can still harm a brand.
- How the module searches Google Play for every brand keyword, ignores the brand's own apps, and flags the rest that use the brand.
- How each listing is tracked over time as new, updated or removed.
- How the risk score is built, what analysts see, and what is still missing (other app stores, D-13).

## 1. What this module detects and why it matters

### Plain words first

**Google Play** is the official Android app store. Apps there are checked by Google, but not for brand
misuse. Anyone with a developer account can publish an app called "Example Bank Loan Helper".

A **rogue app** is an app in an official store that uses a brand's name, product names or logo without the
brand's permission. It may be:

- a scam that collects login details or fees,
- a loan or "helper" app that makes customers think it is endorsed by the bank,
- a harmless fan app that still confuses customers and creates complaints.

The **publisher** (Google calls it the developer) is the account that published the app. Example Bank's real
apps are published by "Example Bank Ltd". Any other publisher using the brand is suspicious.

Chapter 04 deals with APK files on mirror websites. This chapter deals with listings inside Google Play.

### An attack story

1. A company called "QuickLoan Apps" publishes "Example Bank Loan Helper" on Google Play.
2. The description says: "Instant loans for Example Bank customers. Login with your Example Bank netbanking
   ID."
3. It uses an icon very close to the Example Bank logo. It gets 10,000+ installs.
4. Customers enter their netbanking passwords. Some lose money; others call Example Bank to complain about a
   loan they never took from the bank.

The module finds this listing in the daily Google Play search, sees that the publisher is not approved and
that the app uses the brand, and records a finding (and an alert when the rule is met). If the app later
disappears from the store, the finding is marked "Removed" on its timeline.

## 2. Requirements it covers

| ID | Requirement | How the module covers it |
|---|---|---|
| OBJ-03 | Identify fake or unauthorized mobile applications | The whole module |
| ROG-01 | Monitor Google Play search results for brand keywords | Search for each keyword and product term |
| ROG-02 | Monitor other public app stores | **Deferred** (decision D-13, GAP-07) |
| ROG-03 | Compare publisher with approved publisher list | Approved publishers are skipped |
| ROG-04 | Flag apps using brand name, logo or product terminology without authorization | Relevance check and icon comparison |
| ROG-05 | Track app status changes: new, removed, updated | `app_listings` table and `App Status` field |
| ROG-06 | Output: Store, App Name, Publisher, Official Publisher Match, Install Count, Risk Level (M/H) | `OUTPUT_FIELDS[rogue_app]` |
| AC-05 | Detects unauthorized listing by keyword | Acceptance test |

Related decisions: D-03 (Medium/High only), D-13 (Google Play only), D-20 (exact match applies to the app
title), D-25 (short abbreviations need context).

## 3. How it works

### The process, step by step

1. **A scan starts.** Daily at 02:00 UTC for every active brand, or when an analyst starts one.
2. **Build the search list.** The module takes the brand's keywords (or the brand name if there are none)
   plus its product terms, removes duplicates and keeps the first eight. For Example Bank this might be
   "Example Bank", "examplebank", "ExamplePay".
3. **Search Google Play.** For each term, `google_play_scraper.search(term, lang="en", country="in",
   n_hits=30)` returns up to 30 apps. If a search fails, it is retried up to three times, waiting 3 and then
   6 seconds. Results are merged by package name (`appId`), so an app found by two terms is checked once.
4. **Track the listing (every app returned).** `_track` looks up the app in the `app_listings` table:
   - not seen before: stored with state `new`, shown as **New**;
   - seen before, but the version or update date changed, or it was previously removed: state `updated`,
     shown as **Updated**;
   - otherwise: state `unchanged`, shown as **Unchanged**.
5. **Skip approved publishers.** If the publisher name (case-insensitive) is on the brand's approved publisher
   list, the app is the brand's own. No finding (ROG-03).
6. **Check brand use.** The module joins the title, summary and description and asks
   `BrandContext.relevance` whether this text refers to the brand (D-25). It also downloads the icon and
   compares it with the official logo and app icon.
7. **Decide.** If the text is not relevant **and** the icon does not match, the app is ignored (ROG-04).
8. **Build the detection.** Signals, output fields and evidence are prepared, and a `Detection` is returned
   with the state facts `listed = True` and `logo_match`. The publisher mismatch signal is always set, because
   approved publishers were already skipped.
9. **Score and store.** `record_detection` (`backend/app/core/findings.py`) scores it, clamps it to
   Medium/High, creates or updates one finding per package, keyed `play:<package>`, records an observation for
   this scan, and raises an alert only when the alert rule is met (SP2, D-34).
10. **Mark removed apps.** After all apps are checked, every listing in `app_listings` that was not returned
    this time is marked `removed`. If the package is a finding, `mark_state` (`backend/app/core/findings.py`)
    sets its fact `listed = False`, its `App Status` becomes **Removed**, and an `app_status` timeline event
    "App no longer listed on Google Play" is added. The module itself never writes the finding or alert
    tables. This step is skipped if any search failed in this run, because a failed search would make its
    apps look removed.

### Candidate or Finding? (SP2, D-33)

An app that matches the brand only by **name similarity** is stored as a **Candidate** and never alerts. It is a
**Finding** when the exact brand word is in the title or package name, or the icon matches the official logo or
app icon (`analysed = exact or logo_match` in `backend/app/modules/rogue_app/module.py`). Rogue app scores are
clamped to Medium or High, so a Finding reaches the default "Alert from" level (Medium).

On a re-scan, two facts are compared with the previous observation: `logo_match` ("Official logo detected") and
`listed`. An app that was removed and then appears again (`listed` False to True, "App listed again") is a
**meaningful change**: it is written to the timeline and raises a new alert, even if the analyst had closed the
finding (it is re-opened, D-36). Removal itself (`listed` True to False) is only recorded, never alerted.

### Flow diagram

```
 Daily schedule / manual scan
            |
            v
 Terms = keywords + product terms (first 8, no duplicates)
            |
            v
 google-play-scraper search(term, lang=en, country=in, 30 hits)   x3 retries
            |
            v
 Merge results by package (appId)
            |
            v
 For each app:
   _track -> app_listings: New / Updated / Unchanged
            |
   Publisher approved? --yes--> ignored
            | no
            v
   relevance(title + summary + description)    icon vs official logo
            |                                          |
            +------------- either one? ----------------+
                         | no  -> ignored
                         | yes
                         v
   Signals (exact title, similarity, logo, publisher mismatch) -> Detection
            |
            v
 record_detection: score, clamp to Medium/High, finding "play:<package>"
   (Candidate or Finding), observation, evidence; alert if Finding and risk >= "Alert from"
            |
            v
 After the loop (only if every search worked):
   listings not seen this run -> state "removed"; mark_state: listed = False,
   App Status = Removed, app_status timeline event
```

## 4. Tools and libraries used

| Tool | What it is | What we use it for | Why this tool (and alternatives rejected) | Where in the code |
|---|---|---|---|---|
| google-play-scraper | Open-source Python library that reads Google Play's public web pages | Searching Google Play by keyword | Google Play has no public search API. The library talks only to `play.google.com`, a fixed trusted endpoint, so it is the one documented exception to the safe fetcher. Other stores were deferred (D-13). | `backend/app/modules/rogue_app/module.py` (`LivePlaySource`) |
| Safe fetcher | The platform's only general way to reach the internet | Downloading app icons | Required for untrusted URLs (D-18) | `backend/app/core/fetch.py`, `backend/app/modules/common.py` |
| Pillow + ImageHash | Image loading and perceptual hashing | Comparing the icon with the official logo and app icon | No alternative recorded in the decision log | `backend/app/core/imaging.py` |
| RapidFuzz (through `similarity.py`) | String-similarity library | Similarity of the app title to brand terms | No alternative recorded in the decision log | `backend/app/core/similarity.py`, `backend/app/modules/base.py` |
| PostgreSQL + SQLAlchemy | Database and Python database layer | The `app_listings` table that remembers every app seen | Platform database (FND-09) | `backend/app/db/models.py` (`AppListing`) |
| boto3 + S3-compatible storage | Object storage client | Storing the icon and metadata as evidence | RustFS by default; any S3 store works (D-22) | `backend/app/core/evidence.py` |

## 5. How each tool works internally, explained simply

### google-play-scraper

When you search on the Google Play website, the page you get back contains the results as data embedded in
script blocks. The library requests that same search page, finds those script blocks, decodes the data and
picks out each app's fields. In the installed version (1.2.7) a search result contains: `appId`, `title`,
`developer`, `icon`, `installs`, `score` (star rating), `genre`, `price`, `free`, `description`,
`screenshots` and a few others. The module adds the store URL
`https://play.google.com/store/apps/details?id=<appId>` when it is missing.

Two parameters matter. `lang="en"` asks for English text. `country="in"` asks for the India store, so
results reflect what users in India see.

Because Google can change its page layout at any time, a library like this can break without warning. The
module retries transient errors (3 attempts per term) and reports every search on the "Google Play search"
scan component: a failed term marks it `failed` (the scan ends `completed_with_errors`); if **every** term
failed, nothing was checked and the scan ends `failed` (D-31). The "Removal check" component is `ok` when the
removal check ran and `skipped` when a search failed (see below).

### The listing tracker

The `app_listings` table has one row per brand, store and package (a unique constraint). It stores the title,
publisher, installs, version, update date, state, first seen and last seen. Comparing this run with the last
one is what makes "new", "updated" and "removed" possible (ROG-05).

### Brand relevance (D-25)

`BrandContext.relevance` in `backend/app/modules/base.py` decides whether text refers to the brand:

| Term type | Example for Example Bank | Rule |
|---|---|---|
| Strong term (6+ letters) | "Example Bank", "ExamplePay" | Counts on its own when found in the text |
| Close misspelling of an 8+ letter term | "Examp1e Bank" in the app name | Counts on its own when similarity is at least 85 |
| Close misspelling of a 6-7 letter term | - | Needs a context word or abbreviation too |
| Weak term (short abbreviation) | "EXB" | Counts only as an exact word **and** with a context word such as "example" |

So "EXB Example Loans" is relevant, but an unrelated "EXB Fitness Tracker" is not. Words such as "bank",
"limited" and "services" never count as context, because many companies use them.

### Image hashing

The icon is downloaded through the safe fetcher (maximum 2 MB) and turned into perceptual hashes. The match
score is 0-100. At or above `LOGO_MATCH_THRESHOLD` (default 85) the icon counts as the brand's logo.

## 6. Code map

| File | Responsibility |
|---|---|
| `backend/app/modules/rogue_app/module.py` | `LivePlaySource`, tracking, analysis, scan components |
| `backend/tests/support/fixture_sources.py` | `FixturePlaySource`: simulated Google Play results for the automated tests only (D-32) |
| `backend/app/modules/base.py` | `BrandContext`, `relevance`, `Detection` |
| `backend/app/modules/common.py` | `image_match`, `literal_brand_in` |
| `backend/app/core/imaging.py` | Image fingerprints |
| `backend/app/core/similarity.py` | Name similarity, `brand_terms_in_text` |
| `backend/app/db/models.py` | `AppListing`, `Finding`, `Observation`, `FindingEvent`, `Alert` |
| `backend/app/core/scoring.py` | Points, levels, clamp |
| `backend/app/core/findings.py` | `record_detection` (findings, observations, alerts, evidence) and `mark_state` (removed apps) |
| `backend/app/modules/registry.py` | Output fields |

Key functions in call order:

1. `execute_scan` -> `get_runner("rogue_app")` -> `RogueAppModule()`.
2. `RogueAppModule.run` -> `LivePlaySource.search(ctx, self.report)` (the tests inject `FixturePlaySource`).
3. For each app: `RogueAppModule.analyse` -> `_track` -> publisher check -> `ctx.relevance` ->
   `image_match` -> `literal_brand_in` -> `Signals` -> `Detection`.
4. Each detection -> `record_detection` -> `score(signals, ModuleName.rogue_app)`.
5. After the loop -> `_mark_removed` -> `mark_state`.

## 7. Signals collected and how they become the risk score

| Signal | When this module sets it | Points |
|---|---|---|
| `brand_exact_in_domain` | A strong brand term is literally in the app title, or a weak term with context (D-20, D-25) | +40 |
| `typo_similarity` > 80 | 100 when a strong brand term is in the title; otherwise the name similarity from `relevance` | +25 |
| `official_logo` | Icon match at or above the threshold | +30 |
| `publisher_mismatch` | Always, because approved publishers were already skipped (RSK-08) | +25 |

Then the points are summed and capped at 100. The module clamp (D-03) keeps rogue app alerts at Medium or
High: the score is raised to at least 30 and lowered to at most 79. The level follows from the score.

### Worked example

"Example Bank Loan Helper" by "QuickLoan Apps":

| Check | Result | Points |
|---|---|---|
| "Example Bank" literally in the title | yes | +40 |
| Similarity (strong term in title gives 100) | 100 > 80 | +25 |
| Icon match | 92 >= 85 | +30 |
| Publisher not approved | always | +25 |
| Total | 120, capped to 100 | raw 100 |
| Clamp to Medium/High | lowered to 79 | **79, High** |

Compare "Easy Instant Loans" by "Payfast Dev", whose description says "works with Example Bank accounts" but
whose title and icon are its own:

| Check | Result | Points |
|---|---|---|
| Brand in title | no | 0 |
| Title similarity | low | 0 |
| Icon match | no | 0 |
| Publisher not approved | yes | +25 |
| Total | 25 | raw 25 |
| Clamp | raised to 30 | **30, Medium** |

The app is still reported, because it uses the brand in its description (ROG-04), but at the lowest allowed
level.

## 8. Output fields shown to analysts

From `OUTPUT_FIELDS[ModuleName.rogue_app]` in `backend/app/modules/registry.py`:

| Field | Meaning |
|---|---|
| Store | Always "Google Play" in Phase 1 |
| App Name | The app's title |
| Publisher | The developer account name |
| Official Publisher Match | Always False on a finding (approved publishers never get one) |
| Install Count | Installs as Google shows them, such as "10,000+" |
| Risk Level | Medium or High |
| Package Name | The app's unique ID, such as `com.quickloan.examplebankhelper` |
| App Status | New, Updated, Unchanged, or Removed |
| Similarity Score | Title similarity to the brand (100 when the brand name is in the title) |
| Logo Match | True when the icon matches an official image |
| Brand Terms Used | Which brand terms were found in the title, summary or description |
| Store URL | Link to the listing on Google Play |
| Last Updated | The store's update date as a calendar date, when Google provides it |

Extra detail fields also stored: `Version` and `Rating` (the star score).

## 9. Evidence stored

| Evidence | Kind | When |
|---|---|---|
| All simple (text and number) fields returned by Google Play for the app | `metadata` | Always |
| The app icon, with its URL and logo match score | `image` | When the icon could be downloaded |

No screenshot of the store page is taken, and the app itself is never downloaded or installed. Identical
evidence is not stored again on later scans (D-21). Each new item is linked to the finding and to the observation (scan) that captured it. Listing changes
(removed, listed again) and analyst decisions are recorded on the finding timeline.

## 10. Settings and configuration

This module needs no API key. Relevant settings:

| Setting | Where | Effect |
|---|---|---|
| `LOGO_MATCH_THRESHOLD` (default 85) | environment, `backend/app/config.py` | Icon match score that counts as a logo match |
| `FETCH_TIMEOUT_SECONDS`, `FETCH_RATE_PER_HOST_PER_MINUTE` | environment | Apply to icon downloads (not to Google Play searches) |
| Keywords and product terms | brand configuration | What is searched |
| Approved publishers (`publisher` allowlist) | brand configuration | Apps from these publishers are skipped. The name must match the store's publisher name (case is ignored). |
| Official logo and app icon | brand assets | Icon comparison |

Language (`en`), country (`in`) and the number of hits (30) are fixed in the code.

## 11. How it is tested

| Test | File | What it proves | Markers |
|---|---|---|---|
| `test_ac05_unauthorized_play_listing_by_keyword` | `backend/tests/modules/test_acceptance.py` | An unauthorized listing found by keyword raises an alert with Store, Publisher, Official Publisher Match False, Install Count and App Status "New". The brand's own app raises no alert. The listing is stored with state `new`. | AC-05, ROG-01, ROG-03, ROG-04, ROG-05, ROG-06 |
| `test_rogue_app_removed_is_tracked` | same | When the app is missing from the next search, the module counts one removal and the finding shows "Removed" | ROG-05 |
| Relevance tests | `backend/tests/unit/test_relevance.py` | Unrelated apps whose names share an abbreviation are not relevant; real brand uses are | ROG-04, D-25 |
| Module clamp | `backend/tests/unit/test_scoring.py` | Rogue app alerts are always Medium or High | - |
| `test_rogue_app_fails_when_every_store_search_fails` | `backend/tests/unit/test_runner_reporting.py` | When every Google Play search fails, the run is `failed`, not a clean result | RDA-03, RDA-17, RDA-21 |

The acceptance tests use simulated Google Play results in `backend/tests/fixtures/sources/play_search.json`
for a fictional test brand (D-27, D-30).

## 12. Known limitations and missing capabilities

| Limitation | Effect |
|---|---|
| Google Play only | Other stores (Samsung Galaxy Store, Huawei AppGallery, Apple App Store and others) are not monitored. ROG-02 is deferred by decision D-13; the source is pluggable so others can be added. |
| "Updated" is weak on live data | Google Play search results do not include the version or update date. So on live scans an app is marked Updated mainly when it reappears after being removed, and Version and Last Updated are usually empty. The simulated test data does include them. |
| One country and language | Searches use the India store in English. Apps visible only in other countries may be missed. |
| 30 results per term, 8 terms | A popular keyword may have more than 30 apps; later ones are not seen. |
| Removal check needs every search to succeed | If one search fails, no app is marked removed in that run; the scan shows "Removal check: Skipped" with the reason. |
| Removal does not lower the risk | A removed app keeps its score; the analyst sets the decision (for example Resolved). |
| Library depends on Google's page layout | A Google change can break searches until the library is updated. |
| Publisher match is by name | A rogue publisher with exactly the approved name would be skipped. Google Play developer names are not guaranteed unique. |
| No deep app details | The module does not open the full app page, so it does not read permissions, the privacy policy or reviews. |

## Key takeaways

- A rogue app is an app inside an official store that uses the brand without permission.
- The module searches Google Play for up to eight brand terms, skips approved publishers, and flags apps whose
  text or icon uses the brand (D-25 rules apply to short abbreviations).
- Every app seen is tracked in `app_listings`, which gives New, Updated, Unchanged and Removed states.
- Publisher mismatch always fires; scores are clamped to Medium or High.
- Only Google Play is covered in Phase 1 (D-13).
