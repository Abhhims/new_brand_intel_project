# Chapter 04 - Fake APK Monitoring

In this chapter:
- What a fake APK is, and why a bank should care when one appears on a download site.
- How the module finds APK listings on public mirror sites, reads them, and decides which ones are fake.
- How the signing certificate check (decision D-26) tells the real app apart from a copy, without ever running the file.
- Which signals become the risk score, which fields an analyst sees, and what the module cannot do yet.

## 1. What this module detects and why it matters

### Plain words first

An **APK** (Android Package) is the file that installs an app on an Android phone. Most people install apps
from Google Play, but anyone can also download an APK file from a website and install it by hand. This is
called **sideloading**.

Many websites copy APK files and offer them for download. They are called **APK mirrors** or **APK
repositories**. Examples are APKPure, APKMirror, APKCombo and Uptodown. Some mirrors host genuine copies of
real apps. Others host fake or modified copies.

A **fake APK** is an app file that pretends to be the brand's app but was not made by the brand. A
**repackaged** (or "modded") APK is the brand's real app, taken apart, changed (for example with spyware
added), and put back together. Because the attacker does not have the brand's private signing key, the
attacker must sign the changed file with a different key.

### An attack story

Example Bank has an official Android app, package name `com.examplebank.mobile`, published on Google Play by
"Example Bank Ltd".

1. A criminal builds an app called "Example Bank Mobile Banking" with the package name
   `com.examplebank.mobilebanking.secure`. It copies the Example Bank logo as its icon.
2. The criminal uploads it to an APK mirror under the developer name "EB Apps Studio".
3. Victims receive an SMS: "Your Example Bank KYC has expired. Install the new secure app from this link."
4. The app shows a login screen that looks exactly like Example Bank. It sends the username, password and the
   one-time passwords it reads from SMS to the criminal.

The brand's security team cannot remove the listing if it does not know it exists. This module finds such
listings, stores the evidence (including the APK file itself when the mirror offers a direct download), and
raises an alert with a risk score.

## 2. Requirements it covers

Requirement IDs come from `docs/requirements/01-requirements-register.md`.

| ID | Requirement | How the module covers it |
|---|---|---|
| OBJ-03 | Identify fake or unauthorized mobile applications | The whole module |
| APK-01 | Search public APK repositories and indexed APK sources | Web search restricted to 8 mirror sites |
| APK-02 | Match package names against official package list | `Official Package` field, allowlist check |
| APK-03 | Detect similar app names | `Name Similarity` via `BrandContext.relevance` |
| APK-04 | Detect similar package identifiers | `Package Similarity` (RapidFuzz ratio) and brand word in package |
| APK-05 | Detect reused icons/logos | Icon compared with official logo and app icon (`Logo Match`) |
| APK-06 | Detect suspicious developer names | Developer not on the approved publisher list; signer differs (D-26) |
| APK-07 | Extract app name, package, version, developer, download source, SHA256 | Listing page, manifest, file hash |
| APK-08 | Output: App Name, Package, Similarity, Source URL, Logo Match, Risk Level (M/H) | `OUTPUT_FIELDS[apk]` |
| APK-09 | Fake APK inventory with evidence | One finding per listing, with evidence files |
| AC-04 | Detects at least one simulated fake APK entry | Acceptance test |
| OOS-03 | Reverse engineering is out of scope | APKs are never executed or decompiled |

Related decisions: D-12 (APK sources), D-18 (safety rules), D-20 (exact match applies to the package),
D-25 (short abbreviations need context), D-26 (signing certificate verification).

## 3. How it works

### The process, step by step

1. **A scan starts.** The Celery scheduler runs a full scan for every active brand every day at 02:00 UTC
   (`backend/app/workers/celery_app.py`). An analyst can also start one by hand. The `apk` runner runs on
   the normal (non-browser) worker queue.
2. **The brand snapshot is built.** `BrandContext.from_brand` (`backend/app/modules/base.py`) collects the
   brand's keywords, official package names, approved publishers, official signing certificate fingerprints
   and the image fingerprints of the official logo and app icon.
3. **Search.** `LiveApkSource.listings` takes the first three brand terms. For each term it runs one web
   search like this:

   ```
   "Example Bank" apk (site:apkpure.com OR site:apkmirror.com OR site:apkcombo.com OR
   site:uptodown.com OR site:apk.support OR site:apkmonk.com OR site:aptoide.com OR site:malavida.com)
   ```

   It asks for up to 20 results per search.
4. **Filter results.** Duplicate URLs are dropped. Results whose host name is not one of the 8 mirror sites
   are dropped.
5. **Read each listing page.** `_read_listing` downloads the public listing page through the safe fetcher
   and pulls out, with regular expressions: the package name (from the URL path, or from text such as
   "Package name: ..." in the page), the developer, the version, the page title, the icon (the page's
   `og:image` tag) and a direct download link (only an absolute link ending in `.apk`).
6. **Skip the genuine app (first check).** If the package is on the official list, the developer is an
   approved publisher, and there is no way to check the signature, the listing is treated as the real app
   re-hosted by a mirror. No alert.
7. **Check brand relevance.** The module computes name similarity, package similarity, and whether a brand
   word is literally inside the package name. If none of these point to the brand, the listing is dropped.
8. **Compare the icon.** The icon is downloaded and its fingerprint compared with the official logo and app
   icon.
9. **Download the APK (if a direct link exists).** Up to 150 MB. The module computes the SHA-256 hash, reads
   the manifest, and reads the signing certificates. The file is kept as evidence, marked "Untrusted file.
   Do not install or open."
10. **Signature verdict (D-26).** If the APK is signed with one of the brand's official certificates, it is
    the genuine app, whatever the mirror calls it. No alert. If it is signed with a different key, that
    counts as a publisher mismatch.
11. **Build the detection.** The module turns what it saw into `Signals`, fills the output fields and returns
    a `Detection` (with the state facts and the `analysed` flag, see below).
12. **Score and store.** The scan engine (`backend/app/workers/scan.py`) passes the detection to
    `record_detection` (`backend/app/core/findings.py`). This scores it, creates or updates one finding per
    listing, records an observation for this scan, stores new evidence in the S3-compatible bucket, and raises
    an alert only when the alert rule is met (SP2, D-34).

### Candidate or Finding? (SP2, D-33)

A listing that matches only on **name or package** is stored as a **Candidate** and never alerts. It becomes a
**Finding** when the icon matches the official logo or app icon, when it is a repackaged official app, or when the
APK was downloaded and its signer checked (`analysed = logo_match or repackaged or file downloaded` in
`backend/app/modules/apk/module.py`). APK scores are clamped to Medium or High, so an APK Finding always reaches
the default "Alert from" level (Medium); a brand set to "High" only gets alerts for High APK findings.

Each observation records the facts `logo_match` and `signer_mismatch` (unknown when no APK was downloaded). If a
later scan finds that the APK is signed by a non-official certificate ("APK signed by a non-official
certificate"), or that the icon now matches the logo, that is a **meaningful change**: it goes on the timeline
and can raise a new alert, even after an analyst decision (D-36).

### Flow diagram

```
 Daily schedule / manual scan
            |
            v
 BrandContext (keywords, official packages, publishers, signer fingerprints, logo hashes)
            |
            v
 Web search: "<term>" apk (site:apkpure.com OR ...)      <-- backend/app/core/search.py
            |
            v
 Keep only mirror-site URLs, remove duplicates
            |
            v
 Read listing page via safe fetcher                      <-- backend/app/core/fetch.py
 (title, package, version, developer, icon, .apk link)
            |
            v
 Official package + approved developer + nothing to verify? --yes--> ignore (genuine re-host)
            | no
            v
 Brand relevant? (name / package / brand word in package) --no--> ignore
            | yes
            v
 Compare icon with official logo + app icon              <-- backend/app/core/imaging.py
            |
            v
 Direct .apk link? --yes--> download (max 150 MB) -> SHA-256, manifest, signers
            |                                                   |
            |                          signed with official key? --yes--> ignore (genuine)
            v                                                   | no
 Signals + output fields -> Detection  <------------------------+
            |
            v
 record_detection: score, clamp to Medium/High, finding (Candidate or Finding),
   observation, timeline, evidence to bucket; alert if Finding and risk >= "Alert from"
```

## 4. Tools and libraries used

| Tool | What it is | What we use it for | Why this tool (and alternatives rejected) | Where in the code |
|---|---|---|---|---|
| Web search (Brave, SerpAPI or DuckDuckGo) | Search engines reached through an API or a public page | Finding APK listing pages on mirror sites | Mirror sites have no official API; searching is what any user does (D-12). Bing's public page was tested and rejected because it ignores `site:` (D-23). No CAPTCHA solving (D-23). | `backend/app/core/search.py` |
| Safe fetcher (httpx + tenacity) | The only allowed way to reach the internet | Reading listing pages, icons and APK files | Required for every outbound request (D-18) | `backend/app/core/fetch.py` |
| Androguard | Python library that reads Android APK files | Reading the manifest (package, version, app name) and the v2/v3/v3.1 signing certificates | Reads metadata without decompiling or running anything (OOS-03, D-26). MobSF, apktool, JADX and YARA were kept for Phase 2 (D-26). Running the app in an emulator was rejected (D-26). | `backend/app/modules/apk/module.py` (`read_manifest`), `backend/app/modules/apk/signing.py` |
| cryptography | Python library for certificates and cryptography | Reading the v1 (JAR) signature in `META-INF/*.RSA/.DSA/.EC` and the certificate subject | Standard, maintained library; already used by the safe fetcher (D-26) | `backend/app/modules/apk/signing.py` |
| zipfile (Python standard library) | Reads ZIP archives | Fallback manifest reading; listing `META-INF` files | An APK is a ZIP file | `backend/app/modules/apk/module.py`, `signing.py` |
| RapidFuzz | Fast string-similarity library | Package similarity (`fuzz.ratio`), and name similarity through `similarity.py` | No alternative recorded in the decision log | `backend/app/modules/apk/module.py`, `backend/app/core/similarity.py` |
| Pillow + ImageHash | Image loading and perceptual hashing | Comparing the listing icon with official images | No alternative recorded in the decision log | `backend/app/core/imaging.py`, `backend/app/modules/common.py` |
| hashlib (standard library) | Hash functions | SHA-256 of the APK file and of each certificate | Standard | `backend/app/core/evidence.py`, `signing.py` |
| boto3 + S3-compatible storage | Object storage client | Storing the APK, icon and metadata as evidence | Storage is RustFS by default; any S3 store works (D-22) | `backend/app/core/evidence.py`, `backend/app/core/findings.py` |

## 5. How each tool works internally, explained simply

### Web search (shared helper)

`search.search(query, count)` in `backend/app/core/search.py` picks one provider, in this order:

1. **Brave Search API**, if `BRAVE_SEARCH_API_KEY` is set.
2. **SerpAPI** (Google results), if `SERPAPI_API_KEY` is set.
3. **DuckDuckGo's public HTML page**, if `FREE_SEARCH_FALLBACK=true` (the default).

The free DuckDuckGo route is slow on purpose. Only one free search is allowed every 12 seconds
(`FREE_SEARCH_INTERVAL_SECONDS`), shared by all workers through a Redis lock. If DuckDuckGo refuses a search,
free search pauses for 15 minutes for every worker. Each search is reported on the scan component named after
the provider that ran, for example "Web search - DuckDuckGo (free, paced)": `ok` when it worked, `unavailable`
with the reason when it did not. The results of the searches that worked are kept. If **every** search failed,
nothing was checked, so the component is marked fatal and the scan ends `failed` rather than looking clean
(D-31). With the free route, coverage is best-effort; a Brave key makes it reliable (D-23).

### Safe fetcher (shared helper)

`fetch()` in `backend/app/core/fetch.py` allows only `http` and `https`. It resolves the host name and
refuses private, loopback and cloud-metadata addresses, on every redirect and again on the address it
actually connected to. It has timeouts (15 s), up to 3 attempts with back-off, a per-host limit of 30
requests per minute, and a size cap. For APK files the cap is raised to 150 MB (`FETCH_MAX_APK_BYTES`). It
only returns bytes in memory. It never saves or opens a file.

### Androguard

An APK is a ZIP archive. Inside is `AndroidManifest.xml`, stored in a compact binary format. The manifest
declares the package name, version and app name. Androguard knows how to decode that binary format. The
module calls `APK(apk_bytes, raw=True)` and then `get_package()`, `get_androidversion_name()` and
`get_app_name()`. If Androguard fails, the module opens the ZIP itself and searches the manifest as text. A
real APK's manifest is binary, so if this text search works, the module adds the note "Manifest is not
compiled binary XML - not a genuine build". If the file is not a ZIP at all, the note is "Not a valid APK
archive".

### Signing certificates (D-26)

Every Android app is **signed**. The developer holds a private key; the signature proves the file was
produced by the holder of that key and not changed since. The signature contains a **certificate**, which
names the signer and holds the public key.

Android has several signature formats ("schemes"):

| Scheme | Where it lives | How we read it |
|---|---|---|
| v1 (JAR signing) | Files in `META-INF/` ending in `.RSA`, `.DSA` or `.EC` (PKCS#7 blocks) | `cryptography`'s `pkcs7.load_der_pkcs7_certificates` |
| v2, v3, v3.1 | A binary "APK Signing Block" placed inside the ZIP file, before its directory | Androguard's `get_certificates_der_v2/v3/v31` |

For each certificate found, the module computes the SHA-256 hash of the certificate bytes. This is the
**fingerprint**. It is the same value Google Play Console shows under App integrity, App signing key
certificate. The analyst stores Example Bank's fingerprint in the allowlist as a `signing_cert` entry. The
value is normalised (colons and spaces removed, upper case) by `normalize_fingerprint`.

A criminal can copy a name, an icon and even a package name. A criminal cannot produce a signature with
Example Bank's private key. So the fingerprint is the strongest single proof.

### RapidFuzz and the brand relevance rule (shared helper)

RapidFuzz scores how similar two strings are, from 0 to 100. `fuzz.ratio("com.examplebank.mob1le",
"com.examplebank.mobile")` is high; two unrelated package names score low.

Names are judged by `BrandContext.relevance` in `backend/app/modules/base.py` (decision D-25):

- **Strong terms** are brand words of 6 or more letters (spaces removed), such as "Example Bank"
  (`examplebank`). They count on their own.
- **Weak terms** are short abbreviations, such as "EXB". They count only as an exact word **and** only when
  a context word (such as "example") also appears. Generic company words such as "bank", "limited" and
  "services" never count as context.
- A close misspelling of a term with 8 or more letters counts on its own. A misspelling of a 6-7 letter term
  needs context.

This stops an abbreviation that happens to match another company from raising alerts.

### Image hashing (shared helper)

`backend/app/core/imaging.py` turns an image into short fingerprints called **perceptual hashes** (pHash and
dHash). Similar-looking images get similar hashes, even after resizing or re-compression. Borders are trimmed
first so a padded logo still matches. The match score is 0-100 (100 = identical). A score at or above
`LOGO_MATCH_THRESHOLD` (default 85) counts as a logo match.

## 6. Code map

| File | Responsibility |
|---|---|
| `backend/app/modules/apk/module.py` | The module: sources, listing reader, manifest reader, analysis |
| `backend/app/modules/apk/signing.py` | Reading and fingerprinting signer certificates (D-26) |
| `backend/app/modules/apk/__init__.py` | Silences Androguard's very verbose log output |
| `backend/app/modules/base.py` | `BrandContext`, `relevance`, `Detection` |
| `backend/app/modules/common.py` | `image_match`, `literal_brand_in`, `og_image`, `html_title` |
| `backend/app/core/search.py` | Web search providers and pacing |
| `backend/app/core/fetch.py` | Safe fetcher |
| `backend/app/core/imaging.py` | Perceptual hashes and match score |
| `backend/app/core/allowlist.py` | Normalising allowlist values, including signing certificates |
| `backend/app/core/scoring.py` | Points, levels, per-module clamp |
| `backend/app/core/findings.py` | Findings, observations, timeline, alert rule, evidence storage |
| `backend/app/modules/registry.py` | Output fields and runner registration |

Key functions in call order:

1. `execute_scan` (`backend/app/workers/scan.py`) calls `get_runner("apk")`, which creates `ApkModule`.
2. `ApkModule.run` uses `LiveApkSource` (the automated tests inject `FixtureApkSource` from
   `backend/tests/support/fixture_sources.py` instead) and calls `listings(ctx, self.report)`. Every part of the
   work is recorded on the scan report: "Web search - (provider)", "Listing pages" (pages that could not be read
   are counted as failed), "Listing analysis" (only when a listing crashes the analysis) and "APK download &
   analysis" (a file that could not be downloaded is counted as failed, never treated as "no file").
3. `LiveApkSource.listings` calls `search.search`, then `_read_listing` for each result.
4. `ApkModule.analyse` for each `Listing`:
   `ctx.relevance` -> `fuzz.ratio` -> `literal_brand_in` -> `image_match` -> `try_fetch` (APK) ->
   `sha256` -> `read_manifest` -> `read_signers` -> builds `Signals` and `Detection`.
5. `record_detection` scores the detection with `score(signals, ModuleName.apk)`, stores the finding, observation and evidence, and decides on an alert.

## 7. Signals collected and how they become the risk score

The module never computes points itself. It only reports what it saw, as `Signals`. The scoring function in
`backend/app/core/scoring.py` turns them into points.

| Signal | When the APK module sets it | Points |
|---|---|---|
| `brand_exact_in_domain` | A strong brand word is inside the package name (or a weak one with context), or the official package is re-signed with another key (D-20, D-26) | +40 |
| `typo_similarity` > 80 | The best of name similarity, package similarity, and 100 when the brand word is in the package | +25 |
| `official_logo` | Icon match score at or above the threshold (default 85) | +30 |
| `publisher_mismatch` | Developer is not an approved publisher, or the signer differs from the official one | +25 |

Then:

1. The points are added and capped at 100 (RSK-10).
2. The **module clamp** applies (D-03). The APK module may only report Medium or High. So the score is raised
   to at least 30 and lowered to at most 79.
3. The level comes from the score: 0-29 Low, 30-59 Medium, 60-79 High, 80+ Critical (RSK-09).

The total before the clamp is kept as `raw_score` on the finding, for transparency.

### Worked example

The fake "Example Bank Mobile Banking" listing from the story:

| Check | Result | Points |
|---|---|---|
| `examplebank` inside `com.examplebank.mobilebanking.secure` | yes | +40 |
| Similarity (brand word in package gives 100) | 100 > 80 | +25 |
| Icon match with the official logo | 97 >= 85 | +30 |
| Developer "EB Apps Studio" not approved; signer not Example Bank's | yes | +25 |
| Total | 120, capped to 100 | raw score 100 |
| Module clamp (Medium/High only) | 100 lowered to 79 | **79, High** |

A second case: a listing named "Example Bank (MOD, no ads)" with the official package
`com.examplebank.mobile` and the developer label "Example Bank Ltd". Because the brand has a signing
certificate on record and the mirror offers a download, the module does not trust the labels. The file is
signed by someone else. The alert title becomes "Fake APK (official package re-signed with a different
key)", and both `brand_exact_in_domain` and `publisher_mismatch` fire.

A listing with nothing suspicious except a relevant name still scores at least 30 (Medium), because the
clamp never lets an APK alert be Low.

## 8. Output fields shown to analysts

The finding and alert pages show the fields in `OUTPUT_FIELDS[ModuleName.apk]` first (`backend/app/modules/registry.py`),
then any other detail keys. Empty values are hidden.

| Field | Meaning |
|---|---|
| App Name | Title of the listing page (or the search result title) |
| Package Name | Package from the listing, or from the downloaded manifest if the listing had none |
| Similarity Score | Highest of name similarity, package similarity, or 100 if the brand word is in the package |
| Source | URL of the listing page on the mirror |
| Logo Match | True when the icon matches the official logo or app icon at or above the threshold |
| Risk Level | Medium or High, from the scoring model |
| Version | Version from the listing page, or from the manifest |
| Developer | Developer name read from the listing page |
| SHA256 | Hash of the downloaded APK file (empty when no direct download) |
| Logo Match Score | The 0-100 icon match score |
| Package Similarity | RapidFuzz ratio against the closest official package |
| Name Similarity | Similarity of the app name to the brand (from `relevance`) |
| Official Package | True when the package is on the brand's official list |
| Suspicious Developer | True when the developer is not an approved publisher |
| Signed By | Certificate subject(s), e.g. `CN=EB Apps Studio, O=EB Apps Studio` |
| Signer SHA-256 | Fingerprint(s) of the signing certificate(s) |
| Signer Matches Official | True / False; empty when not checked (no file, or no official fingerprint on record) |
| Signature Schemes | Which schemes were found: v1, v2, v3, v3.1 |

Extra detail fields also stored: `Repository` (the mirror host name) and `Manifest` (the manifest data as
JSON).

## 9. Evidence stored

| Evidence | Kind | When |
|---|---|---|
| Listing metadata (site, title, package, version, developer, URLs) | `metadata` | Always |
| The icon image, with its URL and match score | `image` | When the icon could be downloaded |
| The APK file, with URL, SHA-256, manifest, signer details and the warning "Untrusted file. Do not install or open." | `file` | When the listing offers a direct `.apk` link and the download succeeded |

Files go to the evidence bucket under `findings/<brand>/<finding>/...`, and each item is linked to the finding and to the observation (scan) that captured it. Non-image files are stored as
attachments, so a browser downloads them instead of opening them. The same file (same SHA-256) is not stored
twice on later scans (D-21). APK files are never executed or decompiled (OOS-03, D-12, D-18).

## 10. Settings and configuration

Environment variables (`backend/app/config.py`):

| Variable | Default | Effect on this module |
|---|---|---|
| `BRAVE_SEARCH_API_KEY` | empty | Use Brave Search for discovery (recommended) |
| `SERPAPI_API_KEY` | empty | Use SerpAPI if no Brave key |
| `FREE_SEARCH_FALLBACK` | `true` | Use DuckDuckGo's public page if no key |
| `FREE_SEARCH_INTERVAL_SECONDS` | `12.0` | Minimum gap between free searches |
| `FETCH_MAX_APK_BYTES` | 150 MB | Largest APK that will be downloaded |
| `FETCH_TIMEOUT_SECONDS` | `15.0` | Timeout per request |
| `FETCH_RATE_PER_HOST_PER_MINUTE` | `30` | Requests per minute to one mirror |
| `LOGO_MATCH_THRESHOLD` | `85` | Icon match score that counts as a logo match |

Brand settings (entered in the brand configuration screens, stored in the allowlist):

| Allowlist kind | Example for Example Bank | Used for |
|---|---|---|
| `package` | `com.examplebank.mobile` | Official package check and package similarity |
| `publisher` | `Example Bank Ltd` | Approved developer check |
| `signing_cert` | the 64-character SHA-256 from Play Console | Signature verdict (D-26) |
| Brand assets: logo, app icon | uploaded images | Icon comparison |

## 11. How it is tested

Tests are tagged with requirement IDs using `@pytest.mark.req(...)`. The test run writes every result to
`backend/reports/requirements-results.json`, which feeds the UAT report.

| Test | File | What it proves | Markers |
|---|---|---|---|
| `test_ac04_simulated_fake_apk_detected` | `backend/tests/modules/test_acceptance.py` | A fake APK (look-alike package, copied icon, attacker developer) raises an alert with SHA-256, version, developer, file evidence, Medium/High level and `Signer Matches Official` False. The genuine app on a mirror and an unrelated "Zen Tasks" app raise no alert. | AC-04, APK-01 to APK-09, OBJ-03 |
| `test_repackaged_official_app_detected_by_signature` | same | Official package and developer label, but a different signing key: alert titled "re-signed", High, with both exact-match and publisher-mismatch rules | APK-02, APK-06, APK-07, D-26 |
| Relevance tests | `backend/tests/unit/test_relevance.py` | Short abbreviations need context | APK-03, D-25 and others |
| Similarity tests | `backend/tests/unit/test_similarity.py` | Name similarity behaviour | APK-03, APK-04 |
| Signing certificate formats | `backend/tests/unit/test_allowlist.py` | Fingerprints pasted in different formats normalise to the same value | - |
| Module clamp | `backend/tests/unit/test_scoring.py` | APK alerts are always Medium or High | - |
| Honest reporting | `backend/tests/unit/test_runner_reporting.py` | The scan fails when every search is unavailable; results of searches that worked are kept when one fails | RDA-03, RDA-17, RDA-21 |

The acceptance tests use a fictional test brand and simulated listings
(`backend/tests/fixtures/sources/apk_search.json`). The three test APK files in
`backend/tests/fixtures/site/apk/` were built by `backend/tests/support/build_apk_fixtures.py` with two signing
identities (an "official" one and an "attacker" one). They are test files, not real apps.

## 12. Known limitations and missing capabilities

| Limitation | Effect |
|---|---|
| No permissions analysis | The module does not list what the app asks to do (read SMS, overlay screens). Planned for Phase 2 with MobSF (D-26). |
| No extracted URLs or servers | The module does not look inside the code for the attacker's server addresses. Out of scope (OOS-03); Phase 2 (D-26). |
| Most mirrors give no direct file | Many sites hide the download behind buttons, scripts or redirect pages. The module only follows an absolute link ending in `.apk`. Without a file there is no SHA-256, no manifest and no signature check. |
| Listing pages read with simple patterns | Package, developer and version are found with regular expressions. On some sites they may be missed or wrong. |
| Only the first three brand terms are searched | Other keywords and product terms are not used for APK discovery. |
| Without a signing certificate on record | A mirror listing that uses the official package and an approved developer name is assumed genuine. |
| Free search is best-effort | Without an API key, discovery is paced and may pause for 15 minutes (D-23). The scan then shows the search component as Unavailable, and ends `failed` if no search worked at all (D-31). |
| Similarity is checked before the download | A package found only in the downloaded manifest is shown, but was not used for the relevance gate or similarity. |
| Only eight mirror sites | Sites not in `APK_SITES`, and APKs shared on Telegram or by direct links, are not searched by this module. |

## Key takeaways

- An APK is an Android app file; mirrors host both genuine and fake copies.
- The module finds listings through site-restricted web search, reads the public page, and compares name,
  package, icon and developer with the brand's official values.
- When a direct download exists, the file is hashed, its manifest read and its signature checked. A file
  signed with the brand's official key never raises an alert (D-26).
- Points come from `backend/app/core/scoring.py`; APK alerts are always clamped to Medium or High.
- Nothing is ever installed, executed or decompiled. Deeper analysis is planned for Phase 2.
