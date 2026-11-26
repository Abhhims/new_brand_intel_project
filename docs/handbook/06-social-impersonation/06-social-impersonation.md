# Chapter 06 - Social Media Impersonation

In this chapter:
- What social media impersonation is, and why fake "support" accounts are so effective against bank customers.
- How the module finds candidate accounts on Telegram, X, Facebook, Instagram and LinkedIn without logging in or scraping behind logins (D-10, D-23).
- How each account is judged: username, display name, profile picture, bio and support wording.
- How the risk score is built, what analysts see, and the honest limits of search-based discovery.

This chapter is about fake **accounts**. Posts, videos and ads that misuse the brand (on YouTube, Facebook,
Instagram, X, Threads, Meta ads, Pinterest, TikTok, LinkedIn and Telegram) are found by a separate module, the
social media brand-misuse monitor, described in Chapter 14. Accounts on X, Facebook, Instagram, LinkedIn and
Telegram stay in this module, so the same account is not reported twice (D-38).

## 1. What this module detects and why it matters

### Plain words first

**Impersonation** means pretending to be someone else. On social media, a criminal creates an account that
looks like it belongs to a brand: a similar **username** (the unique `@handle`), the brand's name as the
**display name**, the brand's logo as the **profile picture**, and a **bio** (the short description) that
offers "customer support".

Customers who are already upset (a failed payment, a blocked card) search for help. They find the fake
account, or the fake account finds them by replying to their public complaint. The fake "agent" then asks
for card numbers, one-time passwords or a "verification fee".

### An attack story

1. An Example Bank customer posts on X: "My Example Bank transfer failed, money gone!"
2. Within minutes, `@examplebank_support` replies: "Sorry for the trouble. DM us your account number and the
   OTP you receive, our 24/7 team will reverse it."
3. The account uses the Example Bank logo and the display name "Example Bank Support". Its bio says
   "Official Example Bank customer care".
4. The customer sends the OTP. The money is gone for real.

The real Example Bank handle is `@examplebank`. This module finds look-alike accounts, compares them with the
brand's official handles, and records a finding with a screenshot where one can be taken. It becomes an alert
when the finding meets the brand's alert rule (Chapter 10).

## 2. Requirements it covers

| ID | Requirement | How the module covers it |
|---|---|---|
| OBJ-04 | Monitor social platforms for impersonation accounts | The whole module |
| SOC-01 | Platform: X (Twitter) | Site-restricted search on `x.com` and `twitter.com` |
| SOC-02 | Platform: Facebook | Site-restricted search on `facebook.com` |
| SOC-03 | Platform: Instagram | Site-restricted search on `instagram.com` |
| SOC-04 | Platform: LinkedIn | Site-restricted search on `linkedin.com/in` and `linkedin.com/company` |
| SOC-05 | Platform: Telegram public channels/usernames | Telegram API (Telethon) or public `t.me` pages |
| SOC-06 | Username similarity | `Username Similarity` |
| SOC-07 | Display name similarity | `Display Name Similarity` |
| SOC-08 | Profile image/logo similarity | `Logo Match`, `Logo Match Score` |
| SOC-09 | Bio/description contains brand name | `Bio Mentions Brand` |
| SOC-10 | Uses official support/contact terminology | `Support Terms` |
| SOC-11 | Output: Platform, Username, Display Name, Similarity, Logo Match, Followers, Risk Level (L/M/H) | `OUTPUT_FIELDS[social]` |
| SOC-12 | Impersonation dashboard with screenshots | Profile screenshots as evidence |
| AC-06 | Detects simulated fake social account | Acceptance test |

Related decisions: D-03 (Low/Medium/High), D-10 (social sources), D-20 (exact match applies to the handle),
D-23 (working without paid keys), D-25 (short abbreviations need context).

## 3. How it works

### Why discovery is done this way (D-10)

X's API is paid. Facebook, Instagram and LinkedIn have no public search API and forbid scraping. So the
platform does not log in and does not scrape behind logins. Instead:

| Platform | How candidate accounts are found |
|---|---|
| Telegram | The official Telegram API through Telethon, if credentials are configured. Otherwise, public `t.me/<username>` pages for likely impersonator names (D-23). |
| Instagram, TikTok, Facebook, X, LinkedIn (with `APIFY_TOKEN`, D-43) | Apify: Instagram and TikTok account search, plus the authors of the posts and ads found by the Chapter 14 Apify searches (same runs, from cache). These profiles carry the real bio, follower count and avatar, so they are **Findings**, not Candidates. TikTok accounts are covered only this way. |
| X, Facebook, Instagram, LinkedIn | A web search restricted to that site, for example `(site:instagram.com) ("Example Bank" OR "examplebank")`. The profile details come from the search result. When Apify found the same handle, the Apify profile is kept. |

### The process, step by step

1. **A scan starts.** Daily at 02:00 UTC, or by hand. The `social` runner runs on the separate **browser
   worker** queue, because it takes screenshots (D-18).
2. **Telegram discovery.**
   - **With API credentials** (`TELEGRAM_API_ID`, `TELEGRAM_API_HASH`, `TELEGRAM_SESSION`): for each of the
     first three brand terms, Telethon sends Telegram's `contacts.Search` request (limit 50). Every public
     chat, channel or user with a username becomes a candidate.
   - **Without credentials** (and `TELEGRAM_PUBLIC_FALLBACK=true`, the default): the module builds likely
     usernames from each brand label of 4+ letters plus common affixes: `official`, `_official`, `support`,
     `_support`, `help`, `care`, `customercare`, `helpdesk`, `india`, `app` and their underscore forms. For
     Example Bank this gives names like `examplebank_support` and `examplebankcare`. Official handles are
     skipped. Up to 120 names are checked. For each, the public page `https://t.me/<name>` is fetched. If it
     has a page title, the account exists; its name, description, subscriber count and photo are read.
   - The scan always says which of the two ran (D-31). Without credentials it shows **"Telegram API: Not
     configured"** (so the scan ends `partially_completed`) next to **"Telegram public pages: Completed"**.
     With credentials, a client or search error marks "Telegram API" as `failed`.
3. **Search discovery for X, Facebook, Instagram, LinkedIn.** One web search per platform, up to 20 results
   each. From each result URL the module extracts the handle (for example the first path part of
   `instagram.com/examplebank.official/`). Reserved paths such as `search`, `login`, `hashtag`, `posts` and
   `groups` are ignored. The display name is taken from the result title and the bio from the result
   snippet.
4. **Skip official accounts.** If the handle is on the brand's official handle list, it is ignored.
5. **Judge relevance.** The module checks the handle, display name and bio with `BrandContext.relevance`, and
   compares the handle with the brand's labels. Long brand labels (8+ letters) need a handle similarity of
   80; shorter ones need 85 plus brand context (D-25). Irrelevant accounts are dropped.
6. **Collect the other signals.** Is the brand named exactly in the handle? Does the bio mention the brand?
   Which support words appear ("support", "customer care", "DM us", "24/7", "KYC", "refund", "verify",
   "hiring" and others)?
7. **Compare the profile picture** (when there is one) with the official logo, app icon and favicon.
8. **Take a screenshot** of the profile page with the headless browser. Many profiles need a login, so this
   can fail or show a login wall; the failure is logged and the finding is still recorded.
9. **Build the detection** (a `Detection`) and pass it to `record_detection` (`backend/app/core/findings.py`),
   which scores it (Low to High), creates or updates one finding per platform and handle, keyed
   `<platform>:<handle>`, records an observation for this scan, and raises an alert only when the alert rule is
   met.

### Candidate or Finding? (SP2, D-33)

An account known **only from a web search result** (title and snippet) is stored as a **Candidate** and never
alerts. It is a **Finding** when it came from Telegram (API or public page, where the profile itself was read) or
when its profile picture matches the official logo (`analysed = discovery is not "web search" or logo_match` in
`backend/app/modules/social/module.py`). A Finding raises an alert only when its risk level is at or above the
brand's "Alert from" level (default Medium, D-34), so a Low account is kept on the Findings page but does not
enter the alert queue.

Each observation records the fact `logo_match`. If a later scan finds that the profile picture now matches the
logo ("Official logo detected"), that is a **meaningful change**: it goes on the timeline and can raise a new
alert, even after an analyst decision (D-36).

### Flow diagram

```
 Daily schedule / manual scan  (browser worker queue)
            |
            v
 +-----------------------------+      +-----------------------------------------+
 | Telegram                    |      | X / Facebook / Instagram / LinkedIn     |
 | API creds? -> Telethon      |      | web search: (site:...) ("term" OR ...)  |
 |   contacts.Search(term)     |      |   -> handle from result URL             |
 | no creds -> t.me/<brand+    |      |   -> name from title, bio from snippet  |
 |   affix> public pages       |      |                                         |
 +-------------+---------------+      +--------------------+--------------------+
               |                                           |
               +---------------------+---------------------+
                                     v
                     Profiles (platform, handle, name, bio, ...)
                                     |
                       Official handle? --yes--> ignore
                                     | no
                                     v
                Relevant? (handle / name / bio, D-25) --no--> ignore
                                     | yes
                                     v
        exact brand in handle, bio mentions brand, support terms
                                     |
        profile picture vs logo / app icon / favicon (if picture known)
                                     |
        screenshot of profile page (headless browser, may fail)
                                     |
                                     v
        Signals -> Detection -> record_detection (Low/Medium/High) -> finding + observation
        + evidence -> alert if Finding and risk >= brand "Alert from" level
```

## 4. Tools and libraries used

| Tool | What it is | What we use it for | Why this tool (and alternatives rejected) | Where in the code |
|---|---|---|---|---|
| Telethon | Python client for Telegram's official API (MTProto) | Searching public Telegram usernames and channels by keyword | Telegram is the one platform with an official free search API (D-10) | `backend/app/modules/social/module.py` (`_telegram`), `backend/scripts/telegram_login.py` |
| Public `t.me` pages + safe fetcher | Telegram's public preview pages, read like a browser | Fallback when no Telegram credentials are configured | Works without an account (D-23) | `social/module.py` (`telegram_public`, `_telegram_page`), `backend/app/core/fetch.py` |
| Web search (Brave, SerpAPI or DuckDuckGo) | Search engines | Finding public profiles on X, Facebook, Instagram, LinkedIn | X API is paid; Facebook, Instagram and LinkedIn have no public search API and forbid scraping (D-10). Bing rejected (ignores `site:`); CAPTCHA solving and fingerprint spoofing rejected (D-23). | `backend/app/core/search.py` |
| Playwright (Chromium) | Headless browser | Screenshot of the profile page | Already the platform's browser (FND-11); runs in an isolated worker (D-18) | `backend/app/core/browser.py` |
| RapidFuzz (through `similarity.py`) | String similarity | Handle and display-name similarity, with look-alike characters folded | No alternative recorded in the decision log | `backend/app/core/similarity.py` |
| Pillow + ImageHash | Perceptual image hashing | Profile picture vs official images | No alternative recorded in the decision log | `backend/app/core/imaging.py` |
| boto3 + S3-compatible storage | Object storage | Screenshots, profile pictures, metadata | RustFS by default (D-22) | `backend/app/core/evidence.py` |

## 5. How each tool works internally, explained simply

### Telethon and the Telegram API

Telegram offers an official API that any registered app may use. You get an **API ID** and **API hash** from
`https://my.telegram.org`. Telethon logs in as a normal Telegram user account (the "monitoring account").
The login happens once, by hand, with `python -m scripts.telegram_login`: it asks for the phone number and the
code Telegram sends, then prints a **session string**. That string goes into `TELEGRAM_SESSION`, so workers
can reconnect without a code.

The module then calls `contacts.SearchRequest(q=term, limit=50)`. This is the same global search a person
uses in the Telegram app. It returns public channels, groups and users whose name or username matches. The
module keeps those with a username and records the title and, when Telegram gives it, the member count.

### Public t.me pages

Every public Telegram username has a preview page at `https://t.me/<username>`. For a real account, the page
contains a title block (`tgme_page_title`), a description, an "extra" line such as "1 284 subscribers", and a
photo. For a name that does not exist, Telegram returns a generic page without that title, so the module
treats it as "not found". Each check is one request through the safe fetcher, which allows 30 requests per
minute to one host. So 120 checks take about four minutes.

### Site-restricted web search (shared helper)

A search like `(site:x.com OR site:twitter.com) ("Example Bank" OR "examplebank")` asks the search engine for
pages only from those sites. The result gives a URL, a title and a short snippet. That is all the module
learns about the profile on these four platforms. Provider order, pacing (one free search per 12 seconds)
and the 15-minute pause after a refusal are the same as described in Chapter 04 and in
`backend/app/core/search.py`. Each search is reported on the scan component named after the provider that
ran, for example "Web search - Brave Search API". If search is unavailable for one platform, that platform is
skipped and the component shows `unavailable` with the platform and reason; the other platforms still run.

### Similarity with look-alike characters

`similarity()` in `backend/app/core/similarity.py` first "folds" look-alike characters to Latin letters:
Cyrillic `а` to `a`, digit `0` to `o`, `1` to both `l` and `i`, `rn` to `m`, and so on. Then RapidFuzz
compares the result with each brand label. If the brand is (nearly) intact inside a longer handle, a partial
match of 85 or more counts. So `@examp1ebank_care` still scores high against `examplebank`.

### Brand relevance (D-25)

The same `BrandContext.relevance` rule as the other modules: strong terms (6+ letters) count alone; short
abbreviations such as "EXB" count only with a context word such as "example". In addition, for the handle:

| Brand label length | Handle similarity needed |
|---|---|
| 8 or more letters (e.g. `examplebank`) | 80, on its own |
| 6-7 letters | 85, and brand context or an abbreviation must also appear |

### Headless browser screenshot

`capture()` in `backend/app/core/browser.py` opens the profile URL in Chromium, with downloads refused,
service workers blocked, and every request checked against the safe fetcher's destination rules. The module
asks for a viewport-only (not full page) screenshot.

## 6. Code map

| File | Responsibility |
|---|---|
| `backend/app/modules/social/module.py` | `LiveSocialSource`, Telegram public fallback, handle extraction, analysis, scan components |
| `backend/tests/support/fixture_sources.py` | `FixtureSocialSource`: simulated profiles for the automated tests only (D-32) |
| `backend/scripts/telegram_login.py` | One-time Telegram login that prints the session string |
| `backend/app/modules/base.py` | `BrandContext`, `relevance`, `strong_labels`, `context_words` |
| `backend/app/modules/common.py` | `image_match`, `literal_brand_in` |
| `backend/app/core/allowlist.py` | `social_handle` turns pasted profile URLs into handles |
| `backend/app/core/search.py` | Web search |
| `backend/app/core/fetch.py` | Safe fetcher (t.me pages, profile pictures) |
| `backend/app/core/browser.py` | Screenshots |
| `backend/app/core/similarity.py` | Similarity and brand-term matching |
| `backend/app/core/scoring.py` | Points and clamp |
| `backend/app/core/findings.py` | Findings, observations, timeline, alert rule, evidence |

Key functions in call order:

1. `execute_scan` -> `get_runner("social")` -> `SocialModule()`.
2. `SocialModule.run` -> `LiveSocialSource.profiles(ctx, self.report)` -> `_telegram` (Telethon) or `telegram_public` ->
   `_telegram_page`; then `_search` -> `search.search` -> `_handle_from_url`.
3. For each `Profile`: `SocialModule.analyse` -> official handle check -> `ctx.relevance` ->
   `best_similarity` -> `brand_terms_in_text` (bio) -> support terms -> `literal_brand_in` ->
   `image_match` -> `capture` -> `Signals` -> `Detection`.
4. `record_detection` -> `score(signals, ModuleName.social)` -> `meets_rule`.

## 7. Signals collected and how they become the risk score

| Signal | When this module sets it | Points |
|---|---|---|
| `brand_exact_in_domain` | A strong brand term is literally in the handle, or a weak one with brand context (D-20) | +40 |
| `typo_similarity` > 80 | The higher of username similarity and display-name similarity | +25 |
| `social_image_match` | Profile picture matches the logo, app icon or favicon at or above the threshold (RSK-07) | +20 |

Bio mentions and support terms are shown to the analyst but do not add points. The module clamp (D-03)
allows Low, Medium and High: the score may start at 0 but is lowered to at most 79.

### Worked example

The criminal from the story also runs a Telegram channel, `examplebank_support`. The public-page fallback
finds it, and the page gives a profile picture:

| Check | Result | Points |
|---|---|---|
| `examplebank` literally in `examplebank_support` | yes | +40 |
| Username similarity (brand intact inside handle) | 100 > 80 | +25 |
| Profile picture matches the logo | 95 >= 85 | +20 |
| Total | 85 | raw 85 |
| Clamp (Low to High) | lowered to 79 | **79, High** |

`@exampelbank` on Instagram (letters swapped), found by search, so no picture is known:

| Check | Result | Points |
|---|---|---|
| Exact brand in handle | no | 0 |
| Handle similarity to `examplebank` | about 91 > 80 | +25 |
| Picture match | not checked (no picture URL) | 0 |
| Total | 25 | **25, Low** |

This account is a **Candidate** (found by search, no picture match), so it is listed on the Findings page but
does not raise an alert. The Telegram channel above is a Finding at High, so it raises an alert.

The bio "Official Example Bank customer care, DM us" would show `Bio Mentions Brand: True` and
`Support Terms: customer care, official, dm us, care`, which helps the analyst, but the score stays Low.

## 8. Output fields shown to analysts

From `OUTPUT_FIELDS[ModuleName.social]` in `backend/app/modules/registry.py`:

| Field | Meaning |
|---|---|
| Platform | X, Facebook, Instagram, LinkedIn or Telegram |
| Username | The handle, shown with `@` |
| Display Name | The account's shown name (for search results: the start of the result title) |
| Similarity Score | Higher of username and display-name similarity |
| Logo Match | True when the profile picture matches an official image |
| Followers | Followers or subscribers, when known (Telegram only in live use) |
| Risk Level | Low, Medium or High |
| Profile URL | Link to the profile |
| Bio | The bio (for search results: the search snippet) |
| Bio Mentions Brand | True when the bio names the brand (D-25 rules) |
| Support Terms | Support words found in the name, bio or handle |
| Logo Match Score | The 0-100 picture match score |
| Discovery Source | "Telegram API", "Telegram public page" or "web search" |

Extra detail fields also stored: `Username Similarity` and `Display Name Similarity`.

## 9. Evidence stored

| Evidence | Kind | When |
|---|---|---|
| The profile data as found (platform, handle, name, bio, followers, picture URL, profile URL, discovery source) | `metadata` | Always |
| The profile picture, with its URL and match score | `image` | When a picture URL is known and the download succeeded |
| A screenshot of the profile page, with final URL and page title | `screenshot` | When the profile URL could be opened in the headless browser |

Identical evidence is not stored again on later scans (D-21); a changed screenshot is stored as new evidence,
linked to the finding and to the observation (scan) that captured it.

## 10. Settings and configuration

Environment variables (`backend/app/config.py`, example values in `deploy/.env.example`):

| Variable | Default | Effect |
|---|---|---|
| `TELEGRAM_API_ID` | empty | Telegram API ID from my.telegram.org |
| `TELEGRAM_API_HASH` | empty | Telegram API hash |
| `TELEGRAM_SESSION` | empty | Session string printed by `python -m scripts.telegram_login` |
| `TELEGRAM_PUBLIC_FALLBACK` | `true` | Without all three values above, check public `t.me` pages instead |
| `BRAVE_SEARCH_API_KEY` | empty | Reliable search for X, Facebook, Instagram, LinkedIn (recommended) |
| `SERPAPI_API_KEY` | empty | Alternative search API |
| `FREE_SEARCH_FALLBACK` | `true` | DuckDuckGo public page when no key |
| `FREE_SEARCH_INTERVAL_SECONDS` | `12.0` | Gap between free searches |
| `LOGO_MATCH_THRESHOLD` | `85` | Picture match score that counts |
| `FETCH_RATE_PER_HOST_PER_MINUTE` | `30` | Limits the speed of `t.me` checks |

Brand settings: official social handles (`social_handle` allowlist; analysts can paste a full profile URL and
it is turned into the handle), keywords, official domains (their labels are used as Telegram stems), and the
logo, app icon and favicon.

If Telegram credentials are missing, the scan always records "Telegram API: Not configured"
(`TELEGRAM_API_ID / TELEGRAM_API_HASH / TELEGRAM_SESSION not set`). With the fallback on, "Telegram public
pages" is listed next to it; with the fallback off, no Telegram check runs at all. The Integrations page shows
both Telegram integrations and how to configure them.

## 11. How it is tested

| Test | File | What it proves | Markers |
|---|---|---|---|
| `test_ac06_simulated_fake_social_account` | `backend/tests/modules/test_acceptance.py` | A simulated `@..._support` account on X raises an alert with Logo Match, Bio Mentions Brand, "support" in Support Terms, follower count and a screenshot. Findings exist on all five platforms. The official handle raises nothing. | AC-06, SOC-01 to SOC-12, OBJ-04 |
| Relevance tests | `backend/tests/unit/test_relevance.py` | Abbreviation collisions are ignored, real brand uses are caught | SOC-06, SOC-07, D-25 |
| Similarity tests | `backend/tests/unit/test_similarity.py` | Look-alike characters and embedded brand names | SOC-06, SOC-07 |
| Handle normalisation | `backend/tests/unit/test_allowlist.py` | Profile URLs from X, Instagram, LinkedIn, Facebook, YouTube and t.me become plain handles | - |
| Module clamp | `backend/tests/unit/test_scoring.py` | Social findings range from Low to High | - |
| `test_social_without_telegram_credentials_is_not_configured` | `backend/tests/unit/test_runner_reporting.py` | Without credentials the run reports "Telegram API: Not configured" and the public-page check | RDA-03, RDA-17, RDA-21 |

The acceptance test uses simulated profiles in `backend/tests/fixtures/sources/social.json` and a simulated
profile page and avatar in `backend/tests/fixtures/site/social/`.

## 12. Known limitations and missing capabilities

| Limitation | Effect |
|---|---|
| Profile details only from search snippets (X, Facebook, Instagram, LinkedIn) | Display name and bio come from the search result title and snippet, which may be cut short or out of date. Followers are unknown. |
| No profile picture for search-found accounts | No picture URL is collected, so `Logo Match` cannot fire on these four platforms in live use. The screenshot may show the picture, but it is not compared. |
| Telethon results have no picture or bio | With API credentials, Telegram accounts are found by keyword but their photo and description are not read, so picture matching and bio checks do not apply to them. |
| Public t.me fallback only checks guessed names | It finds `examplebank_support` but not `eb_helpdesk_24x7`. |
| Screenshots often show a login wall | Facebook, Instagram and LinkedIn frequently require a login for profile pages. |
| Free search is best-effort | Without an API key, only a few searches run per scan before the free source pauses (D-23). |
| Only the first three brand terms are searched | Other keywords and product terms are not used. |
| Five platforms only | Accounts are checked on five platforms. YouTube channels and content on TikTok, Threads, Pinterest and YouTube are covered by the social media brand-misuse monitor (Chapter 14). Not covered anywhere: WhatsApp, Snapchat and others. |
| No posts or messages here | This module looks at accounts, not at what they post or send. Posts, videos and ads are covered by Chapter 14; private messages are not covered. |
| Bio and support terms add no points | A clear "customer care" scam with no picture and a modest handle may score Low; the analyst must read the fields. |

## Key takeaways

- Social impersonation is a fake account that pretends to be the brand, often as "customer support".
- Telegram uses the official API (Telethon) or, without credentials, public `t.me` pages for likely
  impersonator names. X, Facebook, Instagram and LinkedIn are found through site-restricted web search, never
  by logging in (D-10, D-23).
- Each account is compared with official handles, then judged on handle, display name, picture, bio and
  support words, with the D-25 rules for short abbreviations.
- Points: exact brand in handle +40, similarity over 80 +25, picture matches logo +20; levels Low to High.
- Search-based discovery sees only what the search engine shows: no follower counts and no pictures for
  four of the five platforms.
