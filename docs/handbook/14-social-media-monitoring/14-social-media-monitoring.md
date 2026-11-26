# Chapter 14 - Social Media Brand-Misuse Monitoring

In this chapter:
- What social media brand misuse is: posts, videos, ads and channels that use the brand's name or logo
  without permission, often to push a fake "customer care" number, a WhatsApp link or a UPI ID.
- Where the module looks on each platform, which official API or web search it uses there, and why (D-38).
- Which API key goes where in `deploy/.env`, and how to obtain each key, step by step.
- How fake contact details and scam wording are detected, how the risk score is built, and when a result is a
  Candidate, a Finding or an Alert (D-33, D-34).
- What evidence is kept, how it is tested, and the honest limits of each source.

## 1. What this module detects and why it matters

### Plain words first

Chapter 06 looks for fake **accounts** (profiles that pretend to be the brand). This chapter is about
**content**: a single YouTube video, an Instagram reel, a Facebook ad, a Threads post or a Telegram channel
message that uses the brand to fool people. The account that posts it may look harmless; the post itself is
the trap.

Typical misuse:

| Kind | Example |
|---|---|
| Fake helpline | A video titled "Example Bank KYC update helpline" with a phone number in the description |
| WhatsApp or Telegram lure | "Contact us on WhatsApp wa.me/91..." next to the brand name |
| Payment request | "Pay the processing fee to examplebank.refund@ybl" (a **UPI ID**, the Indian instant-payment address) |
| Investment or loan scam | An ad: "Example Bank pre-approved loan, no documents, guaranteed returns" |
| Logo misuse | A video thumbnail or channel picture that shows the official Example Bank logo |
| Fake channel | A YouTube channel called "Example Bank Help 24x7" |

### An attack story

1. A criminal uploads a YouTube video: "Example Bank KYC update helpline - account blocked? Call now". The
   thumbnail shows the Example Bank logo.
2. The description says: "Call Example Bank customer care on WhatsApp wa.me/919876543210. Refund charges
   payable to exb.refund.desk@ybl."
3. A customer whose card was blocked searches YouTube for "Example Bank KYC", finds the video, sends a
   WhatsApp message and pays the "refund charge". The money goes to the criminal.

The real Example Bank never publishes a WhatsApp number in a video description. This module finds the video
through the YouTube Data API, sees the brand name, the logo in the thumbnail, the WhatsApp link, the UPI ID
and the words "customer care", "KYC" and "call now", takes a screenshot, and raises a **Critical** alert that
lists the exact number and UPI ID being pushed (D-38 demo line).

## 2. Requirements and decisions it covers

| ID | Requirement | How the module covers it |
|---|---|---|
| SMM-01 | One Social Media section showing posts, videos, ads, channels and accounts that misuse the brand, each with a screenshot and a link | Module `social_media`; findings carry `URL`, screenshot and thumbnail, shown on the Social Media page (section 8) |
| SMM-02 | Platforms: YouTube, Facebook, Instagram, X, Threads, Meta ads, Pinterest, TikTok, LinkedIn, Telegram | Official APIs where a key is set, site-restricted web search always (section 3) |
| SMM-03 | Detect fake contact details (phone, WhatsApp, Telegram, UPI) and scam wording | `backend/app/modules/social_media/analysis.py` |
| SMM-04 | Skip the brand's own accounts and content that does not reference the brand | Official check and relevance check (section 3, steps 4 and 5) |
| SMM-05 | A source without a key is reported "not configured", never "nothing found" | Every source reports its own scan component (D-31) |
| SMM-06 | Video evidence = link + thumbnail + screenshot; no video download | Evidence list (section 9) |

Related decisions:

| Decision | What it says |
|---|---|
| D-38 | The social media brand-misuse monitor: platforms, official APIs when a key is set, web search otherwise, no paid scrapers, no video download, scoring points, Meta Ad Library limit |
| D-33 | Every result is stored as a Candidate (discovered, weak) or a Finding (analysed, with evidence) |
| D-34 | Only a Finding at or above the brand's "Alert from" level (default Medium) becomes an alert |
| D-31 | Honest scan status: each source is its own component (`ok`, `not_configured`, `unavailable`, `failed`) |
| D-25 | Short abbreviations need brand context before they count as a brand mention |
| D-10 | No logging in and no scraping behind logins; public web search where there is no API |

## 3. How it works

### Why discovery is done this way (D-38)

Each platform offers something different. The rule is: use the platform's **official API** when the owner
has configured a key, because it returns complete, reliable data (full text, author, views, thumbnail).
Always also run a **site-restricted web search**, because it costs nothing extra and covers platforms that
have no usable public search API. Paid scrapers were first rejected (D-38); since 2026-10-14 the owner allows
**Apify** (D-43) for Instagram, TikTok, Facebook posts, the Meta Ad Library, X and LinkedIn, because web search only
returns a link and a snippet there and the Meta APIs did not work as expected. Apify runs **next to** the official
APIs and web search; YouTube keeps its official API.

| Platform | Source used | Key in `deploy/.env` | Why this source |
|---|---|---|---|
| YouTube | YouTube Data API v3: `search.list` for videos (newest first, last N days) and channels, then `videos.list` and `channels.list` for details | `YOUTUBE_API_KEY` | Official, free daily quota, returns description, tags, views and thumbnail. Without a key, YouTube is searched through web search instead. |
| Meta ads (ads on Facebook and Instagram) | Meta Ad Library API, `ads_archive` endpoint | `META_AD_LIBRARY_TOKEN`, `META_AD_COUNTRIES` | The only official way to search ads. See the EU/UK limit in section 12. |
| Threads | Threads API `keyword_search`, most recent first | `THREADS_ACCESS_TOKEN` | Official Threads search. Without a token, Threads is still covered by web search. |
| X (Twitter) | X API v2 `tweets/search/recent` (reposts excluded) | `X_BEARER_TOKEN` | Official, full post text and counts, but paid. Without a token, X is searched through web search. |
| Telegram | Telethon `messages.SearchGlobal`, public channel posts only | existing `TELEGRAM_API_ID`, `TELEGRAM_API_HASH`, `TELEGRAM_SESSION` | Telegram's free official search. Accounts stay in the Chapter 06 module. |
| Instagram, TikTok, Facebook posts, Meta ads, X, LinkedIn (D-43) | Apify actors (`backend/app/modules/social_media/apify_sources.py`): Instagram hashtag posts/reels, TikTok video search, Facebook post search, Meta Ad Library scraper, X search, LinkedIn post search. Brand terms (last `SOCIAL_MEDIA_LOOKBACK_DAYS`) plus the first `APIFY_SCAM_QUERIES` scam searches | `APIFY_TOKEN`, `APIFY_PLATFORMS`, `APIFY_ITEMS_PER_QUERY`, `APIFY_MAX_CHARGE_USD` | Full text, author, likes/views and thumbnail where web search only gives a snippet; the ad scraper also returns commercial ads shown in India. Paid per result; capped per run and cached `APIFY_CACHE_MINUTES` so the impersonation module reuses the same runs. Each platform is its own scan component ("Apify Instagram", …). |
| Facebook, Instagram, Threads, TikTok, Pinterest, LinkedIn posts (and YouTube, X when they have no key) | Site-restricted web search through `backend/app/core/search.py` (Brave, SerpAPI or DuckDuckGo) | existing `BRAVE_SEARCH_API_KEY` or `SERPAPI_API_KEY`, or none | These platforms have no public search API for this purpose and forbid scraping (D-10). Always on. |

A source without a key reports **Not configured** on the scan, never "nothing found" (D-31). The scan then
ends `partially_completed`, so nobody mistakes a missing key for a clean result.

### The process, step by step

1. **A scan starts.** Daily at 02:00 UTC, together with all other modules, or by hand.
   The `social_media` runner runs on the **browser worker** queue (`BROWSER_RUNNERS` in
   `backend/app/workers/scan.py`), because it takes screenshots.
2. **Collect items from every source** (`all_items` in `sources.py`), in this order: YouTube, Meta ads,
   Threads, X, Telegram posts, web search. Each source searches the first two brand terms (web search and X:
   the first three). "Brand terms" are the brand's keywords, or its name when it has no keywords. One broken
   source never stops the others; its failure is recorded as a component.
   - **YouTube:** two video searches (one per term, 25 newest videos each, published in the last
     `SOCIAL_MEDIA_LOOKBACK_DAYS`), one channel search for the brand name (15 channels), then details for the
     videos and channels found. A video result only carries the uploader's channel ID, so the module also
     looks up each uploader's **@handle** (`channels.list`, 1 unit for up to 50 uploaders). That handle is
     what lets step 5 recognise the brand's own channels.
   - **Meta ads:** one `ads_archive` search per term (up to 50 ads each), active and inactive ads, shown in
     the countries of `META_AD_COUNTRIES`, delivered since the lookback date.
   - **Threads:** one `keyword_search` per term, most recent posts.
   - **X:** one search, for example `("Example Bank" OR "examplebank") -is:retweet`, 25 posts.
   - **Telegram:** one global search per term, 50 messages each, broadcast channels only; only messages from
     channels with a public username are kept (they need a `t.me/<channel>/<id>` link).
   - **Web search:** up to five queries of 20 results each:
     `(site:instagram.com OR site:facebook.com OR site:threads.net) (terms)`,
     `(site:tiktok.com OR site:pinterest.com OR site:linkedin.com/posts) (terms)`, `site:youtube.com` only
     when there is no YouTube key, `site:x.com OR site:twitter.com` only when there is no X token, and one
     **scam query** on Facebook, Instagram and YouTube with the words
     `(whatsapp OR "customer care" OR helpline OR "kyc" OR refund)`. Each result URL is mapped to a platform
     and a content type (video, post, channel or account) from its shape. **Account** pages on X, Facebook,
     Instagram, LinkedIn and Telegram are dropped here: Chapter 06 already covers those, and this avoids two
     findings for one account. If search is not configured or refused before any query worked, the remaining
     queries are skipped.
3. **Remove duplicates.** Every item gets an **entity key**: `<platform>:<type>:<id or cleaned URL>`, for
   example `youtube:video:abc123` or `instagram:post:https://www.instagram.com/p/xyz`. API items come first,
   so an API item wins over the same item found by web search.
4. **Stop if nothing could be checked.** If no source finished with `ok`, the run records a **fatal**
   component "Social media sources: no source could be checked (add API keys or a search key)" and the scan
   is `failed`. This is never shown as "No threats detected".
5. **Skip official content.** The item is skipped when its link is on an official brand domain, or its
   author handle, author ID or author URL (and, for a channel or account, the item's own URL) matches an
   official handle in the brand's `social_handle` allowlist. For YouTube videos this uses the uploader's
   @handle looked up in step 2, so videos on the brand's own channels are skipped when the handle is listed.
6. **Judge relevance.** Title, text, author name and author handle are checked with `BrandContext.relevance`
   (the D-25 rules: long brand words count alone, short abbreviations need brand context). The thumbnail is
   downloaded through the safe fetcher and compared with the official logo and favicon. An item that neither
   names the brand nor shows the logo is dropped.
7. **Look for scam signs** in the same text: contact details and scam wording (section 5). A Telegram link to
   the brand's own official handle is not counted.
8. **Take a screenshot** of the post, video or ad page with the headless browser (viewport only). At most
   `SOCIAL_MEDIA_MAX_ITEMS` screenshots are taken per brand and scan; later items are still reported, with
   their link, metadata and thumbnail. A failed screenshot is recorded on the "Browser capture (social
   media)" component and the item is still reported.
9. **Build the detection.** Signals, output fields and evidence are put together. Title example:
   "Brand used in YouTube video (fake contact details, official logo, scam wording): Example Bank KYC update
   helpline".
10. **Record it.** `execute_scan` passes it to `record_detection` in `backend/app/core/findings.py` (the SP2
    engine, see Chapter 10). It scores it, stores an **observation** for this scan, stores new evidence, and
    decides whether the alert rule is met.

### Candidate or Finding (D-33)

| Stage | When |
|---|---|
| **Finding** (analysed) | The item came from an official API with full fields, **or** a screenshot was captured, **or** a thumbnail was downloaded |
| **Candidate** (discovered, weak) | A bare web-search hit (title and snippet only) whose page could not be captured |

A Candidate never raises an alert, whatever its score. If a later scan captures the page, it is promoted to
a Finding ("Analysis found evidence") and may then alert.

### Flow diagram

```
 Daily schedule (02:00 UTC) / manual scan   (browser worker queue)
                     |
                     v
 +----------------------------------------------------------------------+
 | Sources (each one is a scan component, D-31)                         |
 |  YouTube Data API   --key? no--> "Not configured" (+ site:youtube.com)|
 |  Meta Ad Library    --key? no--> "Not configured"                    |
 |  Threads API        --key? no--> "Not configured" (web search covers)|
 |  X API              --key? no--> "Not configured" (+ site:x.com)     |
 |  Telegram posts     --keys? no-> "Not configured"                    |
 |  Web search: Instagram/Facebook/Threads, TikTok/Pinterest/LinkedIn,  |
 |              scam-word query (accounts on X/FB/IG/LI/TG dropped)     |
 +-----------------------------------+----------------------------------+
                                     v
            Items, de-duplicated by <platform>:<type>:<id or URL>
                                     |
            no source "ok"? --yes--> fatal component, scan failed
                                     | no
                                     v
        official domain / official handle? --yes--> skip
                                     | no
                                     v
        brand named (D-25) or thumbnail = logo? --no--> skip
                                     | yes
                                     v
        contact details (phone, WhatsApp, Telegram, UPI), scam wording
                                     |
        screenshot of the page (up to SOCIAL_MEDIA_MAX_ITEMS per scan)
                                     |
                                     v
        Detection -> record_detection: score (Low..Critical), observation,
        evidence, Candidate or Finding -> alert if Finding and risk >= "Alert from"
```

## 4. Tools and libraries used

| Tool | What it is | What we use it for | Why this tool (and alternatives rejected) | Where in the code |
|---|---|---|---|---|
| YouTube Data API v3 | Google's official API for YouTube | Recent videos and channels that mention the brand, with description, tags, counts and thumbnail | Official and free up to a daily quota; scraping YouTube pages rejected (D-38) | `backend/app/modules/social_media/sources.py` (`youtube`) |
| Meta Ad Library API | Meta's official public archive of ads (`ads_archive`) | Ads on Facebook, Instagram, Messenger and Audience Network that mention the brand | The only official ad search; paid scrapers rejected (D-38) | `sources.py` (`meta_ads`) |
| Threads API | Meta's official API for Threads (`keyword_search`) | Recent public Threads posts | Official; web search covers Threads when there is no token | `sources.py` (`threads`) |
| X API v2 | The official X (Twitter) API (`tweets/search/recent`) | Recent X posts that mention the brand | Official but paid; used only when a token is set, otherwise web search | `sources.py` (`x_posts`) |
| Telethon | Python client for Telegram's official API | `messages.SearchGlobal`: public channel posts | Telegram's free official search (D-10) | `sources.py` (`telegram_posts`) |
| Web search (Brave, SerpAPI or DuckDuckGo) | Search engines | Site-restricted searches on Facebook, Instagram, Threads, TikTok, Pinterest, LinkedIn (and YouTube, X without keys) | No public search API on these platforms; no login, no scraping (D-10, D-23) | `backend/app/core/search.py` |
| Safe fetcher | The platform's guarded HTTP client | All API calls and thumbnail downloads; keys go in headers, never in logged URLs | Same address rules and rate limits as every module | `backend/app/core/fetch.py` |
| Playwright (Chromium) | Headless browser | Screenshot of the post, video or ad page | Already the platform's browser; runs in the isolated browser worker (D-18) | `backend/app/core/browser.py` |
| Pillow + ImageHash | Perceptual image hashing | Thumbnail or channel picture vs official logo and favicon | Same matcher as Chapters 06 and 08 | `backend/app/core/imaging.py`, `backend/app/modules/common.py` (`image_match`) |
| Python regular expressions | Text patterns | Phone numbers, WhatsApp and Telegram links, UPI IDs, scam phrases | Fast, offline, easy to test; no external service needed | `backend/app/modules/social_media/analysis.py` |
| boto3 + S3-compatible storage | Object storage | Screenshots, thumbnails, metadata | RustFS by default (D-22) | `backend/app/core/evidence.py` |

## 5. How each tool works internally, explained simply

### YouTube Data API and its quota

You send a request with your **API key** (in the `X-goog-api-key` header). YouTube does not count requests;
it counts **quota units**. A search (`search.list`) costs **100 units**. A details call (`videos.list`,
`channels.list`) costs **1 unit**, for up to 50 IDs at once. The free daily allowance is **10,000 units**
per Google Cloud project, reset at midnight Pacific time.

One brand scan uses: 2 video searches (200) + 1 channel search (100) + 1 video details call (1, at most 50
videos) + 1 uploader handle lookup (1) + 1 channel details call (1) = **about 303 units**. So one key covers about **33 brand scans a day**.
When the quota runs out, YouTube answers HTTP 403 and the "YouTube API" component shows `failed` with
Google's message.

### Scam-shaped YouTube searches (added 2026-10-10)

Fraud videos are rarely the newest videos about a brand, so besides the newest videos for the first two keywords the
module also searches `"<brand> customer care number"`, `"<brand> helpline number"`, `"<brand> kyc update"`,
`"<brand> loan fraud"` and `"<brand> refund"` (setting `SOCIAL_MEDIA_SCAM_QUERIES`), most relevant first, over the last
year (`SOCIAL_MEDIA_SCAM_LOOKBACK_DAYS=365`), 50 results each, Indian region. Each card shows **Found By Search**.
In the live test for the brand Navi this raised the relevant videos from 26 to 171. It costs about 750 of the 10,000
free daily quota units per brand per scan.

To keep alerts precise: only **phone numbers, WhatsApp links and UPI IDs** count as fake contact details (Telegram
links are usually the creator's own channel and are shown as "Other Links"), and only **strong** scam wording scores
("customer care", "helpline", "KYC update", "account blocked", "guaranteed returns", "processing fee", ...). Words
common in ordinary tutorials ("refund", "cashback", "loan") are shown but do not raise the score. A short brand name
such as "Navi" counts as relevant when the same title/description has fake contact details or strong scam wording.

### Meta Ad Library API

The Ad Library is Meta's public archive of ads. The API is called at
`https://graph.facebook.com/v23.0/ads_archive` with the token in the `Authorization` header, the search
words, `ad_reached_countries` (from `META_AD_COUNTRIES`), `ad_type=ALL`, `ad_active_status=ALL` and the
earliest delivery date. Each ad returns its page name and ID, ad text, link titles and captions, start and
stop dates, and where it was shown (Facebook, Instagram, ...). The module links each ad to its public page
`https://www.facebook.com/ads/library/?id=<ad id>` and screenshots that page.

### Facebook Pages API (Graph API)

With `META_APP_ID` and `META_APP_SECRET` the module builds an **app access token** (`APP_ID|APP_SECRET`, sent
only in the `Authorization` header, never in a URL). It then:

1. searches Facebook Pages by the brand name and first two keywords (`GET /pages/search?q=...`, 25 per search);
2. reads up to 15 pages: name, @username, about, description, category, followers, website, **listed phone**
   and e-mails, verification status and profile picture;
3. reads each page's public posts from the look-back window (up to 10 per page).

Each page becomes an `account` item and each post a `post` item for platform Facebook, and both go through the
same checks (relevance, official allowlist, fake contacts, scam wording, logo match on the profile picture,
screenshot). A fake page that lists a "customer care" phone number is caught by the contact check.

**Approval needed.** Searching other people's pages requires Meta's **Page Public Content Access** feature
on your app (developers.facebook.com > your app > App Review > Permissions and Features), which needs Business
Verification. Without it Meta answers with an error such as "(#10) This endpoint requires the 'Page Public
Content Access' feature"; the scan records exactly that message as a failed component and the Integrations
page shows it. Nothing is invented. `META_GRAPH_TOKEN` can replace the app token (for example a long-lived
user token).

### Threads API

`https://graph.threads.net/v1.0/keyword_search?q=<term>&search_type=RECENT` returns recent public posts with
text, media type, permalink, time, username and a thumbnail. A video post becomes content type `video`.

### X API v2

`https://api.x.com/2/tweets/search/recent` searches posts from roughly the last seven days (that is what
"recent" means in the X API). The module asks for the author's name and username, the first attached media
(for a thumbnail) and the public counts (likes, reposts, replies, views).

### Telegram global post search

With the same monitoring account as Chapter 06 (the `TELEGRAM_*` keys), Telethon sends
`messages.SearchGlobal` with `broadcasts_only=True`. This is the search a Telegram user runs over public
channels. Each message from a channel with a public username becomes a post with the link
`https://t.me/<channel>/<message id>` and its view count.

### Contact detail detection

`contact_details()` in `analysis.py` looks for four kinds of contact in the title, text, author name and
handle:

| Kind | What is matched | Examples |
|---|---|---|
| Phone | Indian mobile numbers (10 digits starting 6-9, optional `+91`), toll-free numbers starting 1800 or 1850, and international numbers written with a `+` | `+91 98765 43210`, `1800 123 4567`, `+44 20 7946 0958` |
| WhatsApp | `wa.me/<number>`, `api.whatsapp.com/send?phone=<number>`, `chat.whatsapp.com/<group>` | `wa.me/919876543210` |
| Telegram | `t.me/<name>` or `telegram.me/<name>` (4+ characters) | `t.me/examplebankhelp` |
| UPI ID | `<name>@<bank or app handle>` for about 40 known UPI handles, such as `ybl`, `ibl`, `axl`, `paytm`, `upi`, `okaxis`, `okhdfcbank`, `okicici`, `oksbi`, `apl`, `airtel`, `jio`, `sbi`, `icici`, `hdfcbank`, `axisbank`, `kotak`, `freecharge` | `exb.refund.desk@ybl` |

Phone numbers are reduced to digits (a leading 91 is removed from 12-digit Indian numbers) and kept when 8
to 13 digits long. At most ten of each kind are kept. A Telegram link to one of the brand's official handles
is removed (`drop_official`), because the brand pointing to itself is not a scam.

### Scam wording detection

`scam_phrases()` lowercases the text and looks for each phrase as a whole word or phrase. The list
(`SCAM_PHRASES`) has about 60 entries in these groups:

| Group | Phrases (selection) |
|---|---|
| Fake support | customer care, customer support, helpline, toll free, call now, whatsapp us, dm us |
| Account scare | kyc, kyc update, account blocked, account suspended, verify your account |
| Money back | refund, cashback, claim your |
| Investment | guaranteed returns, double your money, fixed returns, high returns, daily profit, investment plan, invest now, chit scheme |
| Loans and fees | loan approval, instant loan, pre-approved loan, no documents, processing fee, registration fee |
| Prizes | lottery, lucky draw, you have won, free gift |
| Jobs and agents | work from home, earn daily, job offer, hiring now, official agent, authorised agent, franchise, dealership |

### Platform and content type from a URL

For web-search results, `platform_of()` reads the host (`youtube.com`/`youtu.be`, `instagram.com`,
`facebook.com`/`fb.watch`, `x.com`/`twitter.com`, `threads.net`, `tiktok.com`, `linkedin.com`, `t.me`,
`pinterest.*`/`pin.it`) and `content_type_of()` reads the path: for example `/watch` or `/shorts` on YouTube
is a video, `/reel/` on Instagram is a video and `/p/` a post, `/status/` on X is a post, `/video/` on TikTok
is a video, `/pin/` on Pinterest is a post. Anything else is an account or channel page.

## 6. Code map

| File | Responsibility |
|---|---|
| `backend/app/modules/social_media/module.py` | `SocialMediaModule`: run, official check, relevance, scam checks, screenshot, signals, output fields |
| `backend/app/modules/social_media/sources.py` | `SocialItem`; one function per source (`youtube`, `meta_ads`, `threads`, `x_posts`, `telegram_posts`, `web_search`); `all_items` |
| `backend/app/modules/social_media/analysis.py` | `contact_details`, `scam_phrases`, `drop_official`, `platform_of`, `content_type_of` (pure functions, no network) |
| `backend/app/modules/registry.py` | `OUTPUT_FIELDS[social_media]`, label "Social Media Brand Misuse", runner `social_media` |
| `backend/app/workers/scan.py` | `BROWSER_RUNNERS` puts `social_media` on the browser queue; `execute_scan` calls `record_detection` |
| `backend/app/core/findings.py` | `record_detection`: score, observation, evidence, stage, alert rule (SP2) |
| `backend/app/core/scoring.py` | Points (`brand_in_content`, `scam_contact_details`, `scam_language`, `paid_ad`) and the Low-Critical range |
| `backend/app/core/integrations.py` | Integrations page entries: YouTube Data API, Meta Ad Library API, Threads keyword search API, X API, Telegram post search |
| `backend/app/config.py` | `youtube_api_key`, `meta_ad_library_token`, `meta_ad_countries`, `threads_access_token`, `x_bearer_token`, `social_media_lookback_days`, `social_media_max_items` |
| `backend/app/core/allowlist.py` | `social_handle` turns official profile URLs into handles |

Key functions in call order:

1. `execute_scan` -> `get_runner("social_media")` -> `SocialMediaModule()`.
2. `SocialMediaModule.run` -> `sources.all_items` -> `youtube`, `meta_ads`, `threads`, `x_posts`,
   `telegram_posts`, `web_search` -> de-duplicate by `SocialItem.key`.
3. For each item: `SocialMediaModule.analyse` -> `_official` -> `ctx.relevance` -> `image_match` ->
   `contact_details` -> `drop_official` -> `scam_phrases` -> `capture` -> `Signals` -> `Detection`.
4. `record_detection` -> `score(signals, ModuleName.social_media)` -> observation, evidence, alert decision.

## 7. Signals collected and how they become the risk score

| Signal (rule) | When this module sets it | Points |
|---|---|---|
| `brand_in_content` | The brand is named in the title, text, author or handle (D-25 relevance, or the exact brand word in the author or title) | +20 |
| `social_image_match` | Thumbnail or channel picture matches the official logo or favicon at or above `LOGO_MATCH_THRESHOLD` (85) | +20 |
| `scam_contact_details` | At least one phone number, WhatsApp link, Telegram link or UPI ID (after removing the brand's own Telegram handles) | +30 |
| `scam_language` | At least one scam phrase | +20 |
| `paid_ad` | The item is an ad (Meta Ad Library) | +10 |
| `typo_similarity_gt_80` | Channels and accounts only: the name is more than 80 similar to a brand label | +25 |

Levels are the usual ones (Chapter 02): Low 0-29, Medium 30-59, High 60-79, Critical 80-100. This module may
use the whole range, Low to Critical, and the total is capped at 100.

**Criticality tiers.** The points only order items; the tier decides the level (`social_tier()` in
`backend/app/core/scoring.py`, changed on 2026-10-15 by D-45):

| Tier | When |
|---|---|
| Critical | Contact details (phone, WhatsApp, Telegram, UPI) **together with** a customer-care / helpline claim or scam wording: the number itself is the evidence |
| High | A customer-care / helpline claim **without** a number in the text (the number is usually inside the video: check it), wrong-details scam wording (KYC update, account blocked, guaranteed returns), or brand abuse with the logo or a look-alike name |
| Medium | Contact details next to the brand name **without** any support or scam wording, brand abuse (referral bait, cashback lure, unofficial APK), logo use, a paid ad, a look-alike account name |
| Low | Informative content (how-to, news, review) |

Before D-45 any contact detail or any helpline claim was Critical. In the first Navi scan that made 101
YouTube videos Critical, including a jeweller in "Navi Mumbai" with their own WhatsApp number and news about
"Navi Pillay". A short brand name (D-25) next to a phone number is no longer brand context on its own; it needs
scam wording too. `python -m scripts.rescore_social` applies the current rules to stored findings and sets
items that no longer match to Ignored, with a note on their timeline.

A **brand mention alone** scores 20, which is **Low**. It is recorded (as a Candidate or a Finding) but does
not raise an alert at the default "Alert from" level of Medium. Mention plus logo, contact details or scam
wording reaches Medium or more and alerts.

### Worked examples

The YouTube video from the story (API item, so a Finding):

| Check | Result | Points |
|---|---|---|
| Brand named ("Example Bank" in title and description) | yes | +20 |
| Thumbnail matches the logo | 92 >= 85 | +20 |
| Contact details | `whatsapp: wa.me/919876543210`, `upi: exb.refund.desk@ybl` | +30 |
| Scam wording | customer care, kyc, call now, refund, account blocked | +20 |
| Total | 90 | **90, Critical** -> alert |

A Meta ad from the page "EB Instant Loans": "Example Bank pre-approved loan, no documents, apply now":

| Check | Result | Points |
|---|---|---|
| Brand named | yes | +20 |
| Scam wording | pre-approved loan, no documents | +20 |
| Paid ad | yes | +10 |
| Total | 50 | **50, Medium** -> alert at the default level |

An Instagram post found by web search, "Opened my Example Bank account today", page not captured
(Instagram showed a login wall and the browser timed out):

| Check | Result | Points |
|---|---|---|
| Brand named | yes | +20 |
| Anything else | no | 0 |
| Total | 20 | **20, Low**, stage **Candidate** -> no alert; visible on the Findings page |

## 8. Output fields shown to analysts

From `OUTPUT_FIELDS[ModuleName.social_media]` in `backend/app/modules/registry.py`:

| Field | Meaning |
|---|---|
| Platform | YouTube, Facebook, Instagram, X, Threads, Meta Ads, Pinterest, TikTok, LinkedIn or Telegram |
| Content Type | Video, Post, Ad, Channel or Account |
| Title | Video or ad title, or the start of the post text |
| Author | Channel, page, account or channel name |
| Author URL | Link to the author |
| URL | Link to the item itself ("Open on the platform") |
| Published | Publication or ad start time, when known |
| Risk Level | Low, Medium, High or Critical |
| Views, Likes, Comments | Counts, when the source gives them |
| Brand Terms | Brand words found |
| Logo Match | True when the thumbnail matches an official image |
| Scam Contacts | Each contact found, for example `whatsapp: wa.me/919876543210`, `upi: exb.refund.desk@ybl` |
| Scam Phrases | Scam words found |
| Text Excerpt | The first 500 characters of the text |
| Discovery Source | "YouTube Data API", "Meta Ad Library API", "Threads API", "X API", "Telegram API" or "web search (<provider>)" |

Extra detail fields also stored: `Logo Match Score`, `Thumbnail URL`, `Screenshot` (true or false), and
source-specific counts such as `Subscribers`, `Videos` (YouTube channels), `Reposts` (X), `Shown On` and
`Stopped` (Meta ads).

### Where analysts see them: the Social Media page

The side menu item **Social Media** (`/social`, `frontend/src/app/(app)/social/page.tsx`) shows these findings,
together with the impersonation accounts of Chapter 06, as a grid of cards (Chapter 10, section 8):

- **Platform tabs:** All, YouTube, Facebook, Instagram, X, Threads, Meta Ads, Pinterest, TikTok, LinkedIn,
  Telegram.
- **Filters:** type (Videos, Posts, Ads, Channels and accounts), Stage, Decision, Risk, a search box ("Search
  title, author, phone number...", useful for finding every post that pushes one WhatsApp number or UPI ID),
  and sort.
- **Each card:** the stored screenshot (a placeholder when none was captured; remote thumbnails are
  deliberately not loaded), badges for content type, risk, stage and decision, title, author, date, views and
  likes, **"Fake contact details"** chips, a "Logo used" chip, the scam wording found, an **"Open on
  <platform>"** button and a **Details** link to the finding.
- Impersonation accounts have no Content Type, so they are hidden as soon as a type is chosen.

On the Details page (and the alert detail page), the **Brand misuse** panel (`SocialMisusePanel` in
`frontend/src/components/finding-detail.tsx`) lists the platform and content type, "Fake contact details",
"Scam wording" and "Official logo used" (or "None found."), the text excerpt and the "Open on <platform>" link.
The same findings also appear on the Findings page and, when alerted, in the alert queue.

## 9. Evidence stored

| Evidence | Kind | When |
|---|---|---|
| Everything the source returned: platform, type, URL, title, text (first 4,000 characters), author, handle, author URL, published time, counts, discovery source, and YouTube tags | `metadata` | Always |
| The thumbnail or channel picture, with its URL and logo match score | `image` | When a thumbnail URL is known and the download worked |
| A viewport screenshot of the item's page, with final URL, page title and HTTP status | `screenshot` | When the page could be opened, up to `SOCIAL_MEDIA_MAX_ITEMS` per brand and scan |

Videos are **never downloaded** (SMM-06): the evidence for a video is its link, thumbnail and screenshot.
Evidence belongs to the finding and to the observation (scan) that captured it; identical evidence is not
stored again on later scans.

On a re-scan, the only comparable fact this module reports is `logo_match`. If a thumbnail starts matching
the logo, or the risk level rises (for example scam contacts are added to the description), that is a
**meaningful change**: it is written on the timeline and raises a new alert, even after a decision such as
False Positive (Chapter 10).

## 10. Settings and configuration

### Where the keys go

All keys are environment variables in **`deploy/.env`**. If you do not have that file yet, copy
`deploy/.env.example` to `deploy/.env` first. Every social media key is optional: an empty key only means
that source shows "Not configured" on the scan and on the Integrations page.

| Variable | Default | Effect |
|---|---|---|
| `YOUTUBE_API_KEY` | empty | YouTube Data API v3 key. Without it, YouTube is searched through web search. |
| `META_APP_ID`, `META_APP_SECRET` | empty | Facebook app ID and secret (app > Settings > Basic). Enable Facebook Pages search; the app needs Page Public Content Access |
| `META_GRAPH_TOKEN` | empty | Optional token used instead of the app token for Facebook Pages search |
| `META_AD_LIBRARY_TOKEN` | empty | Meta Ad Library access token. Without it, no ads are searched. |
| `META_AD_COUNTRIES` | `["IN"]` | Countries the ads must have reached, as a JSON list of two-letter codes, for example `["IN","GB"]` |
| `THREADS_ACCESS_TOKEN` | empty | Threads API token with `threads_keyword_search`. Without it, Threads is covered by web search only. |
| `X_BEARER_TOKEN` | empty | X API v2 bearer token (paid). Without it, X is searched through web search. |
| `SOCIAL_MEDIA_LOOKBACK_DAYS` | `30` | Only YouTube videos and Meta ads from the last N days are searched |
| `SOCIAL_MEDIA_MAX_ITEMS` | `60` | Most screenshots taken per brand and scan |
| `TELEGRAM_API_ID`, `TELEGRAM_API_HASH`, `TELEGRAM_SESSION` | empty | Shared with Chapter 06; enables Telegram post search |
| `BRAVE_SEARCH_API_KEY`, `SERPAPI_API_KEY`, `FREE_SEARCH_FALLBACK` | empty, empty, `true` | Web search provider (Chapter 06 and Chapter 11) |
| `LOGO_MATCH_THRESHOLD` | `85` | Thumbnail match score that counts as the logo |

Example lines in `deploy/.env`:

```
YOUTUBE_API_KEY=AIzaSy...your-key...
META_APP_ID=1234567890
META_APP_SECRET=abcdef...your-secret...
META_AD_LIBRARY_TOKEN=EAAG...your-token...
META_AD_COUNTRIES=["IN"]
THREADS_ACCESS_TOKEN=THAA...your-token...
X_BEARER_TOKEN=AAAAAAAA...your-token...
SOCIAL_MEDIA_LOOKBACK_DAYS=30
SOCIAL_MEDIA_MAX_ITEMS=60
```

After changing `deploy/.env`, restart the containers so the workers read the new values (Chapter 12):

```
docker compose -f deploy/docker-compose.yml --profile app up -d
```

Then open the **Integrations** page. Each source should now show as configured; its last result appears
after the next scan. Start a manual scan of one brand to check.

Brand settings that matter here: keywords (the search words), official domains, official social handles in
the `social_handle` allowlist (add the brand's own YouTube channel handle, Telegram channel and so on, so
their content is skipped), and the logo and favicon (for thumbnail matching).

**Add every official YouTube channel handle to the allowlist.** The module looks up the @handle of each video's
uploader and skips the video when that handle is on the brand's `social_handle` allowlist. If the brand's own
channels are missing there, its own videos (which name the brand, show the logo and list the real helpline)
will be reported as misuse. On the brand page, under Allowlists > Social handles, add each official channel
handle without the `@`, for example `kodachadrichitsofficial` or `chitkart`, or paste the channel URL
(`https://www.youtube.com/@chitkart`); it is turned into the handle. The channel ID (starting `UC...`) also works.

### How to get each key, step by step

The consoles of Google, Meta and X change their menus often. The steps below were right when this chapter
was written; if a button has moved, look for the same words nearby.

**YouTube Data API key (`YOUTUBE_API_KEY`) - free**

1. Go to `https://console.cloud.google.com` and sign in with a Google account (a company account is best).
2. At the top, open the project picker and choose **New project**. Name it, for example,
   "brand-intel-youtube", and create it. Make sure it is selected.
3. Open **APIs & Services > Library**, search for **YouTube Data API v3**, open it and click **Enable**.
4. Open **APIs & Services > Credentials**, click **Create credentials > API key**. A key starting with
   `AIza` is shown. Copy it.
5. Click **Edit API key** (or the key name). Under **API restrictions** choose **Restrict key** and tick only
   **YouTube Data API v3**. Save. This way a leaked key cannot be used for other Google services.
6. Paste the key into `deploy/.env` as `YOUTUBE_API_KEY=...` and restart the containers.
7. The free quota is 10,000 units a day (about 33 brand scans). You can see usage under **APIs & Services >
   YouTube Data API v3 > Quotas**.

**Meta Ad Library token (`META_AD_LIBRARY_TOKEN`) - free, needs identity confirmation**

1. Log in to Facebook with a personal account that will own the access (Meta requires a real person).
2. Go to `https://www.facebook.com/ads/library/api` and follow **Confirm your identity**. Meta asks for an
   identity document and sometimes a location check. This can take from a few minutes to several days.
3. Go to `https://developers.facebook.com`, register as a developer if asked, and choose **My Apps > Create
   app**. Pick a business-type app (or "Other"), give it a name and create it.
4. Open the **Graph API Explorer** (`https://developers.facebook.com/tools/explorer`), select your app, and
   click **Generate Access Token**. Approve the login dialog. This gives a short-lived **user access token**
   (valid about one hour).
5. Turn it into a **long-lived token** (valid about 60 days): open the **Access Token Debugger**
   (`https://developers.facebook.com/tools/debug/accesstoken`), paste the token, and click **Extend Access
   Token**. Copy the new token.
6. Paste it into `deploy/.env` as `META_AD_LIBRARY_TOKEN=...`. Set `META_AD_COUNTRIES`, for example
   `["IN"]`. Restart the containers.
7. **The token expires after about 60 days.** Put a reminder in the calendar to repeat steps 4 to 6. When it
   has expired, the "Meta Ad Library" component shows `failed` with Meta's error message.

**Threads token (`THREADS_ACCESS_TOKEN`) - free, needs Meta app review for public posts**

1. Go to `https://developers.facebook.com`, **My Apps > Create app**, and choose the **Access the Threads
   API** use case.
2. In the app's Threads settings, add the permissions **`threads_basic`** and
   **`threads_keyword_search`**.
3. Add your own Threads account as a tester (App roles > Roles > Threads testers) and accept the invitation
   in the Threads app (Settings > Account > Website permissions).
4. Generate a user access token for that account (with the Graph API Explorer for Threads or the app's
   "Generate token" button), then exchange it for a **long-lived token** (valid about 60 days) as described
   in Meta's Threads documentation ("long-lived tokens").
5. **App review:** until Meta approves `threads_keyword_search` for your app through **App Review**, keyword
   search only returns posts of your own (tester) accounts, not public posts. Submit the app for review, with
   a short description of brand-protection monitoring and a screencast if asked.
6. Paste the token into `deploy/.env` as `THREADS_ACCESS_TOKEN=...` and restart. Renew it before the 60 days
   run out.

**X bearer token (`X_BEARER_TOKEN`) - paid**

1. Go to `https://developer.x.com` and sign in with an X account.
2. Sign up for developer access and choose a **paid** option (pay-per-use credits or a monthly plan). The
   free tier does not allow searching posts. Add a payment method and buy credits if required.
3. In the **Developer Portal**, create a **Project** and an **App** inside it.
4. Open the app's **Keys and tokens** tab and generate the **Bearer Token**. Copy it immediately; it is
   shown only once (you can regenerate it later).
5. Paste it into `deploy/.env` as `X_BEARER_TOKEN=...` and restart. Watch the usage page: every search uses
   paid credits.

**Telegram keys (`TELEGRAM_API_ID`, `TELEGRAM_API_HASH`, `TELEGRAM_SESSION`) - free**

The same keys as Chapter 06, section 10: get the API ID and hash at `https://my.telegram.org` (API
development tools), then run `python -m scripts.telegram_login` once to print the session string. With these
keys, both the impersonation module and this module's post search work.

**Web search key (`BRAVE_SEARCH_API_KEY`) - free tier**

Recommended for reliable web search: sign up at the Brave Search API site, choose the free plan, and copy the
key (Chapter 11). Without any key, the free DuckDuckGo fallback runs a few slow searches per scan.

## 11. How it is tested

| Test | File | What it proves | Markers |
|---|---|---|---|
| `test_contact_details_and_scam_wording` | `backend/tests/modules/test_social_media.py` | Phone (`+91 98765 43210` -> `9876543210`), WhatsApp, UPI and Telegram are found; "customer care" is found; Instagram reel URL -> Instagram video; YouTube `@handle` URL -> channel | SMM-03 |
| `test_scam_video_is_flagged_with_screenshot_and_alert_level` | same | A YouTube API video with KYC helpline wording and a WhatsApp link becomes one Finding keyed `youtube:video:abc123`, with scam contacts and a screenshot, scored High or Critical with `brand_in_content`, `scam_contact_details` and `scam_language` | SMM-01, SMM-02, SMM-03, SMM-06 |
| `test_official_irrelevant_and_mention_only` | same | The brand's official channel and an unrelated video are skipped; a web-search post that only mentions the brand, with a failed screenshot, is a Candidate scored Low | SMM-04 |
| `test_no_source_checked_fails_the_run` | same | When no source could be checked, the run records a fatal component (never "nothing found") | SMM-05, D-31 |

The tests use a made-up brand and fake sources and a fake screenshot function, so they need no keys and no
network.

## 12. Known limitations and missing capabilities

| Limitation | Effect |
|---|---|
| **Meta Ad Library returns commercial ads only for the EU and UK** | Meta's API returns ordinary (commercial) ads only when they were shown in the European Union or the United Kingdom. For other countries, including India, it returns only political and issue ads. With `META_AD_COUNTRIES=["IN"]`, most scam ads aimed at Indian customers are invisible. This is stated on the Integrations page. Ads seen in the EU/UK are still found. |
| **Threads needs app review** | Without Meta's approval of `threads_keyword_search`, the Threads API only searches your own accounts' posts. Web search still covers public Threads posts, with less detail. |
| **X is paid** | Without a paid `X_BEARER_TOKEN`, X posts come only from web search (title and snippet). The X recent search covers about the last seven days. |
| **YouTube quota** | 100 units per search and 10,000 units a day: about 303 units per brand scan, so about 33 brand scans a day per key. More brands or more scans need a quota increase from Google or a second project. |
| **Login walls on screenshots** | Instagram and Facebook (and often LinkedIn and Threads) show a login prompt instead of the post. The screenshot then shows the login wall, or capture fails; the item is still reported with its link. A web-search hit without a capture stays a Candidate. |
| **Web search sees snippets only** | For Facebook, Instagram, TikTok, Pinterest and LinkedIn, only the result title and snippet are analysed, not the full post or comments. Contact details hidden in an image or a comment are missed. |
| No official API for TikTok, LinkedIn, Pinterest | They have no public search API for commercial monitoring, so only web search covers them. |
| No transcripts, no image text | Spoken words in videos and text inside images or thumbnails are not read; only titles, descriptions and post text. |
| Few search terms | Each source searches only the first two (web search and X: three) brand terms. Product names are not searched. |
| Lookback window | YouTube videos and Meta ads older than `SOCIAL_MEDIA_LOOKBACK_DAYS` (30) are not searched. The YouTube channel search, Threads, X and Telegram have no date filter of their own beyond what the API returns. |
| Screenshot limit | Only the first `SOCIAL_MEDIA_MAX_ITEMS` (60) items per scan get a screenshot. |
| Accounts are left to Chapter 06 | Account pages on X, Facebook, Instagram, LinkedIn and Telegram found by web search are dropped here to avoid two findings for one account. YouTube channels, TikTok, Pinterest and Threads accounts are kept. |
| Official phone numbers are not known | Only official Telegram handles are removed from contact details. A post that repeats the brand's real helpline number is still flagged; the analyst marks it Legitimate. |
| No allowlist from a decision | "Legitimate" on a social media finding cannot add it to the allowlist automatically (no allowlist kind for this module). An admin adds the official handle to the `social_handle` allowlist by hand. |
| Cards show stored screenshots only | The Social Media page never loads remote thumbnails from the platforms in the analyst's browser. An item without a captured screenshot (login wall, failed capture, or beyond `SOCIAL_MEDIA_MAX_ITEMS`) shows a placeholder card; the thumbnail, when downloaded, is still in the evidence on the Details page. |
| Impersonation accounts and the type filter | The Social Media page also lists `social` impersonation accounts (Chapter 06), but they have no Content Type, so they disappear once a content type is chosen. |

## 13. End-to-end example

1. An admin creates a Google Cloud project, enables YouTube Data API v3, creates a key restricted to it and
   puts it in `deploy/.env` as `YOUTUBE_API_KEY`. No Meta, Threads or X keys yet. They restart the
   containers. The Integrations page shows "YouTube Data API: configured".
2. At 02:00 UTC the scheduled scan queues the `social_media` runner for Example Bank on the browser worker.
3. Sources run. YouTube: two video searches ("Example Bank", "examplebank") and one channel search, about 303
   quota units. Meta Ad Library, Threads and X show **Not configured**; Telegram post search runs with the
   existing Telegram keys. Web search runs the Instagram/Facebook/Threads, TikTok/Pinterest/LinkedIn, X (no X
   token) and scam-word queries. The scan will end `partially_completed`, because some sources were not
   configured.
4. The scam video `youtube:video:abc123` is found. It is not from an official channel, it names the brand,
   its thumbnail matches the logo, and its description has a WhatsApp link, a UPI ID and scam words.
5. A screenshot of the video page is taken. Evidence: metadata, thumbnail, screenshot.
6. `record_detection` scores it **90, Critical**. It came from the API, so it is a **Finding**. Critical is
   above the brand's "Alert from" level (Medium), so an **alert** is raised with trigger `first_crossing` and
   reason "First reached Critical (90)".
7. In the same scan, an Instagram post "Opened my Example Bank account today" is found by web search; the
   screenshot shows a login wall and times out. It is a **Candidate**, Low, with no alert. It is listed on the
   Findings page under stage Candidate.
8. The analyst opens the alert, sees the WhatsApp number and UPI ID in **Scam Contacts**, the screenshot and
   the "Open on YouTube" link, marks it **Confirmed Threat**, and reports the video to YouTube and the UPI ID
   to the payment provider.
9. The next day's scan sees the same video again: one new observation, no new alert (nothing meaningful
   changed). If the video is taken down, it is simply no longer seen.

## Key takeaways

- This module finds brand misuse in **content**: posts, videos, ads and channels; Chapter 06 covers fake
  **accounts**.
- Official APIs are used when a key is set (YouTube Data API, Meta Ad Library, Threads, X, Telegram); a
  site-restricted web search always runs and covers Facebook, Instagram, Threads, TikTok, Pinterest and
  LinkedIn. No logins, no paid scrapers, no video downloads (D-38).
- Fake contact details (phone, WhatsApp, Telegram, UPI) score +30, scam wording +20, logo +20, brand mention
  +20, paid ad +10. A mention alone is Low and does not alert at the default Medium level.
- API items and captured pages are Findings; uncaptured search hits are Candidates and never alert.
- Keys go in `deploy/.env`; restart the containers afterwards. Meta and Threads tokens expire after about
  60 days. A missing key always shows as "Not configured", never as "nothing found".
- Biggest limits: Meta Ad Library shows commercial ads only for the EU/UK, Threads needs app review, X is
  paid, YouTube allows about 33 brand scans a day per key, and Instagram/Facebook screenshots often show a
  login wall.
