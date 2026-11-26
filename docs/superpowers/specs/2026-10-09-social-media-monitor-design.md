# Social media brand-misuse monitor

**Date:** 2026-10-09 · **Status:** approved in chat by the owner ("start the social media part", speed over ceremony)
· **Builds on:** SP2 finding model · **Owner instruction:** no git commits.

## Goal

One **Social Media** section in the dashboard that shows, with a screenshot and a link, every place the brand name or
logo is used without permission: fake accounts/channels, posts and videos, ads, and posts advertising fake contact
details (WhatsApp / phone / UPI / Telegram) — across YouTube, Facebook, Instagram, X, Threads, Meta ads, Pinterest,
TikTok, LinkedIn and Telegram.

Owner decisions (2026-10-09): catch accounts + posts/videos + ads + scam contacts; official APIs where keys are given,
everything else via web search + a Playwright screenshot of the public page (no paid scrapers); video evidence = link
+ thumbnail + screenshot (no download).

## Sources (new module `social_media`, runner `social_media`, browser queue)

| Platform | Source | Key (deploy/.env) | Notes |
|---|---|---|---|
| YouTube | YouTube Data API v3: `search.list` (videos + channels, newest first, last N days) then `videos.list`/`channels.list` for details | `YOUTUBE_API_KEY` | 100 units per search, 1 per details call; 10,000 units/day free |
| Meta ads (Facebook/Instagram) | Meta Ad Library API `ads_archive` | `META_AD_LIBRARY_TOKEN`, `META_AD_COUNTRIES` (default `IN`) | Commercial ads only when delivered to the EU/UK; political/issue ads worldwide — stated on the Integrations page |
| Threads | Threads API `keyword_search` (RECENT) | `THREADS_ACCESS_TOKEN` | Needs `threads_keyword_search` approval for public posts |
| X | X API v2 `tweets/search/recent` | `X_BEARER_TOKEN` | Paid (pay-per-use) |
| Telegram | Telethon `messages.SearchGlobal` (public channel posts) | existing `TELEGRAM_*` | Accounts stay in the existing `social` module |
| Facebook, Instagram, TikTok, Pinterest, LinkedIn, Threads, X, YouTube | Site-restricted web search (existing `core/search.py`) | existing search keys | Always on; covers platforms without a key |

A source without a key reports **not configured** (never "nothing found", D-31).

## Analysis per item

1. **Relevant?** brand terms in title/text/author (shared relevance check, D-25) or thumbnail matches the logo.
2. **Official?** author handle / channel id / page in the brand's `social_handle` allowlist, or link on an official
   domain → skipped.
3. **Misuse signals** (new scoring rules, module `social_media`, levels Low…Critical):
   - `brand_in_content` 20 — brand name used in the post/video/ad/account name or text
   - `social_image_match` 20 — thumbnail/avatar matches the official logo (existing rule)
   - `scam_contact_details` 30 — phone numbers, WhatsApp links (`wa.me`, `api.whatsapp.com`, `chat.whatsapp.com`),
     Telegram links or UPI IDs published next to the brand by a non-official account
   - `scam_language` 20 — "customer care", "helpline", "KYC", "refund", "guaranteed returns", "double your money",
     "investment plan", "loan approval", "work from home" …
   - `paid_ad` 10 — it is a paid ad
   A brand mention alone is Low (a Finding, not an alert at the default Medium level); mention + logo, contact
   details or scam language reaches Medium+ and alerts.
4. **Evidence:** metadata (all API fields), thumbnail image, Playwright screenshot of the post/video/ad page.
5. **Stage (D-33):** API items and items with a captured screenshot/thumbnail are Findings; a bare search hit that
   could not be captured is a Candidate.

Entity key: `<platform>:<type>:<id or normalised URL>`; types: `video`, `channel`, `post`, `ad`, `account`.

## API / UI

- `GET /findings` gains `platform` and `content_type` filters (from details).
- New **Social Media** page: platform tabs (All, YouTube, Facebook, Instagram, X, Threads, Meta Ads, Pinterest,
  TikTok, LinkedIn, Telegram), type filter, card grid with screenshot/thumbnail, title, author, date, views, "why"
  (scam contacts / phrases / logo), decision badge, "Open on <platform>" link, card → finding detail. Includes the
  existing `social` (impersonation account) findings.
- Integrations page lists YouTube, Meta Ad Library, Threads, X with configured/last-run state.

## Not done (by decision)

Video download, paid scrapers (Bright Data/Apify), TikTok/LinkedIn/Pinterest official APIs (no public search for
commercial use), transcript analysis.
