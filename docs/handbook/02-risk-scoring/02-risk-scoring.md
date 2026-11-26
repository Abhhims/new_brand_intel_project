# Chapter 02 - Risk Scoring

In this chapter:
- How every finding gets a number from 0 to 100 and a level: Low, Medium, High or Critical, and when that
  level turns a finding into an alert (the brand's "Alert from" level, SP2).
- Every scoring rule, what it means in plain English, and why it matters.
- The adjustments made after adding points: the 100 cap, module ranges and the D-29 brand-evidence caps.
- How email alerts are scored, including the "two sources must agree" rule, and the separate Email Risk field.
- Where the explanation is stored, how the dashboard shows it, worked examples, and honest limitations.

## 1. Why one scoring model

Analysts see alerts from twelve modules: domains, apps, social accounts, social media posts and ads, documents, logos and emails. To
decide what to look at first, they need one scale that means the same thing everywhere. The requirements
ask for "a consistent risk scoring model" (OUT-02).

So the platform has **one scoring function** for every module: `score()` in `backend/app/core/scoring.py`.
Modules never pick a level themselves. They only report what they observed, as **signals** (true/false
facts, plus a similarity number). The scoring function turns signals into points, and points into a level.

The model is **deterministic**: the same signals always give the same score. It is **explainable**: every
point can be traced to one rule. There is no machine learning (that is out of scope, OOS-02).

## 2. The basic idea in four steps

```
 signals from the module
        |
        v
 [1] add the points of every rule that fired        RULE_POINTS
        |
        v
 [2] cap the total at 100                           MAX_SCORE  -> "raw_score"
        |
        v
 [3] keep it inside the module's allowed levels     MODULE_LEVELS (D-03)
        |
        v
 [4] for live look-alike websites only:             SCORE_CAPS (D-29)
     lower it if the page is parked or
     does not show the brand
        |
        v
 final score 0-100  ->  level (Low / Medium / High / Critical)
```

The order matters: the module range is applied first, then the D-29 cap.

## 3. The levels

The level comes from the final score (`LEVEL_FLOORS` and `level_for()`), following requirement RSK-09:

| Score | Level | Rough meaning |
|---|---|---|
| 0-29 | Low | Worth knowing about; little sign of active abuse |
| 30-59 | Medium | Real brand use or preparation for abuse; review when possible |
| 60-79 | High | Strong signs of impersonation; review soon |
| 80-100 | Critical | Very likely active abuse; review first |

`score()` returns the final score and its level together (`level_for(final score)`), and the finding engine
(`record_detection()` in `backend/app/core/findings.py`) stores both from that one result, so the stored score
and level cannot disagree.

The level also decides whether a finding becomes an **alert**: only at or above the brand's "Alert from" level
(default Medium, section 10).

## 4. The points table

Every rule and its points are in `RULE_POINTS` in `backend/app/core/scoring.py`. The rules come from
three places: the original requirements (section 6 of the source requirements, IDs RSK-01 to RSK-08), the
document rules added in D-06, and the email rules added in D-28.

### 4.1 Website, app and social rules (from the requirements)

| Rule name | Points | Plain English | Why it matters | Used by |
|---|---|---|---|---|
| `brand_exact_in_domain` | +40 | The exact brand name appears in the identifier. For domains this is the domain name (`examplebank-login.com`); for apps the package name or app title; for social media the handle (D-20). Look-alike spellings do not count here. | Using the literal brand name is the strongest sign someone is posing as the brand. | Domains, Fake APK, Rogue app, Social |
| `typo_similarity_gt_80` | +25 | The name is more than 80% similar to a brand term. Exactly 80 does not count (D-05). | Close misspellings (`exampelbank`, `examp1ebank`) are made to fool readers. | Domains, Fake APK, Rogue app, Social, Social media (channels and accounts only) |
| `mx_present` | +15 | The look-alike domain has an MX record, so it can receive email. | The domain is ready for email phishing. | Domains |
| `https` | +10 | The site serves a TLS (HTTPS) certificate. | Criminals add HTTPS so the browser shows a padlock and the site looks safe. | Domains, Logo |
| `login_payment_keywords` | +20 | The page shows login or payment words ("login", "password", "OTP", "card number", "KYC" and others) or has a password field. | Phishing pages exist to collect credentials and payments. | Domains, Logo |
| `official_logo` | +30 | An image on the page (or the app icon) matches the official logo, with an image-fingerprint match of at least 85 out of 100. | Copying the logo is a deliberate attempt to look official. | Domains, Fake APK, Rogue app, Logo |
| `social_image_match` | +20 | A social profile picture, or a post or video thumbnail, matches the official logo. | Impersonating accounts and scam posts use the real logo to look genuine. | Social, Social media |
| `publisher_mismatch` | +25 | The app's publisher is not the official publisher. For APKs, also when the signing certificate differs from the official one (D-26). | Only the brand publishes the brand's apps. | Fake APK, Rogue app (always true for rogue apps, since official ones are skipped) |

Notes:

- Exact match and typo similarity **stack** (D-05). `examplebank-login.com` contains the exact name (+40)
  and is also very similar (+25).
- A homoglyph domain like `examp1ebank.com` does **not** get the exact-match points. It is caught by typo
  similarity instead, because the similarity code reads `1` as `l` (`backend/app/core/similarity.py`).

### 4.2 Document rules (D-06)

The requirements asked for a risk level for documents but gave no rules, so D-06 added these, using only
the checks the document requirements already describe:

| Rule name | Points | Plain English | Why it matters |
|---|---|---|---|
| `doc_brand_keyword` | +30 | The document mentions the brand. Always true for a document alert. | Brand content outside the brand's control. |
| `doc_official_domain` | +20 | The document contains an official domain or brand email domain. | Suggests it came from inside the company. |
| `doc_sensitive_pattern` | +30 | The file name or content contains a sensitive word or pattern, e.g. "confidential", "internal", "salary", "customer". | Indicates a real leak, not a brochure. |
| `doc_many_emails` | +20 | The document contains 5 or more email addresses. | Lists of people are valuable to attackers. |

### 4.3 Phishing email rules (D-28)

| Rule name | Points | Plain English |
|---|---|---|
| `known_malicious_url` | +40 | A link in the email is listed as malicious by **two or more** independent sources |
| `single_source_url_hit` | +15 | A link is listed by exactly **one** source |
| `malware_attachment` | +40 | An attachment is detected by ClamAV antivirus, or its hash is known to URLhaus |
| `suspicious_attachment` | +20 | An attachment looks dangerous: a YARA rule hit, an Office macro, an executable, or a double extension like `invoice.pdf.exe` |
| `auth_fail_brand_from` | +30 | The sender claims an official brand domain but DMARC fails: someone is spoofing the brand's own address |
| `lookalike_sender` | +25 | The sender, Reply-To, Return-Path or a link domain is a look-alike of the brand (similarity above 80) |
| `brand_impersonation` | +20 | The email uses brand terms but was not sent by the brand |
| `reply_to_mismatch` | +10 | Replies go to a different, non-official domain than the sender |
| `credential_or_payment_language` | +15 | Login, payment or urgency words ("verify now", "suspended", "within 24 hours") |
| `young_domain` | +10 | A sender or link domain was registered less than 30 days ago |
| `bad_sender_ip` | +10 | AbuseIPDB gives the sending IP an abuse confidence of 75 or more |
| `rspamd_phish` | +10 | The Rspamd engine flags the message |
| `live_phishing_page` | +20 | A linked page was opened by the website pipeline and looks like phishing |
| `lookalike_can_send` | +10 | A look-alike domain publishes an SPF record, so it is set up to send email |

`lookalike_can_send` is listed with the email rules, but it is set by the **domain** pipeline: a
look-alike domain with an SPF record gets +10 on its domain alert
(`backend/app/modules/domains/module.py`).

### 4.4 Brand email security (posture) rules

These score the brand's **own** domains, not attackers' domains. A gap makes it easier for criminals to
send email that appears to come from `examplebank.com` itself (`backend/app/modules/email/posture.py`).

| Rule name | Points | Plain English |
|---|---|---|
| `posture_dmarc_missing` | +40 | No DMARC record, more than one, or one with no policy |
| `posture_dmarc_none` | +20 | DMARC policy is `p=none`: spoofing is reported but not blocked |
| `posture_spf_missing` | +40 | No SPF record, several SPF records, or SPF ending in `+all` (anyone may send) |
| `posture_spf_softfail` | +10 | SPF ends in `~all`: spoofed mail is only marked, not rejected |
| `posture_dkim_missing` | +10 | No DKIM key found on common selector names |
| `posture_mta_sts_missing` | +5 | No MTA-STS policy (protects mail in transit) |

DMARC report alerts (senders that fail DMARC while using the brand domain, `backend/app/modules/email/dmarc.py`)
fire `auth_fail_brand_from` only: 30 points, Medium.

### 4.5 Social media brand-misuse rules (D-38)

Added on 2026-10-09 for the Social Media Brand Misuse module (`social_media`, Chapter 14). They score posts,
videos, ads and channels that use the brand on YouTube, Facebook, Instagram, X, Threads, Meta ads, Pinterest,
TikTok, LinkedIn and Telegram.

| Rule name | Points | Plain English | Why it matters |
|---|---|---|---|
| `brand_in_content` | +20 | The brand name is used in the post, video, ad or channel name or text. | On its own this is only a mention: Low, recorded but not alerted at the default "Alert from" Medium. |
| `scam_contact_details` | +30 | A phone number, WhatsApp link (`wa.me`, `api.whatsapp.com`, `chat.whatsapp.com`), Telegram link or UPI ID is published next to the brand by a non-official account. | This is how "customer care" scams move victims off the platform and collect payments. |
| `scam_language` | +20 | Scam wording such as "customer care", "helpline", "KYC", "refund", "guaranteed returns", "double your money", "investment plan", "loan approval", "work from home". | Fraud posts follow a few well-known scripts. |
| `paid_ad` | +10 | The item is a paid ad (from the Meta Ad Library). | Someone paid to reach many people with the brand name. |

The module also uses `social_image_match` (+20, thumbnail or channel picture matches the logo) and, for channels
and accounts only, `typo_similarity_gt_80` (+25). A brand mention plus the logo, contact details or scam wording
reaches Medium or higher and alerts.

## 5. The 0-100 cap

Points are added and the total is limited to 100 (`MAX_SCORE`). A domain with every rule firing could
reach 150 points; it is stored as 100. This capped total is kept as `raw_score`. The dashboard shows
"Rule total (capped at 100)" when this happens.

## 6. Module level ranges (D-03)

The requirements give each module a table of the levels it may report. For example, a fake app is never
"Low": any unauthorised use of the brand in an app store is at least Medium. So after adding points, the
score is moved into the module's range (`MODULE_LEVELS`). The number moves with the level, so the score
and the level never contradict each other.

| Module | Lowest | Highest | Score range | Why |
|---|---|---|---|---|
| Typosquat, MX, Phishing | Low | Critical | 0-100 | The requirements use all four levels for domains |
| Fake APK | Medium | High | 30-79 | Any fake app is at least Medium; requirements list Medium/High |
| Rogue app | Medium | High | 30-79 | Same as Fake APK |
| Logo on websites | Medium | High | 30-79 | Requirements list Medium/High |
| Social impersonation | Low | High | 0-79 | Requirements list Low/Medium/High |
| Social media brand misuse | Low | Critical | 0-100 | A post that pushes fake contact details with the logo can be as dangerous as a phishing site (D-38) |
| Sensitive documents | Medium | Critical | 30-100 | A document with brand content is at least Medium; a leak can be Critical |
| Phishing email | Low | Critical | 0-100 | Full range |
| Email posture | Low | Critical | 0-100 | Full range |
| DMARC reports | Low | Critical | 0-100 | Full range |

Example: a rogue app with 90 points is stored as **79 (High)**, with `raw_score` 90. An APK with only 25
points is raised to **30 (Medium)**.

## 7. The D-29 brand-evidence caps

### 7.1 The problem

The first live scans of real brands produced Critical alerts for innocent websites. A different business
with a similar name scored like this: look-alike spelling +25, mail server +15, SPF +10, HTTPS +10, the word
"login" on its page +20 = 80, Critical. Parked pages from domain sellers were flagged too. Those points
describe the **domain**, not the **content**. Nothing on the page pretended to be the brand.

### 7.2 The rule

Decision D-29 (owner, 2026-10-08): a **live look-alike website** only reaches High or Critical when the page
itself shows the brand.

| Situation | Cap | Highest score | Reason shown to the analyst ("Score Cap" field) |
|---|---|---|---|
| Live page is **parked or for sale** | `parked_page` | 29 (Low) | "Parked / for-sale page — capped at Low" |
| Live page shows **no brand evidence** | `no_brand_evidence` | 29 (Low) | "No brand content on the page (logo, favicon, brand name or official-site link) — capped at Low" |
| Live page shows no brand evidence but has a **login or payment form** | `no_brand_login_form` | 59 (Medium) | "Login/payment form but no brand content on the page — capped at Medium" |
| Live page shows the brand | none | 100 | none |
| Domain has **no website** (mail only, or nothing answered) | `no_website` | 79 (High) | "No website seen, so no brand content or phishing behaviour observed — capped at High" |

**Changed on 2026-10-15 (D-45).** Before, an unrelated live site was capped at Medium (59) and a domain with no
website was not capped at all. The first live scan of Navi showed what that did: 59 unrelated sites (a Korean
car-navigation shop, a Japanese job site, `ivan-benavides.com`) were Medium alerts, and 18 domains with only a
mail record were Critical. Now Critical needs the page to show the brand, and an unrelated site only stays
Medium when it asks for a login or payment. Every stored score also carries `"policy": "2026-10-15"`, the
version of these rules, so a score can be reproduced later.

**Brand evidence** means any of these on the page (`backend/app/modules/pagecheck.py`):

- the official logo (image match of at least 85);
- the official favicon;
- the brand name, keywords or product terms in the page text (short abbreviations only with context, D-25);
- a link to or mention of an official domain or email domain.

The page's own domain name is removed from the text before searching, so `examplebank-login.com` printing
its own address does not count as brand evidence.

A page is **parked** when it is served from a known domain marketplace or parking service (such as
hugedomains.com or sedo.com), is on a parking "lander" path, or contains phrases like "this domain is for
sale" or "buy this domain".

### 7.3 Details

- The cap only applies to the three domain modules (`CAPPED_MODULES`) and only when the site is live.
- The cap only lowers a score. It is recorded (`cap` in the finding's `signals`) only when it actually lowered it.
- The points table is unchanged. The un-capped total remains visible as `raw_score`.
- **Suspected Phishing** also requires brand evidence and a non-parked page.
- Trade-off: a phishing kit with no brand text, logo or link scores at most Medium until its content
  changes. It is re-checked on every scan (every 6 hours for domains) and rises automatically. If a decision
  had closed it, the risk increase re-opens it (section 10).
- A registered look-alike **without** a website is not capped: the domain name is the only evidence. So
  `examplebank-login.com` with a mail server and SPF but no website scores 40 + 25 + 15 + 10 = 90, Critical.

## 8. The separate "Email Risk" field (D-02)

The requirements contain two rules that disagree. Section 3.1 says: no MX = Low, MX = Medium, MX and a live
website = High. Section 6 gives MX only +15 points. One alert cannot have two levels.

Decision D-02: the alert's level always comes from the points model. The section 3.1 rule is shown as a
separate field on domain alerts, **Email Risk**, computed by `email_risk()` in `backend/app/core/scoring.py`:

| MX record | Website live | Email Risk |
|---|---|---|
| Yes | Yes | High |
| Yes | No | Medium |
| No | either | Low |

Email Risk does not change the score. It tells the analyst whether the domain can be used for email
phishing.

## 9. Email scoring and two-source corroboration

Email alerts use the same function and the full Low-Critical range, with no D-29 cap. The analysis code is
`backend/app/modules/email/analysis.py`. The precision safeguards (D-28):

**Corroboration.** Every link is checked against three reputation services: URLhaus, OpenPhish and
urlscan.io (`url_reputation()` in `backend/app/modules/email/intel.py`). `corroborated()` counts how many
**different** tools called the link malicious. The platform's own website pipeline also opens up to five
links; if one looks like phishing (login words, the brand favicon or the logo), that counts as one more
independent source. The highest count over all links decides:

| Independent sources | Rule that fires | Points |
|---|---|---|
| 0 | none | 0 |
| 1 | `single_source_url_hit` | +15 |
| 2 or more | `known_malicious_url` | +40 |

No single source can push an email to Critical on its own.

**Not checked is not clean.** A source without an API key, or one that is down, scores 0 and is listed in
the alert's "Not Checked" field. The analyst can see what was not verified.

**Official senders are protected.** An email from an official brand domain that passes DMARC is never
scored for `lookalike_sender` or `brand_impersonation`.

**Verdict label.** Separately from the score, the email gets a summary in its title: "Likely phishing"
(known-malicious link, malware, or a spoofed brand domain), "Suspicious" (look-alike sender, brand
impersonation, or a single-source link) or "Low risk".

Accuracy is measured on a labelled set of emails by `backend/scripts/email_accuracy.py`.

## 10. From score to alert, and how scores change over time

### 10.1 The alert rule (D-33, D-34)

Since SP2 a score no longer turns into an alert by itself. `record_detection()` in `backend/app/core/findings.py`
stores every scored result as a **finding** and checks the **alert rule** (`meets_rule()`):

```
 stage == Finding            (the module analysed it; a Candidate never alerts)
   AND
 risk level >= the brand's "Alert from" level   (brands.alert_min_level, default Medium)
```

| Example for Example Bank ("Alert from" Medium) | Stage | Level | Alert? |
|---|---|---|---|
| `examplebank-pay.net` registered, no website, no MX | Candidate | High (40 + 25 = 65) | No, a Candidate never alerts |
| `exampelbank.com` bakery site, capped by D-29/D-45 | Finding | Low (29) | Only if "Alert from" is Low |
| `examplebnk.com` parked page, capped by D-29 | Finding | Low (29) | No (kept on the Findings page) |
| YouTube video that only mentions "Example Bank" | Finding | Low (20) | No |
| `examp1ebank.com` live phishing site | Finding | High (70) | Yes |

A brand that wants to see Low findings in the queue sets "Alert from" to Low; a brand that is flooded can set it
to High. SP3 will add a confidence condition to the same rule.

### 10.2 Re-scans (D-36)

The score is recalculated from scratch on every scan; points do not accumulate between scans. Each scan stores an
**observation** with that scan's score and level. Then:

- If the level changes, a `rescored` timeline event "Risk Medium -> High (70)" is written.
- A level **increase** is a meaningful change. If the finding already alerted and is New, Investigating or
  Confirmed Threat, a new alert is raised with trigger `change`. If its decision was False Positive,
  Legitimate, Ignored or Resolved, it is re-opened to New and an alert with trigger `reopen` is raised.
- If the finding reaches the alert rule for the first time (for example Low to Medium), the alert has trigger
  `first_crossing`.
- If the level falls, or the score moves inside the same level, the decision stays as it is and no alert is
  raised; only the score and level change.

Chapter 10, section 12, lists all meaningful changes (website went live, login form, logo, MX and others).

## 11. Where the explanation is stored and shown

`ScoreResult.as_dict()` is saved in the finding's `signals` column (JSON), and in each observation. Each alert
record also keeps the rules that fired at that moment (`alerts.reasons`):

```
{
  "score": 59,
  "level": "Medium",
  "raw_score": 80,
  "cap": "no_brand_evidence",
  "rules": {
    "typo_similarity_gt_80": 25,
    "mx_present": 15,
    "https": 10,
    "login_payment_keywords": 20,
    "lookalike_can_send": 10
  }
}
```

The alert detail page (`frontend/src/app/(app)/alerts/[id]/page.tsx`) and the email detail page show a
**"Why this score"** panel:

- the score out of 100, with a bar marking the Low, Medium, High and Critical bands;
- one line per rule that fired, with a readable label (from `RULE_LABELS` in `frontend/src/lib/constants.ts`)
  and its points;
- the "Rule total" (the raw score, noting "capped at 100" when it reached 100);
- when the final score differs from the raw score, a note "Adjusted from X to Y to stay within the risk range
  this module can report".

For domain alerts lowered by D-29, the reason also appears among the alert's fields as **Score Cap**. Note
that the panel's "Adjusted from ..." sentence uses the same wording for module-range adjustments and D-29
caps; the Score Cap field is where the D-29 reason is spelled out.

## 12. Worked examples

All examples use Example Bank (`examplebank.com`, keyword "Example Bank").

**Example 1: live phishing site, High.** `examp1ebank.com`, live, login form, "Example Bank" in the text,
MX record, HTTPS, no SPF, logo not matched.

| Rule | Points |
|---|---|
| typo similarity above 80 (reads as `examplebank`, 100%) | +25 |
| MX present | +15 |
| HTTPS | +10 |
| login/payment keywords | +20 |
| **Total** | **70 -> High** |

No cap: the page shows the brand. Email Risk: High.

**Example 2: the same site adds the official logo, Critical.** 70 + 30 (official logo) = **100 -> Critical**.
Timeline: "Official logo detected" and "Risk High -> Critical (100)"; both are meaningful changes, so a new
alert is raised with trigger `change`.

**Example 3: unrelated business, capped at Low (D-45; Medium before 2026-10-15).** `exampelbank.com` is a bakery's website with a
customer "login" link. It has MX, SPF and HTTPS. Raw: 25 + 15 + 10 + 20 + 10 = 80 (Critical). The page has
no Example Bank name, logo, favicon or link, so the `no_brand_evidence` cap applies: **29 -> Low**.
Score Cap: "No brand content on the page ... — capped at Low". Not Suspected Phishing. Had the bakery page asked
for a password or card number, the `no_brand_login_form` cap would keep it at **59, Medium**.

**Example 4: parked domain, capped at Low.** `examplebnk.com` shows a "This domain is for sale" page with
HTTPS and MX. Raw: 25 + 10 + 15 = 50 (Medium). Parked cap: **29 -> Low**.

**Example 5: registered look-alike, no website, Critical.** `examplebank-login.com` has MX and SPF but no
website. 40 (exact) + 25 (similar) + 15 (MX) + 10 (can send) = **90 -> Critical**. No cap, because there is
no page to judge. It has MX, so it is a Finding and alerts. Without MX (and without a website) the same domain
would be a Candidate and would not alert, whatever its score.

**Example 6: rogue app, clamped to High.** Google Play app "Example Bank Loan Helper" from "QuickFin Apps".
40 (exact name in title) + 25 (similar) + 25 (publisher mismatch) = 90. Rogue apps may only be Medium or
High, so the score becomes **79 -> High**, raw 90.

**Example 7: weak fake APK, raised to Medium.** An APK listing from an unknown developer that passed the
module's relevance check, but whose name and package are only 70% similar to the brand and whose icon does
not match the logo: 25 (publisher mismatch) = 25. APKs are at least Medium: **30 -> Medium**.

**Example 8: social account.** Telegram `@examplebank_help` with the official logo as profile picture:
40 (exact handle) + 25 (similar) + 20 (image match) = 85. Social is capped at High: **79 -> High**.
Without the logo: 65 -> High. An account whose handle is only a close misspelling (no exact brand name,
no logo) earns just the similarity points: 25 -> **Low**.

**Example 9: leaked document, Critical.** A spreadsheet that mentions Example Bank (+30), contains
"Confidential" (+30), contains `examplebank.com` (+20) and lists 400 email addresses (+20) = **100 -> Critical**.
A brochure that only mentions the brand: 30 -> Medium.

**Example 10: phishing email.** From `alerts@examplebank-secure.com`, uses "Example Bank", says "verify
within 24 hours". One link is listed by URLhaus and OpenPhish (two sources).

| Rule | Points |
|---|---|
| known malicious URL (2 sources) | +40 |
| look-alike sender | +25 |
| brand impersonation | +20 |
| credential or urgency language | +15 |
| **Total** | **100 -> Critical** |

If only one source listed the link: 15 + 25 + 20 + 15 = **75 -> High**.

**Example 11: the brand's own email security.** `examplebank.com` has no DMARC record (+40), no DKIM on
common selectors (+10) and no MTA-STS (+5) = **55 -> Medium**.

**Example 12: scam "customer care" video, Critical.** A YouTube video titled "Example Bank customer care number -
KYC update" shows the Example Bank logo as its thumbnail and lists a WhatsApp number and a UPI ID in its
description. 20 (brand in content) + 20 (thumbnail matches logo) + 30 (scam contact details) + 20 (scam
wording) = **90 -> Critical**. A video that only mentions Example Bank in a product review: 20 -> **Low**,
stored as a Finding but not alerted at the default "Alert from" Medium.

## 12a. Confidence: how sure we are (D-47)

Risk answers "how bad would it be?". **Confidence** answers "how sure are we that this is a real brand threat?".
Two Critical findings can deserve very different trust: one built on a captured login page with the official
logo and two threat-intelligence listings, the other on a domain name alone. Since 2026-10-16 every finding
carries both, side by side, and confidence never changes the risk score (`backend/app/core/confidence.py`).

| Factor | Points | Why |
|---|---|---|
| Base | 20 | An automated check found it |
| Page content shows abuse (login/payment form, scam or support wording, sensitive data) | +15 | |
| Contact details next to the brand | +15 | |
| Official logo or favicon matched | +15 | |
| Publisher / sender / signer verified as not the brand's | +15 | |
| Infrastructure ready for abuse (MX, TLS, SPF) | +5 | Common on legitimate sites too, so weak |
| Two threat-intelligence sources list it / one source | +30 / +10 | |
| Two or more of the kinds above agree | +10 | Independent corroboration |
| Only the name matches | −10 | |
| Finding / Candidate | +10 / −10 | |
| Screenshot, page or file captured | +10 | |
| Capture failed / WHOIS failed / threat intel incomplete / engines not checked | −10 / −5 / −5 / −10 | Something that should have been checked is unknown |
| Found through a search snippet, not platform data | −10 | |
| Parked page / live page without brand content | −20 / −15 | Contradicting evidence |
| APK signer verified as not official / not verified | +25 / −10 | |
| Email posture and DMARC (facts read from DNS / reports) | 70 | |

**Each kind of evidence counts once.** Three scam phrases are one confirmation, not three. Levels: **Low**
below 40, **Medium** 40-69, **High** 70 and above. The score panel of every finding lists each factor with its
reason, and the alert and finding lists can be sorted by **Most certain**.

**Example.** `examp1ebank.com` with only its name: base 20, name only −10, Candidate −10 = **0, Low**, even if
its risk is High. The same domain once it shows a captured login page with the logo: 20 + 15 (content) + 15
(logo) + 10 (two kinds agree) + 10 (Finding) + 10 (captured) = **80, High**.

**Not a probability.** Confidence 80 does not mean "80 % likely". That needs analyst decisions to calibrate
against, which do not exist yet.

## 13. Honest limitations

- **Confidence is rule-based, not calibrated (D-47).** Since 2026-10-16 confidence is a separate score
  (section 12a), but its points are fixed numbers, not measured against analyst decisions yet.
- **Fixed points.** The points are fixed numbers from the requirements and decisions, not learned from
  data. They are easy to explain but may over- or under-weight some cases.
- **Domains without a website are at most High (D-45)** unless two threat-intelligence sources list them
  (D-46). Before 2026-10-15 they could be Critical on name and DNS facts alone.
- **Unknown inputs are not scored as "no" (D-31, SP1).** When a website answered but could not be captured,
  the facts are recorded as unknown and never compared, so an existing finding is not treated as "offline"
  and no change is raised (SP2); a new domain in that
  state shows "Website Live: unknown (capture failed)" and earns no page points until a capture succeeds. A
  DNS timeout does not drop a domain as unregistered; it is retried on the next scan. SP1 changed how results
  are reported, not the points table.
- **Brand-free phishing kits** stay at Medium when they ask for a login or payment, Low otherwise, until the
  page shows the brand or two threat-intelligence sources list them (D-29, D-45, D-46).
- **The email link check is looser than D-29.** When the email module opens a linked page, it counts it as
  phishing on login words, the brand favicon or the logo; it does not apply the D-29 brand-evidence and
  parked-page rules used for domain alerts.
- **"Not checked" sources score 0.** Without API keys, some email checks contribute nothing; the alert lists
  them, but the score can be lower than it would be with full coverage.
- **Thresholds are hard edges.** Similarity of exactly 80 gets no points; 80.5 gets 25. Logo matches below
  85 count as no match.

## Key takeaways

- One function, `score()` in `backend/app/core/scoring.py`, scores every module from the same points table.
- Score = sum of fired rules, capped at 100, moved into the module's allowed range, then (live look-alike sites only) capped by D-29.
- Levels: 0-29 Low, 30-59 Medium, 60-79 High, 80-100 Critical.
- A live look-alike site needs brand evidence on the page to be High or Critical; parked pages are at most Low.
- An email link counts as "known malicious" only when two independent sources agree; unchecked sources score 0 and are listed.
- Every finding stores its explanation in `signals` (and each alert keeps the rules that fired when it was raised), shown in the "Why this score" panel; there is no separate confidence score yet.
- A score becomes an alert only for a Finding (not a Candidate) at or above the brand's "Alert from" level (default Medium); re-scans alert again only on a meaningful change such as a risk level increase (D-33, D-34, D-36).
- Social media brand misuse (D-38) adds four rules: brand in content +20, scam contact details +30, scam wording +20, paid ad +10; a bare mention is Low and does not alert by default.
