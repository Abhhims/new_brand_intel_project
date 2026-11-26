# Configuration Guide for New Brands (DEL-06)

Adding a brand takes about five minutes and is done entirely in the dashboard (**Brands → Add brand**, admin role).
Every field below changes what the detection modules look for, so the more complete it is, the fewer false
positives and missed detections.

## 1. Collect from the client first

| Item | Example (demo brand) | Used by |
|---|---|---|
| Brand name | Zentrova Bank | all |
| Keywords — the words people type for the brand | `zentrova`, `zentrova bank` | all modules (typo similarity, text matching) |
| Product terms — product/service names | `zentrova pay`, `zentrova upi`, `zentrova netbanking` | Rogue apps, Documents |
| Official domains | `zentrova.com`, `zentrovabank.com` | Typosquat seeds; never alerted |
| Email domains | `zentrova.com` | Documents (brand emails inside files) |
| Official Android package names | `com.zentrova.mobile` | Fake APK |
| **App signing certificate SHA-256** — Play Console → *App integrity* → *App signing* → "App signing key certificate", SHA-256 (or `apksigner verify --print-certs app.apk`). Colons/spaces are fine | `89:D3:8A:…:5E:FC` | Fake APK: genuine copies on mirrors are recognised, re-signed copies flagged (D-26) |
| Approved app publishers (exact Play Store developer name) | `Zentrova Bank Ltd` | Rogue apps, Fake APK |
| Official social handles (without @) on every platform | `zentrovabank`, `zentrova_official` | Social; never alerted |
| Official logo(s) — PNG/JPG/WEBP, ideally on transparent or white background, ≥ 200 px | `logo.png` | Logo, Phishing, APK, Rogue, Social |
| Favicon (the site's real `/favicon.ico`) | `favicon.ico` | Phishing (favicon hash match) |
| App icon (from the store listing) | `app_icon.png` | Fake APK, Rogue apps |
| Signed authorisation to monitor the brand | — | legal prerequisite |

## 2. Create the brand

1. **Brands → Add brand.** Enter the name, description, keywords and product terms. Every brand is scanned against
   live sources — there is no demo mode in the product (D-32).
2. Open the brand. Under **Official assets** upload the logo (kind *Logo*), favicon (kind *Favicon*) and app icon
   (kind *App icon*). Upload several logo variants (horizontal, square, monochrome) if the brand uses them —
   each one is matched. Without an official logo the Logo scan has nothing to compare against and ends `failed`
   with "Official logo assets: Not configured".
3. Under **Allowlists** add official domains, email domains, packages, publishers, social handles (a profile URL
   is fine — it is converted to the handle) and app signing certificates.
4. Press **Run scan now → All modules**. Watch progress under **Scans**; each scan shows how many items it checked,
   created and updated, and — under **What this scan checked** — every part of the scan with its result (for
   example "Telegram API: Not configured" or "Web search - DuckDuckGo (free, paced): Unavailable"). The
   **Integrations** page lists which tools are configured and how to configure the missing ones (D-31).

Brands are scanned automatically every day at 02:00 UTC; live/email-enabled domains are re-checked every 6 hours.

## 3. Tuning

| Problem | Fix |
|---|---|
| A legitimate partner/reseller domain keeps alerting | Add it to the brand's **domain** allowlist, then mark the alert *False Positive* |
| A real subsidiary app is flagged | Add its publisher and package to the allowlists |
| Too many unrelated social accounts | Remove generic keywords (e.g. a common English word); keep distinctive ones |
| Logo not detected on a page you know uses it | Upload that exact logo variant as an additional *Logo* asset |
| Brand name is a short/common word | Add longer keywords ("acme bank", "acmepay") and product terms; short words generate noisy similarity |

Global thresholds live in `deploy/.env` (restart workers after changing):

| Setting | Default | Meaning |
|---|---|---|
| `TYPO_TLDS` | `["com","in","net","org","co","io","uk","us","ae","sg","au"]` | TLDs every typo pattern is tried on (TYP-08) |
| `LOGO_MATCH_THRESHOLD` | `85` | Logo/favicon/avatar match score (0–100) that counts as "official logo detected" |
| `PHISHING_SIMILARITY_THRESHOLD` | `80` | Similarity needed for "Suspected Phishing" (D-04) |
| `FETCH_RATE_PER_HOST_PER_MINUTE` | `30` | Politeness limit per external host |

## 4. How the risk score works (for analysts)

Every alert shows **Why this score** — the rules that fired and their points (requirements §6 plus decisions
D-05, D-06, D-20):

| Rule | Points |
|---|---|
| Exact brand name in the domain / handle / package | +40 |
| Typo similarity above 80% | +25 |
| MX record present | +15 |
| HTTPS enabled | +10 |
| Login/payment keywords on the page | +20 |
| Official logo detected | +30 |
| Social profile image matches the logo | +20 |
| Official publisher mismatch | +25 |
| Document: brand keyword / official domain / sensitive pattern / ≥5 emails | +30 / +20 / +30 / +20 |

Total capped at 100 → **Low** 0–29, **Medium** 30–59, **High** 60–79, **Critical** 80+. Some modules keep the
level inside the range their requirement allows (APK, Rogue app, Logo: Medium–High; Social: Low–High; Documents:
Medium–Critical — D-03).

## 5. Removing a brand

**Brands → brand → Delete** (admin). This deletes the brand's alerts, evidence records and scan history.
Evidence files in object storage are kept until the bucket's retention policy removes them.
