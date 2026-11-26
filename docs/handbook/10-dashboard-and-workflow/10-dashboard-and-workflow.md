# Chapter 10 - Dashboard and Analyst Workflow

In this chapter:
- Every page of the analyst dashboard, what it shows, and which API call feeds it.
- The three levels of a result since SP2 (decisions D-33 to D-37): **Candidate**, **Finding** and **Alert**, and
  the brand's **"Alert from"** level that decides when a finding becomes an alert.
- How an analyst works an alert: the queue, the detail page, the timeline, the seven analyst **decisions** and the
  allowed moves between them, and the new **Findings** page with bulk decisions.
- What a re-scan does: one **observation** per scan, **meaningful changes**, and when a decided finding is reopened.
- How the dashboard tells "checked and clean" apart from "could not check": the coverage banner, error panels,
  scan states, the component checklist and the Integrations page (D-31).
- The complete REST API under `/api/v1`, with who is allowed to call each endpoint.
- The frontend technology (Next.js, TanStack Query, Tailwind CSS, shadcn/ui) and why it was chosen.

## 1. Plain words first

The **dashboard** is the website analysts use every day. It runs in a normal web browser. It does not
detect anything itself. The detection work happens in background **workers** (see Chapter 01). The workers
store their results in the database. The dashboard reads those results through the **REST API** and shows them.

A few words used throughout this chapter:

| Word | Meaning |
|---|---|
| Brand | A company the platform protects, for example Example Bank with the official site `examplebank.com`. |
| Module | One kind of detection, for example "Typosquat Monitoring" or "Fake APK Monitoring". There are eleven (eight original modules plus three email modules). |
| Candidate | Something a module discovered but has not analysed yet, for example a registered look-alike domain with no website and no mail server. It is kept for reference and never raises an alert (D-33). |
| Finding | One suspicious thing (domain, app, account, post, document, web page or email) that was analysed and has evidence. There is one finding per thing per brand, for example `examp1ebank.com`. It has a score, a risk level and a decision. |
| Alert | A record raised when a finding reaches the brand's "Alert from" risk level for the first time, or later changes in a meaningful way (D-34, D-36). One finding can collect several alerts over time. |
| Observation | One sighting of a finding by one scan (or one email upload): what was seen, with which score, at that moment. |
| Timeline | Everything that happened to a finding, newest first: discovered, changed, rescored, alerted, decided, reopened. |
| Evidence | Files and facts that prove what was seen: a screenshot, a favicon, DNS records, a certificate, a downloaded file. |
| Decision | What the analyst decided about a finding: New, Investigating, Confirmed Threat, False Positive, Legitimate, Ignored or Resolved (D-35). The alert API still calls this field `status` for compatibility. |
| Scan | One run of one module for one brand, started by the schedule or by a person. |
| Scan component | One part of a scan, for example "DNS resolution" or "Telegram API", with its own result. |
| Integration | An external tool or service the scans depend on, for example a web search API or crt.sh. |
| API | Application Programming Interface. Here: the web addresses the dashboard calls to read and change data. |

### Candidate, Finding, Alert (SP2)

Before SP2, every result a module produced went straight into the alert queue. A registered look-alike domain
with nothing on it sat next to a live phishing site. Since SP2 (2026-10-09, decisions D-33 to D-37) a result
climbs three levels. The demo line is: "Discovery is not an alert. We only alert after we've looked."

```
  Module result (a "Detection")
         |
         v
  +-------------+   analysed, with evidence?   +-------------+   risk >= brand's        +---------+
  |  Candidate  | ---------------------------> |   Finding   | ---"Alert from" level--> |  Alert  |
  | discovered, |   (the module decides; a     | analysed,   |   (first time, or a      | record  |
  | weak        |    Finding never goes back)  | evidence    |    meaningful change)    | + reason|
  +-------------+                              +-------------+                          +---------+
   never alerts                                 shown on the Findings page              shown in the
                                                                                        alert queue
```

| Level | What it means | Example for Example Bank | Where you see it |
|---|---|---|---|
| Candidate | Discovered, but the module had nothing more to look at | `examplebank-login.net` is registered, but has no website and no mail server | Findings page, filter "Stage: Candidate" |
| Finding | Analysed, with evidence | `examp1ebank.com` has a mail server, or its website was captured | Findings page |
| Alert | The finding met the alert rule | `examp1ebank.com` is a Finding with risk High, and the brand alerts from Medium | Alert queue, dashboard tiles, exports |

**The alert rule (D-34).** A finding raises an alert only when its stage is **Finding** and its risk level is at
or above the brand's **"Alert from"** level (`brands.alert_min_level`, default **Medium**, set on the brand form).
A Candidate never alerts, whatever its score. A Low finding is stored and visible on the Findings page, but does
not enter the queue unless the brand alerts from Low. SP3 will add a confidence condition to the same rule.

Each module decides when its result counts as analysed (the `analysed` flag on the module's `Detection`). The
module chapters (03 to 09 and 14) explain the rule for each one.

## 2. Frontend technology and why

The dashboard lives in `frontend/`. The pages are in `frontend/src/app`, shared pieces in
`frontend/src/components`, and the API client in `frontend/src/lib/api.ts`. The stack was chosen in the design
spec of 2026-10-06 (`docs/superpowers/specs/2026-10-06-beyond-cloud-brand-intel-design.md`, section 7). No
separate decision ID exists for it. Decision D-28 later confirmed "PostgreSQL + Next.js kept (not
MongoDB/React)" when the email module was added.

| Tool | What it is | What we use it for | Why |
|---|---|---|---|
| Next.js 16 (App Router) | A React framework that adds page routing and a production build | One folder per page under `frontend/src/app`; built as a small standalone Node.js server (`deploy/frontend.Dockerfile`) | File-based routing keeps the page list obvious. One build gives one container. |
| React 19 | A library for building user interfaces from components | Every page and widget | The most widely known UI library; easy to hire for. |
| TanStack Query | A library that fetches server data and caches it | Every API read (`useQuery`) and write (`useMutation`); keys in `frontend/src/lib/queries.ts` | Handles loading states, caching, re-fetching and polling. The Scans page polls every 5 seconds only while a scan is running. |
| TanStack Table | A "headless" table helper (logic only, no styling) | The alert queue and the email list | Sorting and column logic without fixing the look. |
| Tailwind CSS 4 | Utility CSS classes written directly in the markup | All styling, light and dark themes | No separate style sheets to keep in sync. |
| shadcn/ui (on Base UI) | Copy-in components (buttons, dialogs, tables, selects) built on accessible primitives | `frontend/src/components/ui/*` | The code is copied into the project, so it can be changed freely. The primitives handle keyboard and screen-reader access. |
| Recharts | A React chart library | The 30-day trend chart (`frontend/src/components/charts.tsx`) | Simple bar charts with tooltips and click-through. |
| react-hook-form + zod | Form state and validation | Brand form, user form | Clear error messages before anything is sent. |
| sonner | Small pop-up notifications ("toasts") | "Downloaded alerts.csv", "Upload failed" | Non-blocking feedback. |
| next-themes, lucide-react | Theme switcher and icon set | Light / dark / system theme, all icons | Small and standard. |

How the browser talks to the API:

```
 Browser (Next.js page)
   |  1. POST /api/v1/auth/login  -> receives a JWT token
   |  2. token saved in localStorage ("bc.token")
   |  3. every request sends  Authorization: Bearer <token>
   v
 FastAPI at NEXT_PUBLIC_API_URL (default http://localhost:8010) + /api/v1
   |
   +-- 401 (token expired)  -> the page clears the token and opens /login?next=<page>
   +-- 4xx                  -> error message shown, no automatic retry
   +-- 5xx / network error  -> retried up to 2 times by TanStack Query
```

A **JWT** (JSON Web Token) is a signed piece of text that proves who you are. It expires after 12 hours by
default (`JWT_EXPIRE_MINUTES`). The API address is fixed into the web app when it is built
(`NEXT_PUBLIC_API_URL`). Changing it means rebuilding the `web` container.

## 3. Page map

```
 /login
   |
   v
 /  (Dashboard) ------------------------------------------------------------------+
   |         |           |         |         |          |          |              |
 /alerts   /findings   /social   /emails   /brands    /scans   /integrations   /settings/users
   |         |                     |         |                                    (admins only)
 /alerts/  /findings/            /emails/  /brands/[id]
  [id]      [id]                  [id]
```

| Route | Page | Source file | Who sees it |
|---|---|---|---|
| `/login` | Sign in | `frontend/src/app/login/page.tsx` | Everyone |
| `/` | Dashboard ("Brand exposure today") | `frontend/src/app/(app)/page.tsx` | Signed-in users |
| `/alerts` | Alert queue | `frontend/src/app/(app)/alerts/page.tsx` | Signed-in users |
| `/alerts/[id]` | Alert detail | `frontend/src/app/(app)/alerts/[id]/page.tsx` | Signed-in users |
| `/findings` | All findings and candidates, with bulk decisions (new in SP2) | `frontend/src/app/(app)/findings/page.tsx` | Signed-in users |
| `/findings/[id]` | Finding detail | `frontend/src/app/(app)/findings/[id]/page.tsx` | Signed-in users |
| `/social` | Social Media: social media findings as screenshot cards (Chapter 14) | `frontend/src/app/(app)/social/page.tsx` | Signed-in users |
| `/emails` | Phishing emails list and upload | `frontend/src/app/(app)/emails/page.tsx` | Signed-in users |
| `/emails/[id]` | Email detail | `frontend/src/app/(app)/emails/[id]/page.tsx` | Signed-in users |
| `/brands` | Brand list | `frontend/src/app/(app)/brands/page.tsx` | Signed-in users (only admins can add) |
| `/brands/[id]` | Brand detail and onboarding | `frontend/src/app/(app)/brands/[id]/page.tsx` | Signed-in users (only admins can edit) |
| `/scans` | Scan history | `frontend/src/app/(app)/scans/page.tsx` | Signed-in users |
| `/integrations` | Integration status | `frontend/src/app/(app)/integrations/page.tsx` | Signed-in users |
| `/settings/users` | User management | `frontend/src/app/(app)/settings/users/page.tsx` | Admins only (analysts see "Admins only") |

The side menu (`frontend/src/components/app-shell.tsx`) lists Dashboard, Alerts, Findings, Social Media,
Emails, Brands, Scans, Integrations and, for admins, Users. It also has the light/dark/system theme switch and the sign-out button.

## 4. Login

The login page asks for an email and a password. It calls `POST /api/v1/auth/login`. The password is checked
against an Argon2 hash (a slow, salted one-way scramble that resists guessing). A wrong password and a
deactivated account give the same message: "Invalid email or password".

After sign-in the page goes to the address in `?next=` (only if it is a path inside the site), or to the
dashboard. There is no self-registration. The first admin is created automatically when the API starts
(`backend/scripts/bootstrap.py`, using `BOOTSTRAP_ADMIN_EMAIL` and `BOOTSTRAP_ADMIN_PASSWORD`). All other
accounts are created by an admin (decisions D-15 and D-27).

## 5. Dashboard

The dashboard answers one question: "How exposed are our brands today?" A brand selector at the top limits
every number to one brand (the brand is kept in the address as `?brand=<id>`). "Today" means the current UTC
day.

Two API calls feed the whole page:

| API call | Refreshes | Feeds |
|---|---|---|
| `GET /api/v1/stats/executive?brand_id=...` | Every 60 seconds | The coverage banner, the hero box, all tiles, "Open alerts by risk", "Open alerts by module", "Alerted findings by decision" |
| `GET /api/v1/stats/trends?days=30&brand_id=...` | When the page loads | "New alerts, last 30 days" chart |

The counts come from `backend/app/api/stats.py`. Since SP2 the alert tiles count **alerted findings** (findings
that have raised at least one alert), so one domain that alerted twice is still counted once. An alerted finding
is **open** when its decision is New, Investigating or Confirmed Threat (`OPEN` in `stats.py`): a confirmed
threat stays open until someone marks it Resolved. "Today" means the finding's latest alert was raised today.

### The coverage banner

A zero on the dashboard only means something if a scan actually looked. The banner above the tiles
(`CoverageBanner` in `frontend/src/app/(app)/page.tsx`) uses two fields of `/stats/executive`:
`last_completed_scan_at` (when the newest scan ended Completed, Partially completed or Completed with errors)
and `components_unavailable` (how many scan parts were not configured, unavailable or failed in the latest run
of each brand and module).

| Situation | Banner |
|---|---|
| No scan has completed yet | "No scans have run yet" - "Nothing has been checked, so there is no result yet - this is not the same as 'no threats'." with a link to Brands |
| A scan has completed and no alert is open | "No threats detected." with "Last completed scan ..." |
| A scan has completed, alerts are open and some scan parts could not run | An amber note with "Last completed scan ..." |
| A scan has completed, alerts are open and every scan part ran | No banner (the tiles speak for themselves) |

Whenever a scan has completed and some scan parts could not run, the banner adds "N scan parts could not run in
the latest scans, so coverage is reduced - see Scans and Integrations."

"No threats detected." is therefore never shown when nothing was scanned (D-31, RDA-02).

### Error panels

If the API cannot be reached or returns an error, the page shows a red error panel with the message, the
sentence "The numbers on this page are not shown because they could not be loaded - this is not a clean
result." and a **Retry** button (`ErrorPanel` in `frontend/src/components/query-state.tsx`, RDA-19). A failed
request is never shown as an empty list or a zero. The dashboard (stats and trend chart), alert queue, alert
detail, brand list, brand detail, Scans and Integrations pages all use it. On the alert and brand detail pages
only a real 404 shows "not found"; any other failure shows the error panel.

| Box on screen | Field from `/stats/executive` | What is counted | Clicking opens |
|---|---|---|---|
| High and Critical alerts open (hero) | `high_critical_alerts` | Open alerts with risk High or Critical | Queue filtered to High + Critical, open, sorted by risk |
| "+N today" badge | `high_critical_today` | High/Critical findings alerted today | Queue for today, High + Critical |
| Risk mix bar under the hero | `by_risk` | Open alerts per risk level | Queue per level |
| Total alerts today | `total_alerts_today` | All findings alerted today | Queue for today |
| New phishing domains | `new_phishing_domains` | Today's alerts from Typosquat, MX and Active Phishing | Queue for today, those three modules |
| New impersonation accounts | `new_impersonation_accounts` | Today's Social alerts | Queue for today, Social |
| New rogue apps | `new_rogue_apps` | Today's Fake APK and Rogue App alerts | Queue for today, those two modules |
| Sensitive document exposures | `sensitive_document_exposures` | Today's Documents alerts | Queue for today, Documents |
| Phishing emails today | `phishing_emails_today` | Today's Phishing Email alerts | Queue for today, Email |
| Spoofed-sender attempts | `spoofed_sender_attempts` | Open High/Critical alerts from Email, Email Domain Security and DMARC | Queue filtered the same way |
| Open alerts | `open_alerts` | All open alerts ("Awaiting a decision") | Queue, open decisions |
| Candidates (new in SP2) | `candidates` | Candidates that never alerted ("Discovered, not yet analysed") | Findings page, stage Candidate |
| Findings below alert level (new in SP2) | `findings_below_alert_level` | Analysed findings that have not alerted ("Analysed, held back by the brand's alert level") | Findings page, stage Finding, not alerted |

The panels below the tiles:

| Panel | Data | Notes |
|---|---|---|
| New alerts, last 30 days | `/stats/trends`: one bar per day, stacked by risk level | Counts alert records by the day they were raised. Click a day to open that day's alerts. |
| Open alerts by risk | `by_risk` | Bar per level, click to filter. |
| Open alerts by module | `by_module` | Bar per module, including the three email modules (Phishing Email, Email Domain Security, DMARC) and Social Media Brand Misuse. |
| Alerted findings by decision | `by_status` | Every alerted finding, open or closed, per decision. Shows "No alerts yet" when all are zero. |

Every number on the dashboard is a link. Alert numbers open the alert queue with matching filters; the two new
tiles open the Findings page. This is how an analyst moves from "3 new phishing domains" to the three alerts
behind it.

## 6. Alert queue (`/alerts`)

The queue is the analyst's to-do list. It calls `GET /api/v1/alerts` with the current filters, 25 rows per
page by default (25, 50 or 100 can be chosen). It shows the **latest alert of each finding**, so a finding that
alerted three times appears once (the API option `history=true` returns every alert record). Candidates and
findings below the brand's "Alert from" level are never in this queue; they are on the Findings page.

### Columns

| Column | Shows |
|---|---|
| Risk | Risk badge with the finding's current score (0-100). The header sorts by highest risk. |
| (thumbnail) | The first screenshot of the finding, if one exists. |
| Finding | The finding title and its main identifier (domain, app, handle, post, document). A fish icon marks "Suspected Phishing". |
| Module | Which module found it. |
| Brand | Which brand it concerns. |
| Decision | The analyst's current decision on the finding. |
| First seen | When the finding was first discovered. "Newest" and "Oldest" sort by when the alert was raised. |
| Last seen | When a scan last saw the thing. Sortable. |

### Filters

All filters are stored in the page address. A filtered view can therefore be bookmarked or sent to a
colleague. The same filters are used by the exports, so an export always matches what is on screen.

| Filter | Query parameter | Requirement |
|---|---|---|
| Free-text search (title, domain, app, handle, brand name, and any output field) | `q` | DSH-16 |
| Brand (multi-select) | `brand_id` | DSH-11 |
| Module (multi-select, all eleven modules) | `module` | DSH-12 |
| Risk level (multi-select) | `risk_level` | DSH-13 |
| Decision (multi-select; the parameter keeps its old name) | `status` | DSH-15 |
| Alerted from / to (dates the alert was raised) | `date_from`, `date_to` | DSH-14 |
| Suspected phishing only (checkbox) | `suspected_phishing` | PHI-08 |
| Sort: newest, oldest, highest risk, recently seen | `sort` | - |

When nothing matches, the page says "No alerts match these filters" (with filters) or **"No threats
detected."** (without), with a pointer to start a scan if none has run and to check the Scans page for parts
that could not run. If the alert list cannot be loaded, the error panel is shown instead.

### Exports

Two buttons download the filtered list. Both are open to any signed-in user. Both are limited to 10,000 rows.

| Export | Endpoint | Content |
|---|---|---|
| CSV | `GET /api/v1/exports/alerts.csv` | Fixed columns (Alert ID, Finding ID, Scan ID, Brand, Module, Title, Risk Level, Score, Decision, Alert Trigger, Alert Reason, Alerted (UTC), Suspected Phishing, First Seen (UTC), Last Seen (UTC), Source URL) plus every module output field that appears in the exported alerts. UTF-8 with a byte-order mark, so Excel opens it correctly. Requirement DSH-18. |
| PDF | `GET /api/v1/exports/alerts.pdf` | A printable report made with WeasyPrint, with a "Decision / why alerted" column. Requirement DSH-19. Needs the Pango system libraries in the Docker image; without them the API answers "503 PDF export needs the system libraries in the Docker image". |

File names carry a time stamp, for example `alerts-20261009-1430.csv`.

## 7. Alert detail (`/alerts/[id]`)

The detail page calls `GET /api/v1/alerts/{id}`. One call returns the alert record, its finding, the finding's
evidence, observations, every alert raised for it, and the timeline (RDA-13). The layout:

```
+---------------------------------------------------------------------+
| Risk badge + score | Decision badge | Stage badge | "Suspected phishing" |
| Title                                                               |
| Module | Brand (link) | First seen | Last seen                      |
| [!] Suspicious source ... examp1ebank.com/login   [Open source]     |
+-------------------------------------------+-------------------------+
| Why this alert (trigger, reason, alerted, | Decision (buttons)      |
|   scan ID, finding ID)                    | Why this score          |
| Brand misuse (social media only)          | Alert history           |
| Evidence (gallery + file list)            | Timeline                |
| Module output (all fields)                |                         |
| Observations (one row per scan)           |                         |
+-------------------------------------------+-------------------------+
```

### "Why this alert"

The first panel says why this alert exists. It shows the **trigger**, the **reason** text, when it was alerted,
the scan ID and the finding ID. There are four triggers (`TRIGGER_LABELS` in `frontend/src/lib/constants.ts`):

| Trigger | Label on screen | Reason text, for example |
|---|---|---|
| `first_crossing` | First crossed the alert level | "First reached High (70)" |
| `change` | Changed materially | "Website went live; Login/payment form detected" |
| `reopen` | Reopened | "Official logo detected" (the finding had been closed by a decision) |
| `migrated` | Migrated from before findings | "Migrated from Phase 1" (alerts that existed before SP2, D-37) |

Old links keep working: the migration gave every Phase 1 alert a finding and an alert record with the same ID.

**Alert history** lists every alert raised for this finding, with trigger, reason and time, and marks the one
you are looking at. **Observations** is a table with one row per sighting: when, which scan (or upload),
stage, score and risk level at that moment.

For Social Media Brand Misuse alerts (Chapter 14), a **Brand misuse** panel shows the platform and content type,
"Fake contact details", "Scam wording" and "Official logo used" (or "None found."), the text excerpt, and an
"Open on <platform>" link.

### Header and the source warning

If the alert has a source URL, a red box warns: "Suspicious source. Open only in an isolated browser and never
enter credentials." The "Open source" button opens the link in a new tab without sending the dashboard
address (`noopener`, `noreferrer`). Treat this as a live attack site.

### Evidence gallery

Images (screenshots, favicons, matched images) are shown as a gallery. The first screenshot is shown large.
Click any image to enlarge it. Each image has its capture time.

Other evidence (HTML, metadata, SSL certificate, WHOIS, DNS, downloaded files) is listed below the gallery.
Each item shows its type, size, time and SHA-256 fingerprint. "Download" fetches the file. "Details" opens the
stored metadata as text. Evidence files live in the object store. The API gives the browser a short-lived
signed link (a **presigned URL**). Files are stored as downloads, so a hostile HTML or SVG file never opens
inside the browser (see `docs/guides/DEPLOYMENT.md`, security notes).

Identical evidence is stored only once per finding (decision D-21). A daily re-scan that sees the same
screenshot does not add a copy. A changed page adds a new item. Since SP2 each evidence item belongs to the
finding and records the observation (scan) that captured it.

### Module output

This panel lists every output field the module produced, in the order of the requirement tables. The field
lists are in `backend/app/modules/registry.py` (`OUTPUT_FIELDS`) and mirrored in
`frontend/src/lib/constants.ts`. Fields that are empty are hidden. Fields that the module added but that are
not in the list are shown after the listed ones. Examples:

| Module | Some of its fields |
|---|---|
| Typosquat / MX / Active Phishing | Domain, Similarity Score, MX Enabled, Website Live, SSL Present, Email Risk, Suspected Phishing, Registrar, Created, MX Records, A Records, Page Title, Favicon Match, Keywords Found, Brand Evidence On Page, Parked Page, Score Cap, Discovery Source |
| Fake APK | App Name, Package Name, Source, Logo Match, Version, Developer, SHA256, Signer SHA-256, Signer Matches Official |
| Rogue App | Store, App Name, Publisher, Official Publisher Match, Install Count, App Status, Store URL |
| Social | Platform, Username, Display Name, Followers, Profile URL, Bio Mentions Brand, Support Terms |
| Social Media Brand Misuse | Platform, Content Type, Title, Author, URL, Published, Views, Scam Contacts, Scam Phrases, Logo Match |
| Documents | Document Name, File Type, URL, Brand Match, Exposure Confidence, Sensitive Patterns, Hosted On Official Domain |
| Logo | Website, Page URL, Logo Match Score, Matched Image URL, Official Asset |
| Email | Subject, From, Sender IP, SPF, DKIM, DMARC, Rspamd, Malicious URLs, Attachments, Not Checked |

Each module's chapter explains its fields in full.

### "Why this score"

This panel explains the number. It shows:

- The score out of 100, with a marker on a bar split into the four bands: Low 0-29, Medium 30-59, High 60-79,
  Critical 80-100 (requirement RSK-09).
- One line per scoring rule that fired, with its points. Example for Example Bank:
  "Brand name appears exactly in the domain +40", "Domain can receive email (MX present) +15",
  "Serves HTTPS +10", "Login or payment keywords on the page +20".
- The rule total ("capped at 100" when it reached 100).
- When the final score differs from the total, a note: "Adjusted from X to Y to stay within the risk range this
  module can report." This happens because of module ranges (D-03) or score caps (D-29).

The rule names come from `alert.signals.rules`, written by `backend/app/core/scoring.py`. The readable labels
are in `RULE_LABELS` in `frontend/src/lib/constants.ts`. Chapter 02 explains every rule.

### Decision panel

The Decision panel ("Record what this finding is") shows one button per move that is allowed from the current
decision (section 12), for example "Start investigating", "Confirm threat", "False positive", "Legitimate",
"Ignore", "Resolve" or "Reopen". Choosing one opens a small dialog for the note ("What did you check? Why this
decision?"). For False Positive, Legitimate and Ignored the note is required ("A note is required so other
analysts know why."). For Legitimate on a domain, app, APK or social account finding, a checkbox **"Also add to
the brand allowlist"** appears. The page calls `POST /api/v1/alerts/{id}/status`, which sets the decision of the
alert's finding. If the move is not allowed or the note is missing, the API answers 409 with the reason and the
allowed list.

### Timeline

The Timeline panel ("Everything that happened to this finding, newest first") lists every event: who (a user
name, or "System"), when, the change (from, arrow, to) and the note. Event kinds (`finding_events.kind`):

| Event kind | Written when |
|---|---|
| `discovered` | A scan (or upload) saw the entity for the first time ("Finding found by phishing module, risk High (65)"). |
| `promoted` | A Candidate became a Finding ("Analysis found evidence (Candidate -> Finding)"). |
| `changed` | A comparable fact changed, for example "Website went live", or "Website no longer live". |
| `rescored` | A re-scan changed the risk **level** (for example "Risk Medium -> High (62)"). A score change inside the same level is not recorded. |
| `stage` | A domain finding moved forward: Typosquat -> MX -> Phishing (decision D-19). |
| `app_status` | A tracked Google Play app is no longer listed. |
| `alerted` | An alert was raised; the note is its reason. |
| `decision` | A person changed the decision, or the entity was added to the allowlist. |
| `reopened` | A closed decision went back to New: by a person, or automatically after a meaningful change. |

## 8. Findings (`/findings` and `/findings/[id]`)

The Findings page (new in SP2) lists **everything** the modules have stored: candidates, findings below the
alert level, and alerted findings. It calls `GET /api/v1/findings`, 25 rows per page by default.

| Column | Shows |
|---|---|
| (checkbox) | Select for a bulk decision; the header box selects the whole page |
| Risk, (thumbnail), Finding, Module, Brand | As in the alert queue |
| Stage | Candidate or Finding |
| Decision | The current decision |
| Alerts | How many alerts this finding raised and when the last one was, or "Not alerted" |
| First seen | When the entity was first discovered |

| Filter | Query parameter |
|---|---|
| Free-text search | `q` |
| Brand, Module, Risk (multi-select) | `brand_id`, `module`, `risk_level` |
| Stage: Candidate, Finding | `stage` |
| Decision | `decision` |
| Alerted or not / Alerted / Not alerted | `alerted` |
| Platform and content type (API only, for Social Media Brand Misuse, Chapter 14) | `platform`, `content_type` |
| Sort: newest, oldest, highest risk, recently seen | `sort` |

**Bulk decisions.** Select several rows and press **"Set decision..."**. Choose one decision and one note; the
same decision and note are applied to every selected finding (`POST /api/v1/findings/decision`, up to 500 at a
time). It is **all-or-nothing** (D-35): if any one finding cannot make that move (for example a Confirmed Threat
cannot go to False Positive), nothing is changed and the error names the finding that blocked it.

**Finding detail** (`/findings/[id]`, `GET /api/v1/findings/{id}`) shows the same panels as the alert detail page
(evidence, brand misuse for social media, module output, observations, why this score, decision, alert
history, timeline), without the "Why this alert" panel, because a finding may never have alerted. Decisions are saved with
`POST /api/v1/findings/{id}/decision`.

### Social Media page (`/social`)

The Social Media page (side menu "Social Media", `frontend/src/app/(app)/social/page.tsx`) is a view of the
Findings page made for social media (Chapter 14). It calls `GET /api/v1/findings` with the modules
`social_media` (brand misuse) and `social` (impersonation accounts, Chapter 06), 24 cards per page.

| Control | What it does |
|---|---|
| Platform tabs | All, YouTube, Facebook, Instagram, X, Threads, Meta Ads, Pinterest, TikTok, LinkedIn, Telegram (`platform`) |
| Type filter | All types, Videos, Posts, Ads, Channels and accounts (`content_type`) |
| Stage, Decision, Risk | The same filters as the Findings page |
| Search | "Search title, author, phone number..." (`q`), for example a WhatsApp number or UPI ID |
| Sort | Newest first, Highest risk, Recently seen, Oldest first |

Each **card** shows:

- the **stored screenshot** of the post, video or ad (served from the evidence store). Remote thumbnails on the
  platform are deliberately not loaded in the analyst's browser; a card without a captured screenshot shows a
  placeholder with the platform name;
- badges: content type, risk with score, stage and decision;
- title, author, publication date, views and likes;
- **"Fake contact details"** chips (phone, WhatsApp, Telegram, UPI; up to four, then "+N more"), a "Logo used"
  chip and the scam wording found;
- **"Open on <platform>"** (opens the original in a new tab without sending the dashboard address) and
  **Details** (the finding detail page, with the "Brand misuse" panel);
- the module and "first seen" date.

Impersonation accounts from the `social` module appear under "All types" and on their platform tab. They have
no Content Type field, so they disappear as soon as a content type is chosen.

## 9. Emails (`/emails` and `/emails/[id]`)

This page belongs to the phishing-email modules (decision D-28, Chapter 09).

**List and upload.** The "Analyse an email" panel takes a brand and a file (`.eml`, `.msg` or `.txt`, up to
25 MB). It calls `POST /api/v1/emails`. The API stores the raw message and queues the analysis in the
background. The list below calls `GET /api/v1/emails` with an optional brand and a search over subject and
sender. Columns: Verdict (risk), Sender, Subject, Channel (Upload, Mailbox, Microsoft 365, Google) and
Received. Empty state: "No emails analysed yet".

**Detail.** `GET /api/v1/emails/{id}` returns the email, its indicators and its finding. Uploaded and mailbox
emails go through the same finding engine as scans, with channel `upload` or `mailbox` and no scan ID; they
raise an alert only when the brand's "Alert from" level is reached. The page shows:

| Panel | Shows |
|---|---|
| Authentication | The receiving server's SPF/DKIM/DMARC result and the platform's own DMARC alignment re-check |
| Links | Every URL found, unwrapped, as plain text (never clickable), with each threat source's verdict |
| Attachments | Each attachment with ClamAV, YARA and macro results |
| Text preview | Plain text only; no HTML rendering and no remote images |
| Evidence, Why this score, Decision, Timeline | The same panels as on the alert detail page |

Tools that could not run (for example, no URLhaus key) are listed as "not checked". They score zero.

## 10. Brands (`/brands` and `/brands/[id]`)

A brand must be set up ("onboarded") before anything can be found for it. Only **admins** can add or change a
brand. Analysts can view brands and run scans.

### Adding a brand

"Add a brand" opens a form (`frontend/src/components/brand-form.tsx`). It calls `POST /api/v1/brands`.

| Field | Meaning | Example for Example Bank |
|---|---|---|
| Brand name | Unique name | Example Bank |
| Description | Free text for other analysts | Retail bank, India and UAE |
| Keywords | Words that identify the brand. Used to build look-alike domains and to search stores, social networks and documents. If empty, the brand name is used. | examplebank, example bank |
| Product terms | Product names that impersonators combine with the brand | ExamplePay, mobile banking |
| Monitoring active | When on, the daily schedule scans this brand | On |
| Alert from (new in SP2) | The lowest risk level that raises an alert: Low, Medium, High or Critical. Analysed findings below it are kept on the Findings page but do not enter the queue (D-34). Default Medium. | Medium |

Short abbreviations (for example "EB") only count together with other brand words or the logo (decision
D-25). Use distinctive keywords.

### The brand detail page

The detail page calls `GET /api/v1/brands/{id}` and `GET /api/v1/scans?brand_id=...`. It has these panels:

| Panel | Purpose | API |
|---|---|---|
| Monitoring settings | The same form as above, editable by admins | `PATCH /api/v1/brands/{id}` |
| Official assets | Upload the logo, favicon and app icon. Each image is fingerprinted (perceptual hash, and an mmh3 hash for favicons). Max 5 MB. | `POST` and `DELETE /api/v1/brands/{id}/assets` |
| Allowlists | Official things that must never raise an alert. Analysts can also add an entry by marking a finding Legitimate with "Also add to the brand allowlist" (section 12). | `POST` and `DELETE /api/v1/brands/{id}/allowlist` |
| Email security | Email Domain Security and DMARC alerts for this brand | `GET /api/v1/alerts?module=email_posture&module=dmarc` |
| Recent scans | This brand's scans, refreshed every 5 seconds while one runs | `GET /api/v1/scans` |
| Run scan now (button) | Start all modules, or chosen modules | `POST /api/v1/scans` |
| Delete brand (admins) | Removes the brand and, through the database cascade, its findings, observations, alerts, evidence records, scans and lists. You must type the brand name to confirm. | `DELETE /api/v1/brands/{id}` |

Asset kinds:

| Asset | Matched against |
|---|---|
| Logo | Images and screenshots on websites (Logo module, Active Phishing) |
| Favicon | Favicons of suspicious domains |
| App icon | App store and APK icons |

Allowlist kinds (`frontend/src/lib/constants.ts`, `ALLOW_KINDS`):

| Kind | Example | Effect |
|---|---|---|
| Official domains | `examplebank.com` | Never flagged; also the base for look-alike generation |
| Email domains | `mail.examplebank.com` | Treated as official senders and brand references |
| App packages | `com.examplebank.app` | Official app, never flagged |
| App publishers | Example Bank Ltd | Apps from this publisher are ignored |
| Social handles | `examplebank` or a profile URL | Official account, never flagged |
| App signing certificates (SHA-256) | 64 hex characters from Play Console | An APK signed with it is genuine (D-26) |

Without a logo, logo matching and favicon checks cannot work. The page says so: "Upload the logo, favicon and
app icon so logo-matching and favicon checks can work."

## 11. Scans (`/scans`) and Integrations (`/integrations`)

This page lists every scheduled and manual scan, newest first (up to 200). It calls `GET /api/v1/scans` and
polls every 5 seconds while any scan is queued or running. A brand selector filters the list. The same table
appears under "Recent scans" on each brand page.

| Column / detail | Meaning |
|---|---|
| Status | A badge with the scan state; hover it for the plain-English meaning (table below). When the row is closed, the first error line is shown next to it |
| Module, Brand, Trigger | Which module, which brand, and whether it was `schedule` or `manual` |
| Started, Duration | When it started and how long it ran |
| Findings / new / updated / errors | Counts from the scan's statistics |
| Expanded row | **"What this scan checked"**: the component checklist; then the error text, all statistics and the queued/finished times |

Scan states (D-31). The tooltip texts come from `SCAN_STATUS_HELP` in `frontend/src/lib/constants.ts`:

| Status | Plain-English meaning (tooltip) |
|---|---|
| Queued | Waiting for a worker. |
| Running | The scan is in progress. |
| Completed | Every part of the scan ran successfully. |
| Partially completed | The scan ran, but some sources were not configured or unavailable, so coverage was reduced. Results are real but incomplete. |
| Completed with errors | The scan ran, but some lookups or captures failed part-way. Results are real but incomplete. |
| Failed | The scan could not produce results. Nothing was checked, so this is not a clean result. |
| Cancelled | The scan was interrupted (worker restart or timeout). A newer scan replaces it. |

**What this scan checked.** Opening a row shows one line per component
(`frontend/src/components/scan-components.tsx`), for example:

```
 [ok]  DNS resolution                        Completed
       checked: 8912 - registered: 14
 [!]   Telegram API                          Not configured
       TELEGRAM_API_ID / TELEGRAM_API_HASH / TELEGRAM_SESSION not set
 [!]   Web search - DuckDuckGo (free, paced) Unavailable
       Free search (DuckDuckGo) is paused after being rate-limited ...
 [x]   WHOIS/RDAP                            Failed
       3 lookups failed (RDAP coverage/rate limits); registrar and dates shown as 'lookup failed'
```

Each line has an icon and a label: Completed (green tick), Skipped (grey), Not configured or Unavailable
(amber), Failed (red). Counts and the message are shown under the name. A component that made the whole scan
fail adds "- nothing could be checked". Chapter 01 lists the components of every module.

### Integrations page (`/integrations`)

This page answers "Which tools are set up, and did they work last time?" It calls `GET /api/v1/integrations`
(`backend/app/api/integrations.py`, `backend/app/core/integrations.py`) every 60 seconds. Every signed-in user
can see it; secrets are never shown.

Integrations are grouped by category: Discovery (web search, crt.sh, DNS resolvers, WHOIS/RDAP, Google Play,
Telegram search API, Telegram public pages), Social media (YouTube Data API, Meta Ad Library API, Threads
keyword search API, X API, Telegram post search; Chapter 14), Analysis (headless browser), Email analysis (Rspamd, ClamAV,
YARA), Threat intelligence (URLhaus, OpenPhish, urlscan.io, AbuseIPDB) and Email intake (reporting mailbox,
DMARC report mailbox, Microsoft 365, Gmail). Only integrations that exist in the code are listed.

| Column | Meaning |
|---|---|
| Integration | Its name. Web search includes the provider in use, for example "Web search - Brave Search API" |
| Used by | The modules that depend on it |
| Configured | "Yes", or "No" with how to configure it (for example "Set URLSCAN_API_KEY") |
| Last result | The status of the newest scan component for this integration (or, for the email tools, of the newest analysed email), with its time and message. "Not run yet" when there is no evidence yet - it is never assumed to be fine |

## 12. Analyst workflow and decisions

### The seven decisions

Since SP2 the analyst records a **decision** on the finding, not a status on the alert (D-35, requirements
DSH-10 and RDA-11). It replaces the five Phase 1 statuses (New, Under Review, Confirmed, False Positive,
Closed), which no longer exist. The rules live in `ALLOWED_TRANSITIONS` in `backend/app/core/findings.py` and are
mirrored in `TRANSITIONS` in `frontend/src/lib/constants.ts`.

| Decision | Meaning | Counts as open? | Note required? |
|---|---|---|---|
| New | Stored by a scan, nobody has decided yet | Yes | No |
| Investigating | An analyst is looking at it | Yes | No |
| Confirmed Threat | A real threat; action needed (for example a takedown request, done outside the platform) | Yes, until Resolved | No |
| False Positive | Not a threat; the detection was wrong | No | **Yes** |
| Legitimate | Real and harmless, for example a partner's site or the brand's own new domain | No | **Yes** |
| Ignored | Not worth acting on (for example a tiny fan page) | No | **Yes** |
| Resolved | A confirmed threat that has been dealt with (for example taken down) | No | No |

When the Phase 1 alerts were migrated (D-37), statuses were mapped: Under Review became Investigating,
Confirmed became Confirmed Threat, Closed became Resolved; New and False Positive kept their names.

### Allowed moves

| From | Can move to |
|---|---|
| New | Investigating, Confirmed Threat, False Positive, Legitimate, Ignored |
| Investigating | New, Confirmed Threat, False Positive, Legitimate, Ignored |
| Confirmed Threat | Investigating, Resolved |
| False Positive, Legitimate, Ignored | New (reopen), Investigating |
| Resolved | New (reopen), Investigating |

```
  scan stores the finding
          |
          v
       [New] <------------> [Investigating]
          |                      |
          |  (both can go to any of the four below)
          v                      v
  +------------------+  +----------------+  +------------+  +---------+
  | Confirmed Threat |  | False Positive |  | Legitimate |  | Ignored |
  +------------------+  +----------------+  +------------+  +---------+
       |        |               |                  |              |
       |        |               +--------+---------+--------------+
       |        v                        |
       |   [Resolved] ------------------>+--> New ("Reopened") or Investigating
       |
       +--> back to Investigating

  Automatic: a meaningful change on a False Positive, Legitimate, Ignored or
  Resolved finding moves it back to New ("reopened" event) and raises an alert.
```

Rules in plain words:

- New and Investigating can go to any decision except Resolved.
- Confirmed Threat can only go back to Investigating or forward to Resolved.
- A closed decision (False Positive, Legitimate, Ignored, Resolved) can be **reopened** to New, or moved to
  Investigating. "Reopened" is not a decision of its own; it is a timeline event.
- A note is required for False Positive, Legitimate and Ignored, so other analysts know why.
- Moving to the same decision is refused ("Finding is already ...").
- Every change stores who, when, from, to and the note on the finding (`decided_by`, `decided_at`,
  `decision_note`) and as a `decision` event on the timeline.
- Admins and analysts may both set decisions.

**Legitimate and the allowlist.** When marking a finding Legitimate, the analyst can tick "Also add to the brand
allowlist". The entity is then added to the brand's allowlist, so it is not detected again:

| Module | Allowlist kind | Value added |
|---|---|---|
| Typosquat, MX, Active Phishing | Official domains | The domain |
| Rogue App (Google Play), Fake APK | App packages | The package name |
| Social Media Impersonation | Social handles | The handle |

Documents, Logo, Email, Email Domain Security, DMARC and Social Media Brand Misuse findings have no matching
allowlist kind, so the checkbox is not offered for them.

### What scans do to a finding you already decided

A scan never creates a duplicate. It finds the existing finding for the same entity (the three domain modules
share one finding per domain, D-19) and:

1. stores a new **observation** (scan ID, score, risk level, signals, comparable facts);
2. compares the comparable facts with the previous ones and writes any change to the timeline;
3. updates the finding's title, score, signals, output fields and "Last seen", and stores any new evidence;
4. decides whether to raise an alert (D-36).

**Meaningful changes.** Only these count (`CHANGE_TEXT` in `backend/app/core/findings.py`):

| Change | Text on the timeline and in the alert reason |
|---|---|
| Website went from not live to live | "Website went live" |
| A login or payment form appeared | "Login/payment form detected" |
| The official logo appeared | "Official logo detected" |
| The domain gained a mail server | "Domain can now receive email" |
| An APK is signed by a non-official certificate | "APK signed by a non-official certificate" |
| A removed Google Play app is listed again | "App listed again" |
| A Candidate became a Finding | "Analysis found evidence (Candidate -> Finding)" |
| The risk level went up | "Risk Medium -> High (62)" |

Not meaningful (recorded on the timeline but never alerts): a score change inside the same level, a change of
title or text, a risk decrease, and anything turning off ("Website no longer live", "App no longer listed").
An **unknown** value (for example a screenshot that failed, so "live" is not known) is never compared, so a
failed capture never looks like "went offline" or "went live".

**When is an alert raised?** Only if the finding meets the alert rule (stage Finding, risk at or above the
brand's "Alert from" level). Then:

| Current decision | What happened in this scan | Result |
|---|---|---|
| New or Investigating | Never alerted, or did not meet the rule last time | Alert, trigger `first_crossing`, "First reached High (70)" |
| New or Investigating | Already alerted, and a meaningful change | Alert, trigger `change`, reason = the change(s) |
| Confirmed Threat | A meaningful change | Alert, trigger `change`; the decision stays Confirmed Threat |
| False Positive, Legitimate, Ignored, Resolved | A meaningful change | Decision back to **New**, `reopened` event, alert with trigger `reopen` |
| Any decision | No meaningful change | No alert; only the observation and "Last seen" are updated |
| Any decision | Rule not met (Candidate, or below "Alert from") | No alert |

**Example.** On Monday `examp1ebank.com` is found with a mail server but no website: Finding, risk Medium, alert
"First reached Medium (45)". The analyst marks it False Positive with the note "Parked by a domain reseller". On
Tuesday the re-scan sees the same facts: one observation, no alert, the decision stays False Positive. On
Wednesday a login page appears: the timeline gets "Website went live" and "Login/payment form detected", the
risk rises to High, the finding is reopened to New and a `reopen` alert appears at the top of the queue.

### A typical day for an analyst

1. Open the dashboard. Look at "High and Critical alerts open" and the "+N today" badge.
2. Click the number. The queue opens filtered to open High and Critical alerts, highest risk first.
3. Open the top alert. Read "Why this alert" (what triggered it) and "Why this score". Look at the screenshot,
   the module output and the timeline.
4. Set the decision to Investigating with a note, so colleagues know it is taken.
5. Decide: Confirmed Threat (real, act on it), False Positive (the detection was wrong), Legitimate (real but
   allowed) or Ignored (not worth acting on). Add a note with the reason.
6. If the finding is something official (for example, a new official domain of Example Bank), mark it
   Legitimate and tick "Also add to the brand allowlist", so it is not detected again.
7. When a confirmed threat has been taken down, mark it Resolved. If it comes back, the next scan reopens it.
8. Once a week, open the Findings page with "Not alerted" to check what was held back by the "Alert from"
   level, and use bulk decisions to clear obvious noise.
9. At the end of the week, export the Confirmed Threat alerts to PDF for the report.

## 13. The REST API

All endpoints are under `/api/v1`, except `/health`. Interactive documentation is at `/docs` (Swagger) and
`/redoc` on the API server, for example `http://localhost:8010/docs`. The OpenAPI file is also saved in
`docs/api/openapi.json`, and `docs/api/API-GUIDE.md` has examples.

"Any user" means any signed-in, active user (analyst or admin). "Admin" means role admin only; others get
403 "Admin role required".

| Method | Path | Purpose | Who |
|---|---|---|---|
| POST | `/api/v1/auth/login` | Sign in with email and password, receive a token | Anyone |
| GET | `/api/v1/auth/me` | Who am I | Any user |
| GET | `/api/v1/users` | List users | Admin |
| POST | `/api/v1/users` | Create a user (password at least 10 characters) | Admin |
| PATCH | `/api/v1/users/{user_id}` | Change name, password, role, active flag (not your own role or active flag) | Admin |
| GET | `/api/v1/brands` | List brands with open-alert counts | Any user |
| POST | `/api/v1/brands` | Create a brand (with optional allowlist) | Admin |
| GET | `/api/v1/brands/{brand_id}` | One brand with assets and allowlist | Any user |
| PATCH | `/api/v1/brands/{brand_id}` | Change a brand, including `alert_min_level` ("Alert from") | Admin |
| DELETE | `/api/v1/brands/{brand_id}` | Delete a brand and its data | Admin |
| POST | `/api/v1/brands/{brand_id}/assets` | Upload a logo, favicon or app icon (max 5 MB) | Admin |
| DELETE | `/api/v1/brands/{brand_id}/assets/{asset_id}` | Remove an asset | Admin |
| GET | `/api/v1/brands/{brand_id}/allowlist` | List allowlist entries | Any user |
| POST | `/api/v1/brands/{brand_id}/allowlist` | Add an allowlist entry | Admin |
| DELETE | `/api/v1/brands/{brand_id}/allowlist/{allow_id}` | Remove an allowlist entry | Admin |
| GET | `/api/v1/alerts` | Alert queue (latest alert per finding; `history=true` for every alert record) with filters, sort and pages (max 200 per page) | Any user |
| GET | `/api/v1/alerts/{alert_id}` | Alert record with its finding, evidence, observations, alert history and timeline | Any user |
| POST | `/api/v1/alerts/{alert_id}/status` | Kept for compatibility: sets the decision of the alert's finding (`status`, `note` up to 2,000 characters, `add_to_allowlist`) | Any user |
| GET | `/api/v1/alerts/{alert_id}/events` | The finding's timeline only | Any user |
| GET | `/api/v1/findings` | Findings and candidates with filters (brand, module, stage, decision, risk, alerted, platform, content type, search), sort and pages (max 200 per page) | Any user |
| GET | `/api/v1/findings/{finding_id}` | Finding with timeline, observations, evidence and alerts | Any user |
| POST | `/api/v1/findings/{finding_id}/decision` | Set the decision (`decision`, `note`, `add_to_allowlist`); 409 on a move that is not allowed or a missing note | Any user |
| POST | `/api/v1/findings/decision` | Bulk decision for up to 500 findings (`finding_ids`, `decision`, `note`); all-or-nothing | Any user |
| GET | `/api/v1/evidence/{evidence_id}` | One evidence item with a presigned download link | Any user |
| POST | `/api/v1/emails` | Upload an email file for analysis (form fields `brand_id`, `file`) | Any user |
| GET | `/api/v1/emails` | List analysed emails | Any user |
| GET | `/api/v1/emails/{email_id}` | Email detail with indicators and finding | Any user |
| POST | `/api/v1/scans` | Start a scan for a brand (all modules, or a list) | Any user |
| GET | `/api/v1/scans` | Scan history with per-component results (max 500) | Any user |
| GET | `/api/v1/integrations` | Every integration: configured or not, how to configure it, last result | Any user |
| GET | `/api/v1/stats/executive` | Dashboard numbers for one UTC day (`date`, default today), plus scan coverage (`last_completed_scan_at`, `components_unavailable`) | Any user |
| GET | `/api/v1/stats/trends` | Alert records raised per day by risk level (`days` 1-365, default 30) | Any user |
| GET | `/api/v1/exports/alerts.csv` | CSV of the filtered alert list | Any user |
| GET | `/api/v1/exports/alerts.pdf` | PDF of the filtered alert list | Any user |
| GET | `/health` | Database check: 200 "ok" or 503 "degraded" | Anyone (used by Docker) |

Every response carries an `x-request-id` header. An unexpected error returns
`{"detail": "Internal server error", "request_id": "..."}`. The request ID matches the line in the API log
(Chapter 12).

## 14. Known limitations of the dashboard

These are listed in full in Chapter 13. In short:

- Fixed in SP1 (2026-10-09, D-31): pages now show an error panel with Retry when the API fails; "No threats
  detected." appears only after a completed scan; "Open alerts by module" includes the email modules; the
  Integrations page shows which tools are set up; each scan lists its components.
- Fixed in SP2 (2026-10-09, D-33 to D-37): candidates and low findings no longer flood the queue; every scan
  leaves an observation and a timeline entry; seven analyst decisions with required notes, Legitimate to
  allowlist, bulk decisions; a decided finding stays quiet until a meaningful change reopens it.
- The Emails pages do not use the shared error panel yet.
- No confidence score, threat-intelligence matches or related findings on the alert yet (planned in SP3 and
  SP4); the page shows no placeholders for them.
- The Social Media page (`/social`) shows social media findings as a card grid with the stored screenshot only;
  remote thumbnails are deliberately not loaded, so a card without a captured screenshot shows a placeholder.
- Decisions on one finding do not yet influence the scoring of other findings (SP3/SP4).

## Key takeaways

- The dashboard only reads and changes data through the REST API under `/api/v1`. It detects nothing itself.
- "No threats detected." appears only after a scan has completed; failed API calls show an error panel with
  Retry, never a zero. The Scans page shows each scan's state and components, and the Integrations page shows
  every tool's configuration and last result.
- A result is a Candidate (discovered), a Finding (analysed, with evidence) or an Alert (the finding reached the
  brand's "Alert from" level, default Medium). Candidates never alert (D-33, D-34).
- Every dashboard number is a link into the alert queue or the Findings page. Queue filters live in the address
  and are reused by the CSV and PDF exports.
- The alert detail page shows why the alert was raised, evidence, every module output field, "Why this score",
  observations per scan and the full timeline in one place.
- Seven decisions (D-35): New, Investigating, Confirmed Threat, False Positive, Legitimate, Ignored, Resolved.
  A note is required for False Positive, Legitimate and Ignored; Legitimate can add to the allowlist; bulk
  decisions are all-or-nothing.
- A re-scan adds an observation. It raises a new alert only on first crossing or a meaningful change (went live,
  login form, logo, MX, APK signer mismatch, app listed again, Candidate to Finding, risk up); a closed decision
  is then reopened (D-36).
- Admins manage brands, assets, allowlists and users. Analysts review alerts and findings, record decisions, run
  scans, upload emails and export.
- The frontend uses Next.js, TanStack Query, Tailwind CSS and shadcn/ui for clear routing, reliable data
  loading, and accessible components the team can change freely.
