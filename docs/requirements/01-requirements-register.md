# Requirements Register & Traceability Matrix

Every requirement from `00-source-requirements.md` has an ID here. Each ID is traced
to its design section, implementing code, automated test and UAT result. The final
Test/UAT Report is generated from this table, so a requirement cannot be silently dropped.

**Status values:** `Open` → `Designed` → `Built` → `Tested` → `Accepted` (or `Deferred` with a reason
approved by the project owner).

**Live status of every ID** (pass/fail, which test proves it) is in `docs/reports/UAT-REPORT.md`, generated
from the automated test run by `backend/scripts/uat_report.py`. The Status column below is updated by the same script; "Accepted" is set by the project owner at UAT sign-off.

## A. Platform objectives (§1, §11)

| ID | Requirement | Source | Status |
|---|---|---|---|
| OBJ-01 | Continuously discover and monitor suspicious domains related to client brands | §1 | Tested ✅ |
| OBJ-02 | Detect phishing infrastructure and active phishing campaigns | §1 | Tested ✅ |
| OBJ-03 | Identify fake or unauthorized mobile applications | §1 | Tested ✅ |
| OBJ-04 | Monitor social platforms for impersonation accounts and fraudulent activity | §1 | Tested ✅ |
| OBJ-05 | Detect exposure of sensitive documents related to monitored brands | §1 | Tested ✅ |
| OBJ-06 | Identify unauthorized use of brand logos across websites | §1 | Tested ✅ |
| OBJ-07 | Generate alerts, dashboards and evidence for analyst review | §1 | Tested ✅ |
| OBJ-08 | Production-ready for internal analyst use at end of Phase 1 | §1 | Verified ✅ |
| OUT-01 | Analyst can add a new brand with official assets | §11 | Tested ✅ |
| OUT-02 | Analyst can prioritize incidents with a consistent risk scoring model | §11 | Tested ✅ |

## B. Out of scope — must NOT be built in Phase 1 (§2)

| ID | Excluded item |
|---|---|
| OOS-01 | Automated takedown filing |
| OOS-02 | AI-based phishing content classification |
| OOS-03 | Mobile app reverse engineering (metadata/icon extraction from the manifest only) |
| OOS-04 | Dark web crawling infrastructure |
| OOS-05 | Multi-tenant customer portal |

## C. Phishing / Typosquat monitoring (§3.1) — Priority: Critical

| ID | Requirement | Status |
|---|---|---|
| TYP-01 | Generate variants by character omission | Tested ✅ |
| TYP-02 | Generate variants by character substitution | Tested ✅ |
| TYP-03 | Generate variants by transposition | Tested ✅ |
| TYP-04 | Generate variants by homoglyphs | Tested ✅ |
| TYP-05 | Generate variants by added prefixes/suffixes | Tested ✅ |
| TYP-06 | Generate variants by character insertion (dev plan) | Tested ✅ |
| TYP-07 | Generate TLD variations (dev plan) | Tested ✅ |
| TYP-08 | Support .com, .in, .net, .org, .co and country TLDs | Tested ✅ |
| TYP-09 | Monitor newly registered domains against generated variants | Tested ✅ |
| TYP-10 | WHOIS lookup for suspicious domains | Tested ✅ |
| TYP-11 | DNS lookup for suspicious domains | Tested ✅ |
| TYP-12 | Daily discovery of suspicious domains | Tested ✅ |
| TYP-13 | Similarity score 0–100 per domain | Tested ✅ |

## D. MX record monitoring (§3.1) — Priority: High

| ID | Requirement | Status |
|---|---|---|
| MX-01 | Resolve MX records for suspicious domains | Tested ✅ |
| MX-02 | Store MX records | Tested ✅ |
| MX-03 | Flag domains configured for email delivery (MX Enabled Yes/No) | Tested ✅ |
| MX-04 | MX risk tiers: No MX = Low, MX = Medium, MX + active website = High (see CONFLICT-02) | Tested ✅ |

## E. Active phishing domain detection (§3.1) — Priority: Critical

| ID | Requirement | Status |
|---|---|---|
| PHI-01 | Check for active HTTP/HTTPS response (Website Live Yes/No) | Tested ✅ |
| PHI-02 | Capture page title | Tested ✅ |
| PHI-03 | Capture favicon hash | Tested ✅ |
| PHI-04 | Capture screenshot | Tested ✅ |
| PHI-05 | Capture SSL certificate details (SSL Present Yes/No) | Tested ✅ |
| PHI-06 | Compare favicon hash with legitimate brand favicon | Tested ✅ |
| PHI-07 | Detect keywords: login, secure, account, verify, payment, etc. | Tested ✅ |
| PHI-08 | Mark domain "Suspected Phishing" when similarity exceeds threshold (see GAP-01) | Tested ✅ |
| PHI-09 | Output: Domain, Similarity, MX Enabled, Website Live, SSL Present, Screenshot, Risk Level (L/M/H/C) | Tested ✅ |

## F. Fake APK monitoring (§3.2) — Priority: High

| ID | Requirement | Status |
|---|---|---|
| APK-01 | Search public APK repositories and indexed APK sources | Tested ✅ |
| APK-02 | Match package names against official package list | Tested ✅ |
| APK-03 | Detect similar app names | Tested ✅ |
| APK-04 | Detect similar package identifiers | Tested ✅ |
| APK-05 | Detect reused icons/logos | Tested ✅ |
| APK-06 | Detect suspicious developer names | Tested ✅ |
| APK-07 | Extract app name, package name, version, developer, download source, SHA256 (if available) | Tested ✅ |
| APK-08 | Output: App Name, Package, Similarity, Source URL, Logo Match, Risk Level (M/H) | Tested ✅ |
| APK-09 | Fake APK inventory with evidence | Tested ✅ |

## G. Rogue mobile app monitoring (§3.3) — Priority: High

| ID | Requirement | Status |
|---|---|---|
| ROG-01 | Monitor Google Play search results for brand keywords | Tested ✅ |
| ROG-02 | Monitor other public app stores (dev plan; see GAP-07) — Apple App Store added 2026-10-12 (D-41); APK stores in D-40 | Tested ✅ |
| ROG-03 | Compare publisher with approved publisher list | Tested ✅ |
| ROG-04 | Flag apps using brand name, logo or product terminology without authorization | Tested ✅ |
| ROG-05 | Track app status changes: new, removed, updated | Tested ✅ |
| ROG-06 | Output: Store, App Name, Publisher, Official Publisher Match, Install Count, Risk Level (M/H) | Tested ✅ |

## H. Social media impersonation (§3.4) — Priority: High

| ID | Requirement | Status |
|---|---|---|
| SOC-01 | Platform: X (Twitter) | Tested ✅ |
| SOC-02 | Platform: Facebook | Tested ✅ |
| SOC-03 | Platform: Instagram | Tested ✅ |
| SOC-04 | Platform: LinkedIn | Tested ✅ |
| SOC-05 | Platform: Telegram public channels/usernames | Tested ✅ |
| SOC-06 | Username similarity | Tested ✅ |
| SOC-07 | Display name similarity | Tested ✅ |
| SOC-08 | Profile image/logo similarity | Tested ✅ |
| SOC-09 | Bio/description contains brand name | Tested ✅ |
| SOC-10 | Uses official support/contact terminology | Tested ✅ |
| SOC-11 | Output: Platform, Username, Display Name, Similarity, Logo Match, Followers, Risk Level (L/M/H) | Tested ✅ |
| SOC-12 | Impersonation dashboard with screenshots (dev plan) | Tested ✅ |

## I. Sensitive document monitoring (§3.5) — Priority: Medium

| ID | Requirement | Status |
|---|---|---|
| DOC-01 | Source: search-engine-indexed documents | Tested ✅ |
| DOC-02 | Source: public file-sharing links | Tested ✅ |
| DOC-03 | Source: exposed PDF/DOC/XLS/PPT accessible without authentication | Tested ✅ |
| DOC-04 | Brand keyword match | Tested ✅ |
| DOC-05 | Domain match | Tested ✅ |
| DOC-06 | Email address pattern match | Tested ✅ |
| DOC-07 | Filename pattern analysis (confidential, internal, salary, customer, …) | Tested ✅ |
| DOC-08 | Output: Document Name, File Type, URL, Brand Match, Exposure Confidence (L/M/H), Risk Level (M/H/C) | Tested ✅ |

## J. Brand logo on websites (§3.6) — Priority: Medium

| ID | Requirement | Status |
|---|---|---|
| LOGO-01 | Crawl discovered suspicious domains and websites | Tested ✅ |
| LOGO-02 | Extract images from pages | Tested ✅ |
| LOGO-03 | Compute perceptual hash (pHash) | Tested ✅ |
| LOGO-04 | Match against stored official brand logos | Tested ✅ |
| LOGO-05 | Capture screenshot evidence when matched | Tested ✅ |
| LOGO-06 | Output: Website, Page URL, Logo Match Score 0–100, Screenshot, Risk Level (M/H) | Tested ✅ |

## K. Dashboard, workflow, export (§4, dev plan) — Priority: Critical

| ID | Requirement | Status |
|---|---|---|
| DSH-01 | Executive: total alerts today | Tested ✅ |
| DSH-02 | Executive: High/Critical alerts | Tested ✅ |
| DSH-03 | Executive: new phishing domains | Tested ✅ |
| DSH-04 | Executive: new impersonation accounts | Tested ✅ |
| DSH-05 | Executive: new rogue apps | Tested ✅ |
| DSH-06 | Executive: sensitive document exposures | Tested ✅ |
| DSH-07 | Analyst: alert queue | Tested ✅ |
| DSH-08 | Analyst: evidence screenshots | Tested ✅ |
| DSH-09 | Analyst: risk score | Tested ✅ |
| DSH-10 | Status tracking: New, Under Review, Confirmed, False Positive, Closed (see CONFLICT-03) | Tested ✅ |
| DSH-11 | Filter: brand name | Tested ✅ |
| DSH-12 | Filter: module type | Tested ✅ |
| DSH-13 | Filter: risk level | Tested ✅ |
| DSH-14 | Filter: date range | Tested ✅ |
| DSH-15 | Filter: status | Tested ✅ |
| DSH-16 | Search | Tested ✅ |
| DSH-17 | Dashboard charts | Tested ✅ |
| DSH-18 | Export CSV | Tested ✅ |
| DSH-19 | Export PDF | Tested ✅ |
| DSH-20 | Responsive layout | Verified ✅ |
| DSH-21 | Displays alerts from all modules | Tested ✅ |

## L. Risk scoring (§6)

| ID | Requirement | Status |
|---|---|---|
| RSK-01 | Brand exact match in domain +40 | Tested ✅ |
| RSK-02 | Typosquat similarity > 80% +25 | Tested ✅ |
| RSK-03 | MX present +15 | Tested ✅ |
| RSK-04 | HTTPS enabled +10 | Tested ✅ |
| RSK-05 | Login/payment keywords +20 | Tested ✅ |
| RSK-06 | Official logo detected +30 | Tested ✅ |
| RSK-07 | Social profile image matches logo +20 | Tested ✅ |
| RSK-08 | Official publisher mismatch +25 | Tested ✅ |
| RSK-09 | Levels: 0–29 Low, 30–59 Medium, 60–79 High, 80+ Critical | Tested ✅ |
| RSK-10 | Score capped at 100 (0–100 scales used throughout) | Tested ✅ |

## M. Foundation & platform (§5, §7, §8)

| ID | Requirement | Status |
|---|---|---|
| FND-01 | Repository setup | Verified ✅ |
| FND-02 | Database schema finalized + migrations | Verified ✅ |
| FND-03 | Authentication for internal analysts | Tested ✅ |
| FND-04 | Brand configuration module (onboarding) | Tested ✅ |
| FND-05 | Official logo upload | Tested ✅ |
| FND-06 | Whitelists: official domains, packages, publishers | Tested ✅ |
| FND-07 | Scheduler framework (Celery) with retries | Tested ✅ |
| FND-08 | REST APIs for the dashboard | Tested ✅ |
| FND-09 | PostgreSQL + Redis | Verified ✅ |
| FND-10 | Object storage for screenshots and evidence | Verified ✅ |
| FND-11 | Playwright headless browser for screenshots | Tested ✅ |
| FND-12 | Evidence collection: screenshots, metadata, logs | Tested ✅ |
| FND-13 | Logging and error handling | Tested ✅ |
| FND-14 | Performance optimization | Verified ✅ |
| FND-15 | Deployment to staging/production | Tested ✅ |

## N. Acceptance criteria (§9) — must pass by end of Phase 1

| ID | Acceptance criterion | Status |
|---|---|---|
| AC-01 | Typosquat: detects generated variants for configured brand | Tested ✅ |
| AC-02 | MX: resolves and stores MX records | Tested ✅ |
| AC-03 | Active phishing: screenshot + risk score for live suspicious domain | Tested ✅ |
| AC-04 | Fake APK: detects at least one simulated fake APK entry | Tested ✅ |
| AC-05 | Rogue app: detects unauthorized listing by keyword | Tested ✅ |
| AC-06 | Social: detects simulated fake social account | Tested ✅ |
| AC-07 | Documents: detects indexed document containing brand keyword | Tested ✅ |
| AC-08 | Logo: detects official logo on a test website | Tested ✅ |
| AC-09 | Dashboard displays alerts from all modules | Tested ✅ |
| AC-10 | Analyst can change alert status | Tested ✅ |

## O. Final deliverables (§10)

| ID | Deliverable | Status |
|---|---|---|
| DEL-01 | Operational web application | Verified ✅ |
| DEL-02 | Source code repository | Verified ✅ |
| DEL-03 | Database schema & migration scripts | Verified ✅ |
| DEL-04 | API documentation | Tested ✅ |
| DEL-05 | Deployment guide | Verified ✅ |
| DEL-06 | Configuration guide for new brands | Verified ✅ |
| DEL-07 | Test report / UAT report | Verified ✅ |
| DEL-08 | Sample monitoring data for demonstration | Verified ✅ |

---

## Conflicts and gaps found in the source requirements

All resolved on 2026-10-06 (owner delegated choices). Rationale for each is in `docs/decisions/DECISION-LOG.md`.

| ID | Issue | Resolution |
|---|---|---|
| CONFLICT-01 | Project folder is named "15 day" but the requirements specify 30 days | **15 days** (owner) — D-01 |
| CONFLICT-02 | §3.1 MX tiers (No MX = Low, MX = Medium, MX + live = High) disagree with §6 points (MX = +15 only) | Use §6 points for Risk Level; show MX tier as its own field "Email Risk" — D-02 |
| CONFLICT-03 | §4 has 5 statuses (incl. False Positive); dev plan shows 4 | Use all 5 — D-07 |
| CONFLICT-04 | Per-module risk ranges (APK/Rogue/Logo: M/H only; Social: L/M/H; Docs: M/H/C) differ from the global 4-level model | Compute global score, then clamp to each module's allowed range — D-03 |
| CONFLICT-05 | Social image match +20 overlaps with "official logo detected" +30 | Social uses +20 only; +30 is for websites/APK icons |
| GAP-01 | "Suspected Phishing" threshold not defined | Similarity ≥ 80 AND site live AND (keywords OR favicon match OR logo found) — D-04 |
| GAP-02 | No scoring rules for documents (filename, email patterns) | Document rules added — D-06 |
| GAP-03 | "Typosquat similarity > 80%" — is exactly 80 included? | Strictly greater than 80 — D-05 |
| GAP-04 | Can exact-match (+40) and typo-similarity (+25) both apply? | Yes, both apply — D-05 |
| GAP-05 | Source of newly registered domains not specified | Daily DNS resolution of all variants + Certificate Transparency search (crt.sh), both free; paid feed pluggable — D-11 |
| GAP-06 | Social platforms (FB/IG/LinkedIn/X) restrict automated search | Telegram live + search-API discovery + simulated — D-10 |
| GAP-07 | "Other public app stores" not named | Google Play only, unless owner names others — D-13 |
| GAP-08 | Alert notifications (email/Slack) not mentioned beyond dashboard | Dashboard only unless owner asks — D-14 |
| GAP-09 | Analyst roles/permissions not specified | Two roles: Admin, Analyst — D-15 |

## P. Phishing email monitoring (Phase-1.5, D-28) — spec `docs/superpowers/specs/2026-10-08-phishing-email-design.md`

| ID | Requirement | Status |
|---|---|---|
| EML-01 | Parse uploaded .eml/.msg emails (headers, bodies, attachments) | Tested ✅ |
| EML-02 | Extract and unwrap URLs (Safe Links, Proofpoint, Google, hxxp/[.]) | Tested ✅ |
| EML-03 | Analyse the attached original of a forwarded report | Tested ✅ |
| EML-04 | Read SPF/DKIM/DMARC from Authentication-Results | Tested ✅ |
| EML-05 | Independent DMARC alignment evaluation | Tested ✅ |
| EML-06 | Rspamd spam/phishing scoring | Tested ✅ |
| EML-07 | ClamAV attachment malware scan | Tested ✅ |
| EML-08 | YARA phishing/malware pattern rules | Tested ✅ |
| EML-09 | Threat intel: URLhaus, OpenPhish, urlscan.io, AbuseIPDB (cached, corroborated) | Tested ✅ |
| EML-10 | Deterministic risk scoring with the 2-source corroboration rule | Tested ✅ |
| EML-11 | Official DMARC-pass senders are never scored as impersonation | Tested ✅ |
| EML-12 | Email scoring rules in the shared model | Tested ✅ |
| EML-13 | Upload API, storage of raw .eml, dedupe | Tested ✅ |
| EML-14 | Email alert with evidence and the module's output fields | Tested ✅ |
| EML-15 | Brand domain email posture (SPF/DMARC/DKIM/MTA-STS) | Tested ✅ |
| EML-16 | Detect duplicate/invalid/`p=none` DMARC and permissive SPF | Tested ✅ |
| EML-17 | Look-alike domains flagged when email-ready (SPF present) | Tested ✅ |
| EML-18 | DMARC aggregate report parsing (xml/gz/zip, XML-bomb safe) | Tested ✅ |
| EML-19 | IMAP reporting-mailbox intake | Tested ✅ |
| EML-20 | Dashboard: emails page, email alert view, email-security panel | Verified ✅ |

## Q. Real data, accuracy and explainability (owner addendum 2026-10-09) — roadmap sub-projects SP1–SP5

| ID | Requirement | Source | Sub-project | Status |
|---|---|---|---|---|
| RDA-01 | Dashboard and APIs show only real scan results / DB records — no demo, mock or fallback findings, statistics, screenshots or responses | §1, §18 | SP1 | Tested ✅ |
| RDA-02 | Empty state "No threats detected." when there are no findings; zero shows as zero | §1, §18 | SP1 | Tested ✅ |
| RDA-03 | An unconfigured, rate-limited, unavailable or failed integration is shown with its status and error, never as "no threats found"; other scanners continue | §1, §21 | SP1 | Tested ✅ |
| RDA-04 | Test data stays inside test code; never seeds or appears in the application; the app works with an empty database | §2 | SP1 | Tested ✅ |
| RDA-05 | Inspect the existing implementation first; enhance existing features instead of duplicating them | §3, §4 | all | Open |
| RDA-06 | Quality review and improvement of every existing scanner | §5 | SP5 | Open |
| RDA-07 | Multi-signal detection for domains/websites (domain, DNS/infrastructure, website, threat-intel, visual signals) | §6, §7 | SP3 | Open |
| RDA-08 | Separate Risk Score and Confidence Score | §8 | SP3 | Open |
| RDA-09 | Every score explained with reasons traceable to real evidence | §9 | SP3 | Open |
| RDA-10 | False-positive reduction: independent signals, source reliability, history, allowlists, analyst decisions | §10 | SP2, SP3 | Open |
| RDA-11 | Analyst decisions Confirmed Threat, False Positive, Legitimate, Ignored, Investigating, Reopened — preserved and used as context | §10 | SP2 | Tested ✅ |
| RDA-12 | Candidate → Finding → Alert separation; alerts only when criteria are met | §11 | SP2 | Tested ✅ |
| RDA-13 | Alert carries the minimum actionable information (IDs, brand, threat type, target, risk, confidence, severity, times, reasons, evidence, source, indicators, TI matches, related findings, scan ID, status) | §12 | SP2, SP3, SP4 | Partial (SP2 part done) |
| RDA-14 | No double counting: one finding per entity across sources; multiple sources raise confidence, not risk | §13 | SP3, SP4 | Open |
| RDA-15 | Rescan: match entity, store observation, update last_seen, diff state, recalculate, timeline, alert only on meaningful change or threshold crossing | §14 | SP2 | Tested ✅ |
| RDA-16 | Cross-module correlation into campaigns; correlation raises confidence | §13, §15 | SP4 | Open |
| RDA-17 | Real scan states (queued, running, completed, completed_with_errors, partially_completed, failed, cancelled) with per-component status | §16 | SP1 | Tested ✅ |
| RDA-18 | Evidence preserved and linked to the right finding (HTTP headers, redirect chain, IP/ASN, TI responses, APK permissions/URLs, document metadata, scan logs) | §17 | SP3, SP5 | Partial (SP2 part done) |
| RDA-19 | Frontend shows an error state when the backend fails and an empty state when it returns nothing — no fake fallbacks | §19 | SP1 | Open |
| RDA-20 | Scanner lifecycle (discovery → validation → normalization → dedup → analysis → evidence → risk → confidence → correlation → persistence → alert decision → workflow) with structured evidence | §20 | SP2–SP5 | Partial (SP2 part done) |
| RDA-21 | Tool failures captured and recorded; never fabricated, never marked successful, never turned into findings | §21 | SP1 | Tested ✅ |
| RDA-22 | Implementation priority and final rule (prefer "no threat detected" / "unable to scan" / "insufficient evidence" over overstated results) | §22, §23 | all | Tested ✅ |
| RDA-23 | Beginner-friendly handbook: one folder per module, tools and reasons, gaps, end-to-end process, PDF-ready | addendum | docs | Verified ✅ |

## R. Social media brand-misuse monitor (owner request 2026-10-09) — spec `docs/superpowers/specs/2026-10-09-social-media-monitor-design.md`

| ID | Requirement | Source | Status |
|---|---|---|---|
| SMM-01 | One Social Media section showing posts, videos, ads, channels and accounts that misuse the brand, each with a screenshot and a link | owner 2026-10-09 | Tested ✅ |
| SMM-02 | Platforms: YouTube, Facebook, Instagram, X, Threads, Meta ads, Pinterest, TikTok, LinkedIn, Telegram (official API when a key is configured, web search otherwise) | owner 2026-10-09 | Tested ✅ |
| SMM-03 | Detect fake contact details (phone, WhatsApp, Telegram, UPI) and scam wording next to the brand | owner 2026-10-09 | Tested ✅ |
| SMM-04 | Skip the brand's own accounts/channels (allowlist) and content that does not reference the brand | owner 2026-10-09 | Tested ✅ |
| SMM-05 | A source without a key is reported "not configured", never "nothing found" (D-31) | owner 2026-10-09 | Tested ✅ |
| SMM-06 | Video evidence = link + thumbnail + screenshot; no video download | owner 2026-10-09 | Tested ✅ |
| SMM-07 | Apify (optional, `APIFY_TOKEN`) for Instagram, TikTok, Facebook posts, Meta ads, X and LinkedIn content and impersonation profiles, next to the official APIs and web search; YouTube keeps its API (D-43) | owner 2026-10-14 | Tested ✅ |
