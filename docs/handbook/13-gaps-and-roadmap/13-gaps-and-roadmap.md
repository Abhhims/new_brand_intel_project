# Chapter 13 - Gaps and Roadmap

In this chapter:
- An honest list of what the platform does not do yet, based on the audit of 2026-10-09 and checked against the code.
- Why each gap matters, with a small Example Bank story where it helps.
- The approved roadmap of 2026-10-09: five sub-projects, in order, with what each one fixes and which requirements it covers.
- What sub-project 1 (SP1, honest scan status) and sub-project 2 (SP2, the finding model) fixed on 2026-10-09,
  what the new social media brand-misuse monitor added the same day, and what is still planned (SP3 to SP5).
- Where to follow progress.

## 1. Plain words first

A **gap** is something the platform should do but does not do yet, or does in a way that can mislead. Gaps are
not hidden bugs. They are known, written down and planned.

On 2026-10-09 the project owner added a set of requirements about real data, accuracy and explainability.
They are in `docs/requirements/01-requirements-register.md`, section Q, with IDs **RDA-01 to RDA-23**. The
same day an audit compared the code with them. This chapter lists what the audit found. All RDA requirements
were "Open" on that date. **SP1 was completed the same day (2026-10-09)**: RDA-01, RDA-02, RDA-03, RDA-04,
RDA-17, RDA-19 and RDA-21 are now tested, and the gaps it fixed are marked **DONE (2026-10-09)** below. The
**SP2 was completed the same day too**: RDA-11, RDA-12 and RDA-15 are tested, and RDA-13, RDA-18 and RDA-20
are partly done (the rest belongs to SP3 to SP5). Its gaps are also marked **DONE (2026-10-09)**. The social
media brand-misuse monitor (D-38, Chapter 14) was added outside the roadmap on the owner's request. The other
gaps are still planned.

A few terms used below:

| Term | Meaning |
|---|---|
| Risk | How bad it would be if this thing is a real attack (impact). Today the score 0-100 is a risk score. |
| Confidence | How sure we are that the detection is correct (evidence quality). Not measured today. |
| Candidate | Something a scanner noticed that may or may not matter, for example a registered look-alike domain with no website and no mail server. Exists since SP2. |
| Finding | A candidate that was checked and has real evidence. |
| Alert | Raised when a finding meets the criteria for an analyst to act on (since SP2: stage Finding and risk at or above the brand's "Alert from" level). |
| Observation | One record of what a scan saw at one moment, kept as history. |
| Correlation | Linking separate findings that share something, for example the same IP address. |
| Campaign | A group of correlated findings run by the same attacker. |

## 2. What is missing today

Each gap below lists what happens today, where in the code, and why it matters. Gaps marked **DONE
(2026-10-09)** were fixed by SP1 or SP2; their "before" description is kept so the change is clear.

### 2.1 No confidence score separate from risk - DONE (2026-10-16, D-47)

Since 2026-10-16 every finding has a **Confidence** score (0-100, Low/Medium/High) next to its risk, built from
named factors (independent kinds of evidence, direct capture, unknowns, contradictions) and shown in the score
panel; lists can be sorted by "Most certain" (Chapter 02, section 12a). Still open: calibration against analyst
decisions. The text below describes the situation before.

| Today | Where |
|---|---|
| Every finding has one number, the risk score, built from the points table. Nothing says how reliable the evidence is. The only "confidence" field is the Documents module's **Exposure Confidence** (Low/Medium/High, D-06), which is an output field, not a score. | `backend/app/core/scoring.py`, `backend/app/db/models.py` (`Finding.score`) |

**Why it matters.** A Critical alert built on four strong, independent facts and a Critical alert built on
weak or guessed facts look the same. Analysts cannot sort by "how sure are we". Requirement RDA-08.

### 2.2 No candidate, finding and alert separation - DONE (2026-10-09)

| Before SP2 | Since SP2 (2026-10-09) | Where |
|---|---|---|
| Every result a module yielded went straight to `upsert_finding` (in `backend/app/core/alerts.py`, now removed) and became an alert, usually with status New. Low-value results (for example a registered look-alike domain with no website and no mail server) sat in the queue next to real attacks. | Every result is stored as a **finding** in stage **Candidate** (discovered, weak) or **Finding** (analysed, with evidence); each module decides through `Detection.analysed` (D-33). An **alert** record is raised only for a Finding at or above the brand's "Alert from" level, default Medium (D-34). Candidates and findings below that level are on the new Findings page, not in the queue. | `backend/app/core/findings.py` (`record_detection`, `meets_rule`), `backend/app/modules/*/module.py`, `frontend/src/app/(app)/findings/` |

**Why it mattered.** The queue filled with Low alerts that needed no action. Requirements RDA-12 (tested) and
RDA-20 (SP2 part done).

### 2.3 Rescans overwrite the alert; little history - DONE (2026-10-09)

| Before SP2 | Since SP2 (2026-10-09) | Where |
|---|---|---|
| A rescan overwrote the existing alert. The activity timeline only recorded a change of risk level, a stage change and reopening. There was no per-scan observation table and no change detection: nothing said "a login form appeared on `examp1ebank.com` today". | Every sighting stores an **observation** (scan ID, stage, score, level, signals, comparable facts). The engine compares facts with the previous observation and writes **meaningful changes** to the finding's timeline: website went live, login/payment form, official logo, MX added, APK signed by a non-official certificate, app listed again, Candidate to Finding, risk level up (D-36). A new alert is raised on the first crossing of the rule or on a meaningful change; an unchanged re-scan only updates "last seen". Unknown values (failed capture) are never compared. Evidence is linked to the finding and to the observation that captured it. | `backend/app/core/findings.py` (`derive_state`, `diff_state`, `CHANGE_TEXT`), `backend/app/db/models.py` (`Observation`, `FindingEvent`, `Alert`) |

**Why it mattered.** Example: `examp1ebank.com` was parked for weeks, then showed an Example Bank login form.
Its score rose but stayed High, so before SP2 no event was written. Now the timeline says "Website went live"
and "Login/payment form detected" and a new alert explains why. Requirement RDA-15 (tested).

**Still open.** Changes of text or title are not tracked as changes. Score changes inside one level are kept in
the observations but not shown as timeline events.

### 2.4 Analyst decisions are limited - DONE (2026-10-09)

| Before SP2 | Since SP2 (2026-10-09) | Where |
|---|---|---|
| Five statuses only: New, Under Review, Confirmed, False Positive, Closed (D-07). No Legitimate, no Ignored, no Reopened. Marking an alert False Positive did not stop it from coming back. Only admins could stop detection, through the allowlist. | Seven **decisions** on the finding: New, Investigating, Confirmed Threat, False Positive, Legitimate, Ignored, Resolved, with who, when and a note (required for False Positive, Legitimate and Ignored). "Reopened" is a timeline event. A decided finding stays quiet on later scans until a meaningful change reopens it (D-35, D-36). Legitimate can add the domain, app package or social handle to the allowlist, so analysts can stop detection too. Bulk decisions are all-or-nothing. Phase 1 statuses were migrated (Under Review to Investigating, Confirmed to Confirmed Threat, Closed to Resolved) with the same IDs (D-37). | `backend/app/core/findings.py` (`ALLOWED_TRANSITIONS`, `set_decision`), `backend/app/api/findings.py`, migration `20261009_c41e7a9d2b10_finding_model` |

**Why it mattered.** Analyst knowledge was not reused. Requirement RDA-11 (tested).

**Still open.** Decisions are not yet used as scoring context for *other* findings (for example "this
publisher was Legitimate before"). That is part of RDA-10, planned for SP3 and SP4.

### 2.5 No cross-module correlation or campaigns - DONE (2026-10-16, D-49)

Since 2026-10-16 findings that share a certificate, APK signer, file, scam phone/UPI number, developer contact, a look-alike mail server or an email link to a look-alike domain are linked; strong links form campaigns, shared IPs and favicons are shown as weak links only. Finding and alert pages show **Related findings**. The text below describes the situation before.

| Today | Where |
|---|---|
| Each module works alone. Shared infrastructure is not linked: the same IP address, TLS certificate, favicon hash, APK file hash or APK signer seen in several alerts is not connected. URLs found in phishing emails are captured and checked by the page analysis, but the email alert is not linked to a domain alert for the same site. The only merging is the one-alert-per-domain rule for the three domain modules (D-19). | `backend/app/modules/*`, `backend/app/modules/email/analysis.py` (`_live_page_phishing`) |

**Why it matters.** Attackers reuse infrastructure. Example: three look-alike domains, a fake Telegram support
account and a phishing email all point to one server. Today that shows as five unrelated alerts. Requirements
RDA-14, RDA-16.

### 2.6 Silent failures: unknown treated as "no" - DONE (2026-10-09)

This was the most important gap. The platform never invented findings, but in some places it recorded "could
not check" as "checked, nothing there". SP1 fixed it (decision D-31):

| Situation | Before SP1 | Since SP1 (2026-10-09) | Where |
|---|---|---|---|
| DNS lookup times out or the server fails (SERVFAIL) | Treated as "domain does not exist" and dropped | The domain is *unresolved*: counted on the "DNS resolution" component (`failed`) and retried next scan, never "not registered" | `backend/app/modules/domains/infra.py` (`DnsInfo.status`: `resolved`, `nxdomain`, `unknown`) |
| Browser cannot capture a page that accepts connections | Treated as "website not live" | "Website Live: unknown (capture failed)"; since SP2 the facts are recorded as unknown and never compared, so an existing finding only gets a new observation; reported on "Website probe & browser capture" | `backend/app/modules/domains/module.py` |
| RDAP (WHOIS) lookup fails | Error hidden in the `whois` field | Registrar and Created show "lookup failed"; the "WHOIS/RDAP" component reports the count | `backend/app/modules/domains/module.py` |
| TLS certificate cannot be read | Error hidden; "SSL Present: No" | Reported on the "TLS certificate" component (the field still shows "SSL Present: No") | `backend/app/modules/domains/module.py` |
| No Telegram API credentials | Silent switch to public `t.me` pages | "Telegram API: Not configured" plus "Telegram public pages" on every social scan | `backend/app/modules/social/module.py` (`_telegram`) |
| Which web-search provider ran | Not recorded; rate limits only in error text | Component named "Web search - <provider>" (`component_name()`); a rate limit is `unavailable` with the reason; Fake APK and Documents scans are `failed` when no search worked | `backend/app/core/search.py`, `modules/apk`, `modules/documents` |
| One APK search fails | Results of the whole run were lost | Results of the searches that worked are kept | `backend/app/modules/apk/module.py` |
| No official logo uploaded | Logo scan stopped with an error line | "Official logo assets: Not configured" and the run is `failed` | `backend/app/modules/logo/module.py` |
| Email analysis fails after its retries | Row stayed `queued` forever | Row is marked `failed` with the reason | `backend/app/workers/tasks.py` |

Email engines and feeds already reported "not checked" before SP1 (D-28).

**Still open.** If the message broker is down when an email is uploaded, the row stays `queued` (the task was
never queued). RDA-22 (prefer "unable to scan" over overstated results) applies to every later sub-project.

### 2.7 No per-component scan status and no integrations page - DONE (2026-10-09)

| Before SP1 | Since SP1 (2026-10-09) | Where |
|---|---|---|
| A scan run had one status (queued, running, succeeded, partial or failed) plus free-text errors. It did not say which parts ran. No page showed which integrations were configured. | Scan states are `queued`, `running`, `completed`, `partially_completed`, `completed_with_errors`, `failed`, `cancelled`, derived by `derive_run_status()` from a list of **components** stored in `scan_runs.components` (each `ok`, `skipped`, `not_configured`, `unavailable` or `failed`, with message and counts). The Scans page shows them under "What this scan checked". `GET /api/v1/integrations` and the **Integrations** page list every integration, whether it is configured, how to configure it, and its last result ("Not run yet" until there is evidence). | `backend/app/db/models.py` (`ScanStatus`), `backend/app/modules/base.py` (`ScanReport`, `derive_run_status`), `backend/app/core/integrations.py`, `frontend/src/app/(app)/integrations/page.tsx`, `frontend/src/components/scan-components.tsx` |

**Why it mattered.** "Partial" could mean "one image failed to download" or "the whole search engine was
blocked". Now an admin sees at a glance which part could not run and why. Requirements RDA-03, RDA-17.

### 2.8 Missing website and domain signals

| Missing signal | What it would show |
|---|---|
| Redirect chain | Every hop from the look-alike domain to the final page (today only the final URL is kept) |
| AAAA, CNAME records | IPv6 addresses and aliases (AAAA is only used to decide whether to try a connection, and is not stored) |
| ASN | Which network owns the IP address (for example a bulletproof hosting provider) |
| OTP and payment fields | Forms asking for one-time passwords or card numbers (today: keyword list only) |
| Suspicious scripts | Scripts that send typed passwords to another site |
| External resources | Images or scripts loaded from the real `examplebank.com` (a common phishing-kit pattern) |
| Threat intelligence for domains - **DONE (2026-10-16, D-46)** | OpenPhish, urlscan.io and URLhaus now check every registered look-alike; two sources are needed before the caps lift (Chapter 03) |

Requirements RDA-07, RDA-18.

### 2.9 Module gaps

| Module | Missing | Requirement / decision |
|---|---|---|
| Fake APK | Permissions and URLs inside the APK are not extracted. Deeper static analysis (MobSF) is recorded for Phase 2. | RDA-18, D-26, OOS-03 |
| Sensitive documents | Document metadata (author, company, creation tool, dates) is not read | RDA-18 |
| Social | Few profile details are kept (for example account age, post count, linked websites) | RDA-06 |
| Social media brand misuse | No video transcripts; TikTok, LinkedIn and Pinterest only through web search; Meta Ad Library returns commercial ads only for the EU/UK (Chapter 14, section 12) | D-38 |
| Rogue apps | Only Google Play is searched; other app stores are not | ROG-02 (deferred), D-13 |

### 2.10 Frontend states - DONE (2026-10-09)

| Before SP1 | Since SP1 (2026-10-09) | Where |
|---|---|---|
| When the API failed, pages could look clean: "No alerts yet", "Alert not found" for any failure, endless loading tiles. No "No threats detected." state. "Open alerts by module" left out the email modules. | Every data page shows an error panel with **Retry** when the API fails (only a real 404 says "not found"). The dashboard says "No threats detected." only after a completed scan, "No scans have run yet" otherwise, and "N scan parts could not run" when coverage was reduced (`/stats/executive` gained `last_completed_scan_at` and `components_unavailable`). The alert queue's empty state is "No threats detected.". "Open alerts by module" includes the email modules. | `frontend/src/components/query-state.tsx`, `frontend/src/app/(app)/page.tsx`, `alerts/page.tsx`, `alerts/[id]/page.tsx`, `brands/[id]/page.tsx`, `backend/app/api/stats.py` |

**Why it mattered.** An outage must never look like "all clear". Requirements RDA-02, RDA-19. The Emails pages
do not use the shared error panel yet.

### 2.11 Other known items

| Item | Detail |
|---|---|
| Demo mode in the product - **DONE (2026-10-09)** | `brands.demo_mode`, `ALLOW_DEMO_MODE`, `FIXTURES_DIR`, `FIXTURES_BASE_URL`, the demo toggle, tag, banner and "Demo data" chip are gone (D-32). The simulated sources moved to `backend/tests/support/fixture_sources.py` and the seed script to `backend/tests/support/seed_test_brand.py`; the brand API rejects a `demo_mode` field. A guard test checks that product code has no demo or fixture paths. Requirements RDA-01, RDA-04. |
| Libraries installed but unused | dkimpy, pyspf, checkdmarc and others are installed but not called (Chapter 11, section 9). DKIM signatures are not re-verified by the platform. |
| No notifications | Alerts appear in the dashboard only; no email or Slack (D-14). |

### 2.12 Social media posts, videos and ads - ADDED (2026-10-09)

| Before | Since 2026-10-09 (D-38) | Where |
|---|---|---|
| Only social **accounts** were monitored (Chapter 06), on five platforms. Posts, videos, paid ads and fake "customer care" numbers were not seen, and YouTube, Threads, TikTok and Pinterest were not covered at all. | A new module, Social Media Brand Misuse (`social_media`), finds posts, videos, ads and channels on YouTube, Facebook, Instagram, X, Threads, Meta ads, Pinterest, TikTok, LinkedIn and Telegram. It uses official APIs when a key is set (YouTube Data API, Meta Ad Library, Threads keyword search, X API, Telegram) and site-restricted web search otherwise. It flags fake contact details (phone, WhatsApp, Telegram, UPI) and scam wording, and keeps the link, a thumbnail and a screenshot. Requirements SMM-01 to SMM-06 are tested. | `backend/app/modules/social_media/`, Chapter 14 |

**Dashboard.** A **Social Media** page (`/social`) shows the results as a card grid with platform tabs and
filters (Chapter 10, section 8; Chapter 14, section 8).

**Still open.** Several sources need paid or approved access (X is paid; Threads needs Meta app review; the Meta Ad Library
shows commercial ads only for the EU/UK). Chapter 14 lists every limit.

## 3. The approved roadmap

On 2026-10-09 the owner approved a roadmap of five sub-projects (SP1 to SP5), to be done in this order. Each
one builds on the previous one.

```
  SP1 Honest status        "Tell the truth about what was and was not checked"
     |
     v
  SP2 Finding model        "Keep history; separate noise from alerts; remember decisions"
     |
     v
  SP3 Scoring v2           "Risk AND confidence, explained, no double counting"
     |
     v
  SP4 Correlation          "Link findings that share infrastructure into campaigns"
     |
     v
  SP5 Module enrichment    "More signals and evidence in every scanner"
```

Why this order: honest inputs come first, because a better score on top of hidden failures would still mislead.
History and decisions (SP2) are needed before confidence can use them (SP3). Correlation (SP4) needs findings
and confidence to link. New signals (SP5) are most useful once the model can store, score and correlate them.

### SP1 - Honest status and failure handling - DONE (2026-10-09)

| Item | Detail |
|---|---|
| Fixes | 2.6 silent failures, 2.7 scan status and integrations, 2.10 frontend states, demo mode in the product (2.11) |
| What changes | Scan states become `queued`, `running`, `completed`, `partially_completed`, `completed_with_errors`, `failed`, `cancelled`. Each scan stores a list of components with a status each: `ok`, `failed`, `unavailable`, `not_configured`, `skipped`. A DNS timeout becomes "unresolved", never "not registered", and an existing alert is left unchanged. A failed capture becomes "Website Live: unknown". The search provider and the Telegram mode are named. A new `GET /api/v1/integrations` and an Integrations page show what is configured and its last result. Demo mode leaves the product; test fixtures move to `backend/tests/support/`. Every data page gets loading, error, empty and "No threats detected." states. |
| Why it matters | Analysts and admins can trust that "nothing found" really means "checked and nothing found". |
| Requirements | RDA-01, RDA-02, RDA-03, RDA-04, RDA-17, RDA-19, RDA-21 |
| Status | **DONE (2026-10-09).** Design `docs/superpowers/specs/2026-10-09-sp1-honest-status-design.md`, plan `docs/superpowers/plans/2026-10-09-sp1-honest-status.md`. Decisions D-31 (honest scan states and per-component results) and D-32 (no demo mode in the product) are logged. Migration `20261009_7b1d0c4e9a21_scan_components`. The listed requirements are tagged on tests and marked "Tested" in the register. |

### SP2 - Finding model: candidates, findings, alerts, observations, decisions - DONE (2026-10-09)

| Item | Detail |
|---|---|
| Fixes | 2.2 no separation, 2.3 overwrites and missing history, 2.4 analyst decisions |
| What changed | Results go through stages: Candidate, then Finding (analysed, with evidence), then Alert (only for a Finding at or above the brand's "Alert from" level, default Medium). Every scan stores an **observation** per entity. The engine compares it with the previous one and records meaningful changes on a timeline, for example "Login/payment form detected" or "Domain can now receive email". A new alert is raised only on first crossing or a meaningful change, with trigger `first_crossing`, `change`, `reopen` or `migrated` and a reason. Analyst decisions are New, Investigating, Confirmed Threat, False Positive, Legitimate, Ignored and Resolved; a note is required for False Positive, Legitimate and Ignored; Legitimate can add to the allowlist; "Reopened" is a timeline event; bulk decisions are all-or-nothing. One engine (`backend/app/core/findings.py`, `record_detection`) owns persistence; modules no longer write alerts. New Findings page and API (`/api/v1/findings`); the alert detail page shows why the alert was raised, observations and the timeline. Phase 1 alerts were migrated with the same IDs. |
| Why it matters | A quieter queue, a clear story per entity, and analyst work that is not lost on the next scan. |
| Requirements | RDA-11, RDA-12, RDA-15 (tested); RDA-13, RDA-18, RDA-20 (SP2 part done); RDA-10 (decision part) |
| Status | **DONE (2026-10-09).** Design `docs/superpowers/specs/2026-10-09-sp2-finding-model-design.md`. Decisions D-33 (Candidate, Finding, Alert), D-34 (alert rule), D-35 (analyst decisions), D-36 (re-scans and meaningful changes) and D-37 (migration with the same IDs). Migration `20261009_c41e7a9d2b10_finding_model`. Tests in `backend/tests/api/test_findings.py` (Chapter 12). |

### Added outside the roadmap - Social media brand-misuse monitor - DONE (2026-10-09)

| Item | Detail |
|---|---|
| What changed | New module `social_media` (gap 2.12): posts, videos, ads and channels across ten platforms, scam contact and wording detection, four new scoring rules, screenshot and thumbnail evidence. It is built on the SP2 finding model: a bare mention is a Low finding (not alerted by default), an uncaptured search hit is a Candidate. |
| Requirements | SMM-01 to SMM-06 (tested) |
| Status | **DONE (2026-10-09)**, including the Social Media page (`/social`). Design `docs/superpowers/specs/2026-10-09-social-media-monitor-design.md`, decision D-38, migration `20261009_d7a3b5e1f082_social_media_module`, tests in `backend/tests/modules/test_social_media.py`. Chapter 14 describes it. |

### SP3 - Scoring v2: risk plus confidence - DONE (2026-10-16, D-45 to D-47)

| Item | Detail |
|---|---|
| Fixes | 2.1 no confidence, the domain part of 2.8 (threat intelligence for domains), double counting |
| What changes | Two scores per finding: **risk** (impact) and **confidence** (evidence quality and source reliability). Every point is explained by a reason linked to real evidence. Domains are checked against threat-intelligence sources too. One entity seen by several sources is one finding: more sources raise confidence, not risk. Multi-signal detection for domains and websites: domain, DNS and infrastructure, website, threat intelligence and visual signals. |
| Why it matters | Analysts can sort by "most dangerous and most certain". Scores stay explainable. Repeated sightings no longer inflate risk. |
| Requirements | RDA-07, RDA-08, RDA-09, RDA-10, RDA-13, RDA-14, RDA-18 |

### SP4 - Correlation and campaigns - DONE (2026-10-16, D-49)

| Item | Detail |
|---|---|
| Fixes | 2.5 no correlation |
| What changes | Findings that share an IP address, certificate, favicon hash, APK hash or signer, or an email link that points to a monitored domain, are linked. Linked findings form a **campaign**. Correlation raises confidence. Alerts show their related findings. |
| Why it matters | One attacker, one campaign view. Analysts can act on the whole operation instead of piece by piece. |
| Requirements | RDA-13, RDA-14, RDA-16 |

### SP5 - Module enrichment - planned

| Item | Detail |
|---|---|
| Fixes | 2.8 missing website signals, 2.9 module gaps |
| What changes | Quality review of every scanner. Website: redirect chain, HTTP headers, AAAA/CNAME/ASN, OTP and payment fields, suspicious scripts, external resources. APK: permissions and embedded URLs. Documents: metadata. Social: richer profile details. Other app stores are considered here (today deferred by D-13). |
| Why it matters | More and better evidence per finding, feeding the SP3 scores and SP4 links. |
| Requirements | RDA-06, RDA-18, RDA-20 |

### Requirements that apply to every sub-project

| ID | Rule |
|---|---|
| RDA-05 | Inspect the existing code first; improve existing features instead of building duplicates. |
| RDA-22 | When in doubt, say "no threat detected", "unable to scan" or "insufficient evidence" rather than overstate. |
| RDA-23 | Keep this beginner-friendly handbook up to date (one folder per chapter, PDF-ready). |

## 4. Gap-to-roadmap map

| Gap (section) | SP1 | SP2 | SP3 | SP4 | SP5 |
|---|---|---|---|---|---|
| 2.1 No confidence score | | | yes | | |
| 2.2 No candidate / finding / alert | | DONE (2026-10-09) | | | |
| 2.3 Overwrites, no observations, no change detection | | DONE (2026-10-09) | | | |
| 2.4 Limited analyst decisions | | DONE (2026-10-09) | yes (decisions as context) | yes (decisions as context) | |
| 2.5 No correlation or campaigns | | | | yes | |
| 2.6 Silent failures | DONE (2026-10-09) | | | | |
| 2.7 No per-component status or integrations page | DONE (2026-10-09) | | | | |
| 2.8 Missing website signals | | | yes (threat intel) | | yes |
| 2.9 Module gaps | | | | | yes |
| 2.10 Frontend states | DONE (2026-10-09) | | | | |
| 2.11 Demo mode in product | DONE (2026-10-09) | | | | |
| 2.12 Social media posts, videos and ads | Added outside the roadmap (D-38, 2026-10-09) | | | | yes (richer evidence) |

## 5. How to follow progress

| What | Where |
|---|---|
| Requirement status (Open, then PASS) | `docs/requirements/01-requirements-register.md` section Q, and `docs/reports/UAT-REPORT.md` after each test run |
| Designs and plans per sub-project | `docs/superpowers/specs/` and `docs/superpowers/plans/` |
| New decisions | `docs/decisions/DECISION-LOG.md` (D-31 onwards; D-33 to D-37 for SP2, D-38 for the social media monitor) |
| This handbook | Update the affected chapters when a sub-project lands |

## Key takeaways

- SP1 is DONE (2026-10-09): every scan reports which parts ran, a DNS timeout is "unresolved" and a failed
  capture is "unknown", the Integrations page shows every tool, error and empty states are honest, and demo
  mode is gone from the product (D-31, D-32).
- SP2 is DONE (2026-10-09): results are Candidates, Findings or Alerts; alerts come only from Findings at or
  above the brand's "Alert from" level; every scan stores an observation; meaningful changes go on a timeline
  and re-alert; seven analyst decisions are kept and respected on re-scan (D-33 to D-37).
- The social media brand-misuse monitor is DONE (2026-10-09, D-38): posts, videos, ads and channels on ten
  platforms, with fake contact details and scam wording flagged. The Social Media page shows them as screenshot cards.
- There is one score (risk) and no confidence. SP3 adds confidence, explanations tied to evidence, domain
  threat intelligence and protection against double counting.
- Modules do not share what they know. SP4 links shared infrastructure into campaigns.
- SP5 adds missing signals: redirect chains, ASN, OTP and payment fields, scripts, APK permissions, document
  metadata and richer social profiles.
- The roadmap was approved on 2026-10-09. SP1 and SP2 are complete; SP3 (risk plus confidence), SP4
  (correlation and campaigns) and SP5 (module enrichment) remain, in that order.
