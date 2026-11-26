# SP2 — Finding model: Candidate → Finding → Alert, re-scan observations, analyst decisions

**Date:** 2026-10-09 · **Status:** awaiting owner approval · **Roadmap:** sub-project 2 of 5 (approved 2026-10-09)
**Requirements:** RDA-11, RDA-12, RDA-13 (SP2 part), RDA-15, RDA-18 (linking part), RDA-20 (SP2 part); RDA-10
(analyst-decision part) · **Owner instruction:** do not commit anything to git during SP2.

## 1. Problem

Today every `Finding` a module yields becomes an alert immediately (`backend/app/core/alerts.py` `upsert_finding`):

- A registered look-alike domain with no website, a search hit that only mentions the brand, or a clean email all
  land in the alert queue — there is no Candidate or Finding stage (owner addendum §11).
- A re-scan overwrites the alert in place. There is no per-scan record of what was observed, no comparison of
  previous and current state, and the only history is a few `alert_events` rows (§14).
- Analyst statuses are New / Under Review / Confirmed / False Positive / Closed; "Legitimate", "Ignored" and
  "Reopened" from §10 do not exist, and a decision is not used when the entity is seen again — except that a risk
  increase re-opens a Closed / False Positive alert.
- Evidence hangs off the alert, not off the scan that captured it (§17).
- Two modules write the alert tables themselves: Google Play marks "App Status: Removed" and adds an event
  (`rogue_app/module.py:115-128`); the domain module looks up an existing alert (`domains/module.py:186-191`).

## 2. Goals / non-goals

**Goals**

1. Three separate levels: **Candidate** (discovered, weak), **Finding** (analysed, with evidence), **Alert** (a
   record raised only when the configured alert rule is met).
2. Every scan that sees an entity stores an **observation**; the engine compares it with the previous one,
   records meaningful changes on a **timeline**, and raises a new alert only on first crossing or a meaningful change.
3. Analyst **decisions** Confirmed Threat, False Positive, Legitimate, Ignored, Investigating (+ New, Resolved), kept
   on the finding with who/when/why, and used on re-scan (suppress unless a meaningful change → Reopened).
4. Alerts carry the minimum actionable information available after SP2 (§12) and evidence is linked to the right
   finding and observation.
5. Modules stop touching alert tables; one engine owns persistence and the alert decision (§20 lifecycle).

**Non-goals (later sub-projects)**

- Confidence score, new scoring, explainable score breakdown, threat-intel for domains (SP3). SP2 uses today's
  risk score and fired rules unchanged.
- Using decisions as scoring context for *other* findings, correlation, related findings, campaigns, the
  logo-URL vs domain duplicate entity (SP3/SP4).
- New scanner signals (SP5).

## 3. Design

### 3.1 Data model

New tables; `alerts` is re-purposed.

| Table | One row per | Columns |
|---|---|---|
| `findings` | entity per brand and module family | `id`, `brand_id`, `module`, `entity_key`, `stage` (`candidate`/`finding`), `decision`, `decided_by`, `decided_at`, `decision_note`, `title`, `similarity`, `score`, `risk_level`, `suspected_phishing`, `signals` (JSONB), `details` (JSONB), `state` (JSONB, latest comparable facts), `source_url`, `first_seen`, `last_seen`, `last_alert_at`, `updated_at` |
| `observations` | finding × time it was seen | `id`, `finding_id`, `scan_id` (nullable — email upload/mailbox), `channel` (`scan`/`upload`/`mailbox`/`migration`), `observed_at`, `stage`, `score`, `risk_level`, `signals`, `state`, `details` |
| `finding_events` | timeline entry | `id`, `finding_id`, `kind`, `from_value`, `to_value`, `note`, `user_id`, `observation_id`, `alert_id`, `at` |
| `alerts` | each time the alert rule was met | `id`, `finding_id`, `scan_id`, `observation_id`, `trigger` (`first_crossing`/`change`/`reopen`/`migrated`), `reason` (text shown to analysts), `score`, `risk_level`, `reasons` (fired rules at that moment), `created_at` |
| `evidence` | stored item | as today, but `alert_id` → `finding_id` + `observation_id` |
| `brands` | — | new `alert_min_level` (`risk_level`, default `Medium`) |
| `email_messages` | — | `alert_id` → `finding_id` |

- Uniqueness: `findings (brand_id, module_family, entity_key)` where the domain modules (typosquat, mx, phishing)
  form one family and the finding's `module` is the furthest stage reached, as today (D-19). Implemented as a stored
  `family` column with a unique index.
- `finding_events.kind`: `discovered`, `promoted` (candidate → finding), `changed`, `rescored`, `alerted`,
  `decision`, `reopened`, `stage` (domain pipeline stage moved forward), `app_status`.
- `decision` enum `finding_decision`: `New`, `Investigating`, `Confirmed Threat`, `False Positive`, `Legitimate`,
  `Ignored`, `Resolved`. The old `alert_status` enum is dropped.
- Evidence is stored once per finding (same SHA-256 file or identical metadata is not stored again — the current
  rule), and each new item records the observation that captured it.

### 3.2 Candidate vs Finding (RDA-12)

The module `Finding` dataclass (rename to `Detection` to stop the name clash with the new table/stage) gains
`analysed: bool` (default `True`). The engine sets `stage = finding if analysed else candidate`. Each module sets it:

| Module | `analysed = False` (Candidate) | `analysed = True` (Finding) |
|---|---|---|
| Domains | registered look-alike with no website captured and no MX | MX present, or website captured |
| APK | name/package match only | logo match, repackaged build, or APK downloaded and signer checked |
| Google Play | name similarity only | exact brand word in title/package, or icon matches the logo |
| Social | search hit only (title/snippet) | profile page fetched (bio/avatar), or avatar matches the logo |
| Documents | file could not be downloaded, or exposure confidence Low | downloaded and text checked (Medium/High) |
| Logo, Email, Email posture | — | always (only analysed results are yielded) |

A finding never goes back from Finding to Candidate; once analysed it stays a Finding (a later weaker observation
is recorded as an observation only).

### 3.3 Alert rule (RDA-12)

An entity meets the rule when `stage == finding` **and** `risk_level >= brand.alert_min_level`. A Candidate never
alerts, whatever its score. SP3 adds a confidence condition to the same function.

### 3.4 Engine: one detection in, persisted result out (RDA-15, RDA-20)

`app/core/findings.py` replaces `app/core/alerts.py`. `record_detection(db, brand, module, detection, scan_id,
channel)`:

1. **Match** the finding by brand + family + entity key; create it with a `discovered` event if absent.
2. **Score** with today's `score()` (unchanged).
3. **Observe**: insert an observation (scan ID, signals, score, level, `state`, details) and store new evidence
   linked to it.
4. **Diff** the new `state` with the finding's previous `state` (§3.5); write one `changed` event per meaningful
   change; `promoted` when stage moves to Finding; `rescored` when the level changes; `stage` when the domain
   pipeline stage moves forward.
5. **Update** the finding (last seen, score, level, signals, details, state, title).
6. **Decide** on an alert (§3.6); if raised, insert the `alerts` row and an `alerted` event.

`execute_scan` calls it per detection exactly where it calls `upsert_finding` today (each in its own savepoint).
Email `service.py` and `intake/mailbox.py` call it with `channel="upload"`/`"mailbox"` and no scan ID.

Modules no longer read or write findings/alerts:

- Google Play: when a tracked listing disappears (all searches succeeded, as today), the module yields a
  detection for that entity with `state.listed = False` and the previous details; the engine records the
  observation and an `app_status` event. When it is listed again, `listed` flips to `True` (meaningful change).
- Domains: the "capture failed and an alert already exists → yield nothing" rule becomes "capture failed → yield
  with `state.live = None` (unknown)"; the diff ignores unknown values, so nothing changes on the finding except
  last seen.

### 3.5 Meaningful changes (RDA-15)

`state` holds only comparable facts. A value of `None` means "unknown" and is never compared.

| Fact | Set by | Meaningful change |
|---|---|---|
| `live` | domains, logo | `False → True`: "Website went live" |
| `login_form` | domains, logo | `False → True`: "Login/payment form detected" |
| `logo_match` | domains, logo, APK, Play, social | `False → True`: "Official logo detected" |
| `mx` | domains | `False → True`: "Domain can now receive email" |
| `signer_mismatch` | APK | `False/None → True`: "APK signed by a non-official certificate" |
| `listed` | Google Play | `False → True`: "App listed again"; `True → False` recorded as `app_status` only |
| `stage` | engine | `candidate → finding`: "Analysis found evidence" |
| `risk_level` | engine | increase across a level: "Risk Medium → High" |

Not meaningful: score movement within a level, title/snippet/text changes, risk decrease (recorded as `rescored`),
`True → False` on any fact (recorded as `changed` on the timeline but never alerts), unknown values.

### 3.6 Alert decision (RDA-12, RDA-15, RDA-11)

After the update, with `meets = rule(finding)`, `changes = meaningful changes in this observation`:

| Decision now | Condition | Result |
|---|---|---|
| any | `not meets` | no alert |
| New / Investigating | no alert raised yet, or previous observation did not meet the rule | alert, trigger `first_crossing`, reason "First reached <level>" |
| New / Investigating | already alerted and `changes` non-empty | alert, trigger `change`, reason = the change text(s) |
| Confirmed Threat | `changes` non-empty | alert, trigger `change` (decision unchanged) |
| False Positive / Legitimate / Ignored / Resolved | `changes` non-empty | decision → `New`, `reopened` event with reason, alert trigger `reopen` |
| False Positive / Legitimate / Ignored / Resolved / Confirmed Threat | no changes | no alert; observation + last seen only |

### 3.7 Analyst decisions (RDA-11)

Allowed transitions:

| From | To |
|---|---|
| New | Investigating, Confirmed Threat, False Positive, Legitimate, Ignored |
| Investigating | New, Confirmed Threat, False Positive, Legitimate, Ignored |
| Confirmed Threat | Investigating, Resolved |
| False Positive, Legitimate, Ignored | New (manual reopen → `reopened` event), Investigating |
| Resolved | New (manual reopen → `reopened` event), Investigating |

- A note is required for False Positive, Legitimate and Ignored.
- Choosing Legitimate may add the entity to the brand allowlist (`add_to_allowlist: true`): domain → `domain`,
  Play/APK → `package`, social → `social_handle`, APK with a signer → `signing_cert`. Documents, logo, email and
  posture have no allowlist kind; the option is not offered for them.
- `decided_by`, `decided_at`, `decision_note` are kept on the finding; every change is a `decision` event.
- Both roles (admin, analyst) may set decisions; bulk decisions apply the same decision and note to many findings,
  each validated and evented separately, all-or-nothing.

### 3.8 What an alert shows (RDA-13, RDA-18)

The alert detail returns: alert ID, finding ID, brand, threat type (module), target (entity / source URL), risk
score and level (severity), alert time, trigger and reason, first seen, last seen, reasons (fired rules at alert
time), evidence (grouped by observation, with screenshot / DNS / WHOIS / HTTP / SSL / logo / APK metadata where the
module captured them), source (module + source URL), scan ID, current decision, and the finding timeline.
Confidence score and threat-intel matches (SP3) and related findings (SP4) are absent until then; the UI does not
show placeholders for them.

## 4. API and dashboard

| Endpoint | Change |
|---|---|
| `GET /findings` | new — filters: brand, module, stage, decision, risk, alerted (yes/no), search; paginated like `/alerts` |
| `GET /findings/{id}` | new — current state, timeline, observations (newest first, with scan IDs), evidence by observation, alerts |
| `POST /findings/{id}/decision` | new — `{decision, note?, add_to_allowlist?}`; 400 on invalid transition / missing note |
| `POST /findings/decision` | new — bulk `{finding_ids, decision, note?}` |
| `GET /alerts`, `GET /alerts/{id}` | alert records joined to their finding; filters as today (status filter → decision) |
| `POST /alerts/{id}/status` | kept for compatibility; sets the finding's decision |
| `GET /alerts/{id}/events` | returns the finding timeline |
| `GET /evidence/{id}` | unchanged |
| stats, brand counts, CSV/PDF export | "open" = alert whose finding is New or Investigating; exports add Finding ID, Scan ID, Decision, Trigger |
| `PATCH /brands/{id}` | accepts `alert_min_level` |

Dashboard:

- **Alerts** queue — alert records with reason and decision badge; filters unchanged except status → decision.
- **Alert detail** — §3.8 fields, evidence, **Timeline** tab, decision buttons (note dialog where required,
  allowlist checkbox for Legitimate).
- **Findings** page (new nav item) — all findings and candidates; filters stage / decision / alerted; multi-select
  bulk decision; detail view shares components with alert detail.
- **Brand settings** — "Alert from" level selector.
- **Executive dashboard** — counts by decision; "Candidates" and "Findings below alert level" tiles.
- Error / empty / no-threats states follow SP1 (RDA-19).

## 5. Migration

One Alembic revision with upgrade and downgrade:

- Each `alerts` row → `findings` row with the **same ID**, stage `finding`, decision mapped New → New, Under Review →
  Investigating, Confirmed → Confirmed Threat, False Positive → False Positive, Closed → Resolved; `state` derived
  from stored signals (`page_live`, `login_payment`, `official_logo`, `mx_present`); plus one observation (channel
  `migration`) and one alert record (trigger `migrated`, reason "Migrated from Phase 1").
- `alert_events` → `finding_events` (status → decision kind, values mapped); `evidence.alert_id` → `finding_id`
  (observation = the migrated one); `email_messages.alert_id` → `finding_id`.
- Checked first on a copy of the dev database (as in SP1), including downgrade + upgrade round trip.

## 6. Testing

All tests carry `@pytest.mark.req(...)`.

| Level | Tests | Req |
|---|---|---|
| Unit | stage per module (candidate vs finding) | RDA-12 |
| Unit | alert rule: per-brand threshold; candidate never alerts | RDA-12 |
| Unit | diff: each meaningful change; non-changes and unknowns ignored | RDA-15 |
| Unit | alert decision table §3.6, every row | RDA-11, RDA-15 |
| Unit | decision transitions, required notes, allowlist kinds | RDA-11 |
| Module acceptance | AC-01…08 through the new engine; a second identical scan → no new findings, no new alerts, one observation each; a fixture that goes live → exactly one `changed` event and one alert | RDA-15, RDA-20 |
| API | findings list/detail/decision/bulk; alert detail fields; compatibility status endpoint | RDA-13, AC-10 |
| Migration | upgrade on a populated DB, downgrade + upgrade round trip | — |
| E2E (Playwright) | alert queue, decision change with note, timeline visible, Findings page filters | AC-09, AC-10 |

## 7. Decisions to log

- D-33 Candidate → Finding → Alert stages and per-module "analysed" rule.
- D-34 Alert rule: stage Finding + risk ≥ brand `alert_min_level` (default Medium); confidence added in SP3.
- D-35 Analyst decision set, transitions, required notes, Legitimate → allowlist.
- D-36 Meaningful changes and re-scan alerting (suppress after a decision unless a meaningful change → Reopened).
- D-37 Phase 1 alerts migrated as findings with the same IDs.

Docs: requirements register (RDA-11/12/15 → tested; RDA-13/18/20 partial), UAT report, handbook chapters on alerts
and the analyst workflow, `openapi.json`. No git commits (owner instruction).

## 8. Risks

- **Fewer alerts after migration than before upgrade scans run:** none — every Phase 1 alert keeps an alert record.
  New scans may *not* re-raise existing low-risk entities; that is the intended behaviour (§11).
- **Broad change across API, frontend and tests:** keep `/alerts` URLs and the compatibility status endpoint; land
  backend first with its tests, then frontend, then e2e.
- **Candidate volume:** domains can produce many registered look-alikes; the Findings page paginates and filters
  by stage, and candidates never enter the alert queue.
- **Unknown vs negative:** diff ignores `None`; a failed capture never reads as "went offline" (SP1 rule kept).
