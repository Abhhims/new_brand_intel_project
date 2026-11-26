# Phishing Email Monitoring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add phishing-email monitoring (email analysis, brand domain email posture, look-alike email-readiness, DMARC
report monitoring) as new modules of the existing platform, scored by the shared deterministic risk model.

**Architecture:** A new package `backend/app/modules/email/` follows the existing module pattern (sources → analyse →
`Finding` → `core/alerts.upsert_finding`). Analysis is split into focused units (parser, auth, engines, intel,
attachments, analysis orchestrator). Rspamd and ClamAV run as separate containers reached over their network APIs;
YARA runs in-process. Every external call goes through the safe fetcher; every verdict is stored as evidence.

**Tech Stack:** Python 3.12, FastAPI, Celery, SQLAlchemy/Alembic, PostgreSQL; stdlib `email`, extract-msg, dkimpy, pyspf,
checkdmarc, oletools, yara-python, defusedxml; Rspamd, ClamAV (Docker); URLhaus, OpenPhish, urlscan.io, AbuseIPDB;
Next.js frontend.

**Spec:** `docs/superpowers/specs/2026-10-08-phishing-email-design.md`

## Global Constraints

- Database stays PostgreSQL; frontend stays Next.js (spec §5) — no MongoDB.
- Every outbound HTTP request uses `app.core.fetch.fetch/try_fetch` (D-18); Rspamd/ClamAV are internal service hosts and
  are the only additions to the private-host allowlist **for those two hostnames only** (`rspamd`, `clamav`).
- Attachments are never executed or opened by an application; only scanned (ClamAV, YARA, oletools) and read as text.
- Scoring rules and points exactly as spec §4; `known_malicious_url` requires **≥2 independent sources**; unreachable
  source = 0 points + listed as "not checked".
- Official senders that pass DMARC never receive `brand_impersonation` or `lookalike_sender` points.
- Demo data stays test-only (D-27): fixture emails live under `fixtures/emails/` and are used only by tests.
- New module names: `email`, `email_posture`, `dmarc` (enum values via migration).
- Requirement IDs for traceability: new register section **EML-01…EML-20** (Task 11).
- Commits: only after the owner says "commit" (owner instruction); steps marked *Commit* are batched until then.
- Library deviations from spec §3 (recorded in D-28): stdlib `email` (policy.default) instead of mail-parser — same
  capability, no extra dependency; a small `defusedxml`-based DMARC parser instead of parsedmarc — parsedmarc pulls in
  Elasticsearch/OpenSearch/Kafka/cloud SDKs we do not use. All libraries verified to install on this machine
  (dkimpy, pyspf, checkdmarc, extract-msg, oletools, yara-python 4.5.4, defusedxml).

## Review Focus

1. **Malformed / hostile emails** (broken MIME, huge headers, encoded-word subjects, nested `message/rfc822`, 30 MB
   attachments, zip bombs) → parsed best-effort with limits, never crash the worker → tests in Task 2.
2. **Legitimate company email** (sent from `mykcpl.com`, DMARC pass, mentions the brand and "login") → must not score
   as impersonation → test in Task 6.
3. **One tool says "malicious", others are silent or unreachable** → at most `single_source_url_hit` (+15), never
   Critical on that alone; unreachable tools shown as "not checked" → tests in Task 5 and Task 6.
4. **The same email uploaded twice / forwarded from the mailbox again** → same alert updated, not duplicated → test in
   Task 7.
5. **Forwarded email** (analyst forwards a phish to the reporting mailbox) → analyse the *attached original*
   (`message/rfc822` or inline headers), not the forwarder's wrapper → test in Task 2 and Task 10.

---

## File Structure

```
backend/app/modules/email/
  __init__.py
  model.py        dataclasses: ParsedEmail, Attachment, UrlRef, ToolVerdict, EmailAnalysis
  parser.py       parse(raw: bytes, filename) -> ParsedEmail   (.eml, .msg, forwarded originals)
  urls.py         extract_urls(text, html) -> list[UrlRef]; unwrap(url) -> str
  auth.py         authenticate(parsed, raw) -> dict   (Authentication-Results + dkimpy + pyspf + DMARC alignment)
  engines.py      rspamd_check(raw) / clamav_scan(data) / yara_scan(data) -> ToolVerdict
  intel.py        urlhaus_url / urlhaus_hash / openphish_hit / urlscan_lookup / abuseipdb_check -> ToolVerdict (cached)
  attachments.py  analyse_attachment(att) -> dict
  analysis.py     analyse(parsed, raw, ctx) -> EmailAnalysis (signals + indicators + evidence)
  service.py      process_email(db, raw, filename, brand_id, channel) -> Alert
  posture.py      PostureModule (capability B)
  dmarc.py        parse_report(bytes) -> list[DmarcRecord]; DmarcModule (capability D)
  intake/imap.py  ImapSource; intake/graph.py GraphSource; intake/gmail.py GmailSource; intake/mailbox.py MailboxModule
backend/app/api/emails.py          upload / list / detail endpoints
backend/app/alembic/versions/...    migration: enum values + email tables
backend/rules/yara/                 curated YARA rules (phishing kits, maldocs, credential harvesting)
deploy/docker-compose.yml           rspamd, clamav services
frontend/src/app/(app)/emails/page.tsx, components/email-sections.tsx, brand page "Email security" panel
fixtures/emails/                    test emails (phish, legit, forwarded, malformed, EICAR attachment)
backend/tests/unit/test_email_*.py, tests/modules/test_email_acceptance.py, tests/api/test_emails_api.py
docs/architecture/09-EMAIL.md
```

---

### Task 1: Data model, migration and scoring rules

**Files:** Modify `backend/app/db/models.py`, `backend/app/core/scoring.py`, `backend/app/modules/registry.py`;
Create migration `backend/app/alembic/versions/<date>_email_monitoring.py`; Test `backend/tests/unit/test_scoring.py`.

**Interfaces — Produces:** `ModuleName.email|email_posture|dmarc`; tables `email_messages`, `email_indicators`,
`dmarc_reports`, `mail_sources`; `Signals` fields `known_malicious_url, single_source_url_hit, malware_attachment,
suspicious_attachment, auth_fail_brand_from, lookalike_sender, brand_impersonation, reply_to_mismatch,
credential_or_payment_language, young_domain, bad_sender_ip, rspamd_phish, live_phishing_page, lookalike_can_send`,
posture fields `posture_dmarc_missing, posture_dmarc_none, posture_spf_missing, posture_spf_softfail,
posture_dkim_missing, posture_mta_sts_missing`.

- [ ] Step 1: tests — each new rule adds its points (spec §4 table); `known_malicious_url` and `single_source_url_hit`
  are mutually exclusive by construction (analysis sets one); module levels for `email`, `email_posture`, `dmarc` are
  Low–Critical.
```python
@pytest.mark.parametrize(("signals", "points", "rule"), [
    (Signals(known_malicious_url=True), 40, "known_malicious_url"),
    (Signals(single_source_url_hit=True), 15, "single_source_url_hit"),
    (Signals(malware_attachment=True), 40, "malware_attachment"),
    (Signals(suspicious_attachment=True), 20, "suspicious_attachment"),
    (Signals(auth_fail_brand_from=True), 30, "auth_fail_brand_from"),
    (Signals(lookalike_sender=True), 25, "lookalike_sender"),
    (Signals(brand_impersonation=True), 20, "brand_impersonation"),
    (Signals(reply_to_mismatch=True), 10, "reply_to_mismatch"),
    (Signals(credential_or_payment_language=True), 15, "credential_or_payment_language"),
    (Signals(young_domain=True), 10, "young_domain"),
    (Signals(bad_sender_ip=True), 10, "bad_sender_ip"),
    (Signals(rspamd_phish=True), 10, "rspamd_phish"),
    (Signals(live_phishing_page=True), 20, "live_phishing_page"),
    (Signals(lookalike_can_send=True), 10, "lookalike_can_send"),
    (Signals(posture_dmarc_missing=True), 40, "posture_dmarc_missing"),
    (Signals(posture_dmarc_none=True), 20, "posture_dmarc_none"),
    (Signals(posture_spf_missing=True), 40, "posture_spf_missing"),
    (Signals(posture_spf_softfail=True), 10, "posture_spf_softfail"),
    (Signals(posture_dkim_missing=True), 10, "posture_dkim_missing"),
    (Signals(posture_mta_sts_missing=True), 5, "posture_mta_sts_missing"),
])
def test_email_rules(signals, points, rule):
    r = score(signals, ModuleName.email)
    assert (r.score, r.fired) == (points, [rule])
```
- [ ] Step 2: run → FAIL (unknown fields). Step 3: add fields to `Signals`, points to `RULE_POINTS`, checks in
  `_fired_rules`, `MODULE_LEVELS` entries; models + migration (`ALTER TYPE module_name ADD VALUE ...` in an autocommit
  block; create 4 tables); `OUTPUT_FIELDS` / `MODULE_LABELS` / `RUNNERS` entries (`email` → `mailbox`,
  `email_posture` → `email_posture`, `dmarc` → `dmarc`). Step 4: tests pass; `alembic upgrade head` on the test DB.

### Task 2: Parser and URL extraction

**Files:** Create `modules/email/model.py`, `parser.py`, `urls.py`; fixtures `fixtures/emails/*.eml`; Test
`tests/unit/test_email_parser.py`.

**Produces:** `parse(raw: bytes, filename: str = "") -> ParsedEmail` with `message_id, date, subject, from_addr,
from_name, reply_to, return_path, to, received (list[str]), sender_ip, auth_results_header, text, html,
urls: list[UrlRef(url, text, source)], attachments: list[Attachment(name, content_type, data, sha256, size, nested)],
images: list[Attachment], headers: dict, is_forwarded_original: bool, warnings: list[str]`;
`extract_urls(text, html) -> list[UrlRef]`; `unwrap(url) -> str` (Microsoft Safe Links, Google redirect, Proofpoint
v2/v3, `hxxp[s]://` and `[.]` de-obfuscation).

- [ ] Tests (fixtures): plain phish with link; HTML phish where link text ≠ href; encoded-word subject
  (`=?UTF-8?B?...?=`); multipart/alternative; PDF + ZIP attachments; forwarded message with `message/rfc822` original
  → parser returns the original (`is_forwarded_original=True`); `.msg` sample via extract-msg; malformed MIME (missing
  boundary) → no exception, `warnings` non-empty; limits: >50 attachments or >30 MB total → truncated with warning.
- [ ] Sender IP = first public IP in the topmost `Received` header added by the receiving MTA (skip private/loopback).
- [ ] Implementation uses `email.message_from_bytes(raw, policy=email.policy.default)`; HTML links from `href`/`src`
  via `html.parser`; plain URLs by regex; dedupe by normalised URL.

### Task 3: Email authentication (two independent evaluations)

**Files:** Create `modules/email/auth.py`; Test `tests/unit/test_email_auth.py`.

**Produces:** `authenticate(parsed: ParsedEmail, raw: bytes) -> dict` with keys
`header: {spf, dkim, dmarc, arc}` (from `Authentication-Results`), `dkim_verified: bool|None` (dkimpy `dkim.verify`),
`spf_result: str|None` (pyspf `spf.check2(ip, mail_from, helo)`), `dmarc: {policy, aligned_spf, aligned_dkim, result}`
(record via `checkdmarc.get_dmarc_record`, relaxed alignment by registered domain), `from_domain`, `checked_at`.

- [ ] Tests: parse sample `Authentication-Results` lines (pass/fail/softfail/none); DMARC alignment logic with
  monkeypatched record lookups (From `mykcpl.com`, SPF pass on `mail.mykcpl.com` → aligned under relaxed); DNS
  failure → result `temperror`, never an exception.

### Task 4: Engines — Rspamd, ClamAV, YARA

**Files:** Create `modules/email/engines.py`, `backend/rules/yara/*.yar`; Modify `deploy/docker-compose.yml`
(services `rspamd` image `rspamd/rspamd:latest`, `clamav` image `clamav/clamav:stable`), `app/config.py`
(`rspamd_url`, `clamav_host`, `clamav_port`, `clamav_enabled`, `yara_rules_dir`); Test `tests/unit/test_email_engines.py`.

**Produces:** `ToolVerdict(tool, status: "ok"|"not_checked"|"error", malicious: bool, score: float|None, details: dict,
checked_at)`; `rspamd_check(raw) -> ToolVerdict` (POST `/checkv2`, `malicious` when action is `reject` or phishing
symbols such as `PHISHING`, `PHISHED_*`, `DMARC_POLICY_REJECT` fire); `clamav_scan(data) -> ToolVerdict` (clamd
`INSTREAM` over TCP, chunked, `FOUND` → malicious); `yara_scan(data) -> ToolVerdict` (compiled once, matches list).

- [ ] Tests: Rspamd JSON responses mocked with respx; ClamAV protocol tested against a fake socket server returning
  `stream: Eicar-Test-Signature FOUND`; integration test (skipped unless containers reachable) scans the EICAR string;
  YARA rule test on a fixture HTML credential-harvest page; engine down → `status="not_checked"`.

### Task 5: Threat-intelligence adapters

**Files:** Create `modules/email/intel.py`; Modify `app/config.py` (`urlhaus_auth_key`, `urlscan_api_key`,
`abuseipdb_api_key`, `openphish_feed_url`); Test `tests/unit/test_email_intel.py`.

**Produces:** `urlhaus_url(url)`, `urlhaus_hash(sha256)`, `openphish_hit(url)`, `urlscan_lookup(url)`,
`abuseipdb_check(ip)` → `ToolVerdict`; `url_reputation(url) -> list[ToolVerdict]`; `corroborated(verdicts) -> int`
(count of independent malicious verdicts). All cached in Redis 24 h (feed 6 h); no key → `not_checked`.

- [ ] Tests (respx): each adapter maps known/unknown/error responses; OpenPhish feed parsed into a set and matched by
  normalised URL; quota/429 → `not_checked`; `corroborated()` counts distinct tools only.

### Task 6: Analysis orchestrator and scoring

**Files:** Create `modules/email/attachments.py`, `analysis.py`; Test `tests/unit/test_email_analysis.py`.

**Consumes:** Tasks 2–5, `BrandContext.relevance`, `core/similarity`, `core/imaging`, domain pipeline helpers
(`LiveInfra.whois`, `core/browser.capture`, `modules/pagecheck.analyse`).

**Produces:** `analyse(parsed, raw, ctx) -> EmailAnalysis(signals: Signals, details: dict, indicators: list[dict],
evidence: list[EvidenceItem], verdict_summary: str, related_domains: list[str])`.

Rules (exactly spec §4): `known_malicious_url` when any URL has `corroborated() >= 2` (our live-page "Suspected
Phishing" counts as one source); else `single_source_url_hit` when one source; `malware_attachment` (ClamAV FOUND or
URLhaus hash); `suspicious_attachment` (YARA, macros via `oletools.olevba.VBA_Parser.detect_vba_macros`, executable /
script / double extension / archive containing executable); `auth_fail_brand_from`; `lookalike_sender` (sender,
Reply-To or link registered domain similarity > 80 to brand labels and not official, or domain already an alert);
`brand_impersonation` (ctx.relevance or logo match ≥85 in images) — only when not an official DMARC-pass sender;
`reply_to_mismatch`; `credential_or_payment_language` (pagecheck keyword list + urgency terms); `young_domain`
(< 30 days via RDAP); `bad_sender_ip` (AbuseIPDB ≥ 75); `rspamd_phish`; `live_phishing_page` (linked page analysed by
the website pipeline is Suspected Phishing — max 5 URLs per email).

- [ ] Tests: (a) phish fixture (look-alike sender `mykcp1.com`, Reply-To gmail, login link on URLhaus + OpenPhish) →
  rules `known_malicious_url, lookalike_sender, brand_impersonation, reply_to_mismatch,
  credential_or_payment_language` → Critical; (b) legitimate company email (From `mykcpl.com`, DMARC pass, says
  "login to your account") → no `brand_impersonation`, no `lookalike_sender`, score < 30; (c) only URLhaus lists the
  URL, urlscan unreachable → `single_source_url_hit` only, detail shows urlscan "not checked"; (d) EICAR attachment
  with ClamAV mocked FOUND → `malware_attachment`.

### Task 7: Service, persistence, API and Celery task

**Files:** Create `modules/email/service.py`, `app/api/emails.py`; Modify `app/main.py` (router),
`app/workers/tasks.py` (`analyse_email_task`), `app/schemas/api.py`; Test `tests/api/test_emails_api.py`.

**Produces:** `process_email(db, raw, filename, brand_id, channel) -> Alert` — stores raw `.eml` in evidence, upserts
`email_messages` (dedupe by Message-ID, else SHA-256 of raw), `email_indicators`, alert (`module=email`,
`entity_key="email:<message-id or sha>"`). Endpoints: `POST /emails` (multipart `file`, `brand_id`; ≤ 25 MB;
`.eml/.msg/.txt`) → 202 + message id, queued on `default`; `GET /emails?brand_id=&page=`; `GET /emails/{id}`.

- [ ] Tests: upload phish fixture → alert created with evidence (raw eml + verdicts); upload same file twice → one
  alert, `last_seen` updated; non-email file → 422; analyst role can upload; unknown brand → 404.

### Task 8: Dashboard

**Files:** Create `frontend/src/app/(app)/emails/page.tsx`, `components/email-sections.tsx`; Modify
`components/app-shell.tsx` (nav "Emails"), `app/(app)/alerts/[id]/page.tsx` (render email sections when
`module==="email"`), `app/(app)/brands/[id]/page.tsx` (Email security panel), `lib/api.ts`, `lib/constants.ts`
(module labels), `app/(app)/page.tsx` (tiles "Phishing emails today", "Spoofed-sender attempts").

- [ ] Upload (drag-and-drop) with brand picker; list with verdict, sender, subject, score, channel; detail: header
  table, SPF/DKIM/DMARC chips (both evaluations side by side), URL table with each source's verdict or "not checked",
  attachment table (ClamAV/YARA/hash/macros), sanitised text preview (no HTML rendering, no remote images).
- [ ] `npm run lint`, `npx tsc --noEmit`, `npm run build` pass; e2e test uploads a fixture in the *test* environment
  only.

### Task 9: Brand email posture (B) and look-alike email readiness (C)

**Files:** Create `modules/email/posture.py`; Modify `modules/domains/module.py` (`check_domain`: SPF + DMARC lookup
for registered look-alikes, `lookalike_can_send`, detail fields "SPF Record", "DMARC Record", "Email-ready");
Test `tests/unit/test_email_posture.py`, extend `tests/modules/test_acceptance.py`.

**Produces:** `PostureModule.run(ctx, db)` → one finding per official domain (`entity_key="posture:<domain>"`) with
`checkdmarc.check_domains` results: duplicate/invalid DMARC → `posture_dmarc_missing`, `p=none` →
`posture_dmarc_none`, SPF missing or `+all` → `posture_spf_missing`, `~all` → `posture_spf_softfail`, no DKIM on
common selectors (`default, selector1, selector2, google, k1, s1, s2, dkim, mail`) → `posture_dkim_missing`,
no MTA-STS → `posture_mta_sts_missing`.

- [ ] Tests: monkeypatched DNS answers reproducing mykcpl.com today (two DMARC records, one malformed) →
  `posture_dmarc_missing` with detail "2 DMARC records — receivers treat DMARC as absent"; a well-configured domain →
  score 0 → no alert.

### Task 10: Intake — IMAP mailbox, DMARC reports, Microsoft 365 / Google

**Files:** Create `modules/email/intake/imap.py`, `intake/mailbox.py`, `intake/graph.py`, `intake/gmail.py`,
`modules/email/dmarc.py`; Modify `app/config.py` (`imap_*`, `dmarc_imap_*`, `ms_graph_*`, `gmail_*`),
`workers/celery_app.py` (beat: mailbox every 5 min, DMARC hourly, posture daily); Test
`tests/unit/test_email_intake.py`, `tests/unit/test_dmarc.py`.

**Produces:** `ImapSource.fetch_new() -> list[(uid, raw)]` (IMAP4_SSL, `UNSEEN`, marks `\Seen` after successful
processing, moves to `Processed` folder if it exists); `MailboxModule` → calls `process_email` per message with
`channel="mailbox"`; `parse_report(blob) -> DmarcReport` (zip/gzip/xml with `defusedxml`); `DmarcModule` → stores
`dmarc_reports`, alerts per failing source IP (`entity_key="dmarc:<domain>:<ip>"`). Graph/Gmail sources implement
the same `fetch_new()` interface (credentials from `.env`).

- [ ] Tests: IMAP via a fake `imaplib.IMAP4_SSL` class; forwarded phish → original analysed; DMARC aggregate XML
  sample (Google/Microsoft formats, zip and gz) → rows parsed; XML bomb rejected by defusedxml.

### Task 11: Traceability, accuracy measurement, docs

**Files:** Modify `docs/requirements/01-requirements-register.md` (section P: EML-01…EML-20), tests carry
`@pytest.mark.req("EML-xx")`; Create `backend/scripts/email_accuracy.py` (runs `analyse` over
`<folder>/phish/*.eml` and `<folder>/legit/*.eml`, prints precision, recall, confusion matrix, writes
`docs/reports/EMAIL-ACCURACY.md`), `docs/architecture/09-EMAIL.md`; Modify `docs/decisions/DECISION-LOG.md` (D-28),
`docs/guides/DEPLOYMENT.md` (new keys, containers, mailbox and DNS steps), architecture README.

- [ ] Full test suite + UAT report regenerated; accuracy report produced as soon as the owner supplies labelled emails.
