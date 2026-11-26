# Phishing Email Monitoring — Design Spec

- **Date:** 2026-10-08 · **Status:** Draft — awaiting owner approval
- **Owner choices (2026-10-08):** intake = upload `.eml/.msg` + reporting mailbox (IMAP) + DMARC reports + Microsoft 365 /
  Google Workspace connector; engines = Rspamd + ClamAV + YARA; threat intel = URLhaus + OpenPhish + urlscan.io +
  AbuseIPDB; also detect look-alike *email* domains of the brand ("close to mykcpl.com but not ours").
- **Scope change:** new module beyond the original Phase-1 requirements (new register section EML, decision D-28).

## 1. What it adds — four capabilities

| # | Capability | Answers the question |
|---|---|---|
| A | **Email analysis** | "Is this email a phishing attempt against our brand?" — any email that arrives (upload, mailbox, M365/Google) |
| B | **Brand email-domain posture** | "Can someone spoof *our own* domains?" — SPF, DMARC (incl. duplicate/invalid records, `p=none`), DKIM, MTA-STS, BIMI for every official domain |
| C | **Look-alike email domains** | "Which domains close to ours are set up to send or receive email?" — extends the domain pipeline: MX + SPF + DMARC + DKIM on every registered look-alike |
| D | **DMARC report monitoring** | "Who is sending email *as* our domain right now?" — parses aggregate (rua) / forensic (ruf) reports: every IP sending as `@mykcpl.com`, pass/fail, volumes |

A and C are linked both ways with the existing website pipeline: every URL in an email is analysed by the phishing-website
pipeline (screenshot, favicon/logo, keywords, TLS, WHOIS); a sender domain that is already a look-alike alert links the
two alerts.

## 2. Pipeline for one email (capability A)

```
intake (upload / IMAP / Graph / Gmail)
  → parse          headers, bodies (text+HTML), URLs, attachments, embedded images           [Python email + mail-parser]
  → authenticate   SPF / DKIM / DMARC / ARC verdicts + Rspamd score & symbols               [Rspamd, dkimpy, checkdmarc]
  → sender         From vs Reply-To vs Return-Path, display-name spoofing, domain age (RDAP),
                   sender-domain similarity to the brand, sender IP reputation               [whoisit, RapidFuzz, AbuseIPDB]
  → URLs           unwrap redirects (safe fetcher), reputation, live page analysis            [URLhaus, OpenPhish, urlscan.io,
                                                                                               existing domain/website pipeline]
  → attachments    true type, SHA-256, malware scan, pattern rules, text extraction,
                   macro detection (never executed)                                           [ClamAV, YARA, oletools,
                                                                                               existing extractors, URLhaus]
  → brand/content  brand terms (D-25 relevance), login/payment/urgency language,
                   logos in HTML/images vs official logos                                     [RapidFuzz, ImageHash]
  → score          deterministic points table + corroboration rule (§4)
  → alert          module "email" — same alerts, evidence, workflow, exports as all modules
```

Everything runs in isolated containers through the safe fetcher; attachments and links are **never opened by a person's
mail client or executed** — attachments are only scanned (ClamAV/YARA) and read as text.

## 3. Tools (each with a distinct job — no single point of truth)

| Tool | Licence | Role |
|---|---|---|
| Python `email` + **mail-parser** | stdlib / Apache-2 | MIME parsing, `.msg` via **extract-msg** |
| **Rspamd** (container) | Apache-2 | independent spam/phish engine: SPF/DKIM/DMARC/ARC checks, ~2,000 rules, URL/phish modules → score + symbols |
| **dkimpy**, **checkdmarc** | BSD / Apache-2 | second, independent SPF/DKIM/DMARC evaluation + posture checks (capability B/C) |
| **parsedmarc** | Apache-2 | DMARC aggregate/forensic report parsing (capability D) |
| **ClamAV** (container, `clamd`) | GPL-2 (separate process) | attachment malware signatures (daily updates) |
| **YARA** (`yara-python`) + curated public rule sets | BSD-3 / rule licences | phishing kit / maldoc / credential-harvest patterns |
| **oletools** | BSD | Office macro / OLE object detection (static) |
| **URLhaus** (abuse.ch) | free, commercial OK | malicious URL + payload hash database |
| **OpenPhish** community feed | free feed | known phishing URLs (refreshed every 6 h, cached locally) |
| **urlscan.io** | free tier (public scans) | independent sandboxed page verdict + screenshot |
| **AbuseIPDB** | free key, 1,000/day | sender-IP abuse reputation |
| Existing: safe fetcher, Playwright, RapidFuzz, ImageHash, whoisit, dnspython | — | reused from the platform |

Not used: SpamAssassin (overlaps Rspamd), VirusTotal free API (licence forbids commercial use), PhishTank (no new keys).

## 4. Risk scoring — precise and explainable

Same principles as §6 of the requirements: integer points per fact, capped at 100, Low <30 · Medium 30–59 ·
High 60–79 · Critical 80+, every fired rule shown in **Why this score**.

| Rule | Points | Fact (and which tool produced it) |
|---|---|---|
| `known_malicious_url` | +40 | URL listed by **≥2 independent** sources (URLhaus, OpenPhish, urlscan.io malicious verdict, our page analysis = Suspected Phishing) |
| `single_source_url_hit` | +15 | listed by exactly 1 source (corroboration rule — one tool alone cannot make an email Critical) |
| `malware_attachment` | +40 | ClamAV detection **or** hash known to URLhaus |
| `suspicious_attachment` | +20 | YARA match, macro/OLE object, executable/script/archive-with-executable, double extension |
| `auth_fail_brand_from` | +30 | From uses an official brand domain and DMARC fails (spoofing) |
| `lookalike_sender` | +25 | sender / Reply-To / link domain is a look-alike of the brand (similarity > 80 or existing look-alike alert) |
| `brand_impersonation` | +20 | brand terms (D-25) or official logo in an email **not** sent from an official domain |
| `reply_to_mismatch` | +10 | Reply-To / Return-Path domain differs from From and is not official |
| `credential_or_payment_language` | +15 | login / verify / password / OTP / card / payment / urgent / suspended language |
| `young_domain` | +10 | sender or link domain registered < 30 days |
| `bad_sender_ip` | +10 | AbuseIPDB confidence ≥ 75 |
| `rspamd_phish` | +10 | Rspamd score ≥ its reject threshold or phishing symbols fired |
| `live_phishing_page` | +20 | a linked page analysed by our website pipeline is Suspected Phishing |

Level range: all four. **Precision safeguards:** (1) corroboration rule above; (2) official senders that pass DMARC never
get brand-impersonation points; (3) every external verdict is stored as evidence with its timestamp and raw response;
(4) a source that is unreachable contributes **0**, never a guess, and is listed on the alert as "not checked";
(5) accuracy measured on a labelled set (phishing samples + legitimate brand emails) — precision/recall reported in the
UAT report. No system has zero error; this one makes every decision traceable.

Capability B (posture) produces alerts in module `email_posture`, scored by fixed findings: no/duplicate/invalid DMARC
(+40), `p=none` (+20), SPF missing/`+all` (+40) or `~all` (+10), no DKIM found on common selectors (+10),
no MTA-STS (+5). Capability C adds to existing domain alerts: SPF present on a look-alike (+10, new rule
`lookalike_can_send`), shown as **Email-ready** with the MX tier (D-02).
Capability D creates alerts for sources failing DMARC while sending as the brand, grouped per sending IP/organisation.

## 5. Data model additions (PostgreSQL — not MongoDB)

- `email_messages`: message-id, received_at, intake channel, from/reply-to/return-path, subject, sender IP, auth results
  (JSON), raw `.eml` stored in the evidence bucket (SHA-256), linked alert id.
- `email_indicators`: per message — URL / domain / IP / attachment hash, with each tool's verdict (JSON) and checked_at.
- `dmarc_reports`: reporter, period, domain, policy, source IP rows (count, SPF/DKIM/DMARC result).
- `mail_sources`: configured intakes (IMAP mailbox, M365 tenant, Google domain, DMARC mailbox) — secrets in `.env`, not DB.
- Alerts: new `ModuleName.email`, `email_posture`, `dmarc` (migration adds enum values).

## 6. Dashboard

- **Emails** page: upload `.eml/.msg` (drag-and-drop), list with verdict, sender, subject, score, intake channel.
- Alert detail for an email: header table (From/Reply-To/Return-Path/IP), SPF/DKIM/DMARC chips, each URL with its source
  verdicts, each attachment with ClamAV/YARA/hash results, rendered-safe preview (sanitised HTML, images blocked),
  linked website alerts.
- **Email security** tab on the brand page: posture of each official domain (B) and DMARC sender map (D).
- Executive dashboard: tiles "Phishing emails today", "Spoofed-sender attempts".

## 7. Containers & resources (this PC is near its memory limit)

| Container | RAM (approx.) |
|---|---|
| rspamd (+ uses existing Redis) | 150–300 MB |
| clamav (clamd with signatures) | 1.2–1.5 GB |
| intake worker (IMAP/Graph/Gmail pollers, queue `email`) | 200 MB |

ClamAV can be switched off (`CLAMAV_ENABLED=false`) without changing scores elsewhere.

## 8. External inputs needed

| Item | For |
|---|---|
| URLhaus auth key (https://auth.abuse.ch) | URL / hash reputation |
| urlscan.io API key | independent page verdicts |
| AbuseIPDB API key | sender-IP reputation |
| Reporting mailbox on the mail host (e.g. `phishing@mykcpl.com`): IMAP host, port, user, app password | email intake |
| DMARC mailbox (e.g. `dmarc@mykcpl.com`) + DNS change adding it to `rua=` on each official domain (keep MXToolbox too) | capability D |
| Optional: Microsoft 365 app registration (tenant, client id/secret, Mail.Read + admin consent) or Google Workspace service account (gmail.readonly, domain-wide delegation) | only if mail moves to M365/Google |
| 10–20 real phishing emails and 10–20 legitimate company emails (`.eml`) | accuracy measurement |

## 9. Testing

Unit tests for every scoring rule and the corroboration rule; parser tests on real-world `.eml` samples (multipart,
encoded headers, TNEF, `.msg`); fixture emails for acceptance tests (in the test database only, D-27); integration
tests against the Rspamd and ClamAV containers (EICAR test file for ClamAV); measured precision/recall on the
owner-provided labelled set.

## 10. Build order

1. Parser + upload + scoring + alert/evidence + dashboard page (works with no keys).
2. Rspamd, ClamAV, YARA containers and integration.
3. Threat-intel adapters (URLhaus, OpenPhish, urlscan.io, AbuseIPDB) with caching and quotas.
4. Posture (B) and look-alike email readiness (C).
5. IMAP mailbox intake; DMARC report intake (D); M365/Google connectors.
6. Accuracy run on labelled emails, UAT report update, docs (architecture doc 09, decision log D-28).
