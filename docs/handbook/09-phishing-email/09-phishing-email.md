# Chapter 9: Phishing Email Monitoring

**In this chapter**

- What the phishing-email module does and the four questions it answers for a brand.
- How a reported email travels from upload to a scored alert, step by step.
- Which tools it uses (Rspamd, ClamAV, YARA, URLhaus, OpenPhish, urlscan.io, AbuseIPDB) and why.
- How the risk score is calculated, what analysts see, what evidence is kept, and what the module cannot do yet.

All statements describe the code as of 2026-10-09. The running example is a fictional bank, **Example Bank**, whose real website and email domain is `examplebank.com`.

---

## 1. What this module does and why it matters

### 1.1 A short email-security primer

Before the module makes sense, you need a handful of terms. Each one is explained with Example Bank.

| Term | Plain explanation | Example Bank example |
|---|---|---|
| **From** | The sender address you see in your mail app. Anyone can type anything here; it is not proof of who sent the email. | `From: Example Bank <alerts@examplebank.com>` |
| **Reply-To** | Where your reply goes if you press Reply. Fraudsters set it to their own mailbox so the conversation leaves the bank. | `Reply-To: support@examplebank-help.com` |
| **Return-Path** | The hidden "bounce" address used by mail servers when delivery fails. Also called the envelope sender or MAIL FROM. | `Return-Path: bounce@mailer.cheap-sender.net` |
| **Received headers** | Every mail server that handles the message adds a `Received:` line, like stamps on a parcel. The oldest one (at the bottom) is closest to the real sender and usually contains the sender's IP address. | `Received: from unknown (203.0.113.45) ...` |
| **SPF** (Sender Policy Framework) | A DNS record in which a domain lists the servers allowed to send its mail. Receivers check the sending server against this list. | `examplebank.com TXT "v=spf1 include:_spf.mailhost.com -all"` |
| **DKIM** (DomainKeys Identified Mail) | A digital signature added to each email by the sending domain. The public key is published in DNS under a "selector" name. A valid signature proves the message was not altered and came from someone holding the domain's key. | key at `selector1._domainkey.examplebank.com` |
| **DMARC** | A DNS record (`_dmarc.examplebank.com`) that says: "an email claiming to be From examplebank.com must pass SPF or DKIM *for a matching domain* (alignment). If it does not, do this." The action is the policy `p=none` (only report), `p=quarantine` (spam folder) or `p=reject` (refuse). | `v=DMARC1; p=reject; rua=mailto:dmarc@examplebank.com` |
| **Alignment** | DMARC's key idea: passing SPF for `cheap-sender.net` does not help an email whose From says `examplebank.com`. The authenticated domain must match the From domain (exactly in "strict" mode, same registered domain in "relaxed" mode). | |
| **Authentication-Results** | A header the *receiving* mail server writes, recording its SPF/DKIM/DMARC verdicts. | `spf=fail; dkim=none; dmarc=fail header.from=examplebank.com` |
| **MTA-STS** | A DNS + HTTPS policy telling other mail servers to only deliver to the domain over encrypted, verified connections. Prevents downgrade and interception attacks. | `_mta-sts.examplebank.com TXT "v=STSv1; id=..."` |
| **DMARC aggregate report (rua)** | A daily XML file that big receivers (Gmail, Microsoft, Yahoo) send to the address in `rua=`. It lists every IP address that sent mail claiming to be the domain, how many messages, and whether they passed. | |
| **Spam engine** | Software that scores a whole message using hundreds of rules (headers, content, links, authentication). | Rspamd |
| **Antivirus** | Software that compares files against a database of known malware signatures. | ClamAV |
| **YARA rule** | A small text "pattern recipe" (strings + conditions) that matches suspicious content inside a file. | "HTML with a password field and urgency words" |
| **Threat-intel feed** | A public or commercial list of URLs, file hashes or IPs already known to be malicious. | URLhaus, OpenPhish |

### 1.2 The four capabilities

The module (decision D-28) answers four separate questions. Each produces findings (and alerts, when the brand's alert rule is met) in the same lists, with the same analyst decisions, timeline, evidence and exports as every other module.

| Capability | Question it answers | Alert module name |
|---|---|---|
| **A. Email analysis** | "Is this reported or uploaded email a phishing attempt against our brand?" | `email` ("Phishing Email Analysis") |
| **B. Brand domain posture** | "Can someone spoof *our own* domains?" | `email_posture` ("Email Domain Security") |
| **C. Email-ready look-alikes** | "Which look-alike domains are set up to send email?" | adds a rule to existing domain findings |
| **D. DMARC aggregate reports** | "Who is sending email as our domain right now, and failing?" | `dmarc` ("DMARC Spoofing Reports") |

**Attack story A.** A customer receives "Your Example Bank account is suspended, verify within 24 hours" from `alerts@exarnplebank.com` (an "rn" posing as an "m"). The link goes to a fake login page. The customer forwards it to the bank's `phishing@` mailbox. The module parses it, sees the look-alike sender, checks the link against threat feeds, opens the linked page in an isolated browser, and raises a Critical alert with all the evidence.

**Attack story B.** Example Bank publishes `p=none` in its DMARC record. That means a fraudster can send email with `From: security@examplebank.com` from any server, and receivers will deliver it (they only report it). The posture check flags this so the bank can move to `p=reject`.

**Attack story C.** A criminal registers `examplebank-secure.com` and publishes an SPF record. The domain has no website yet, but it is ready to send mail. The domain pipeline (Chapter on typosquat/MX monitoring) adds a "can send email" rule to that domain's alert.

**Attack story D.** Gmail's daily DMARC report for `examplebank.com` shows 4,200 messages from IP `198.51.100.7` that failed both SPF and DKIM. That is someone spoofing the bank at scale. The module raises an alert for that IP.

---

## 2. Requirements covered

These IDs come from `docs/requirements/01-requirements-register.md` (section EML).

| ID | Requirement | Status in register |
|---|---|---|
| EML-01 | Parse uploaded .eml/.msg emails (headers, bodies, attachments) | Tested |
| EML-02 | Extract and unwrap URLs (Safe Links, Proofpoint, Google, hxxp/[.]) | Tested |
| EML-03 | Analyse the attached original of a forwarded report | Tested |
| EML-04 | Read SPF/DKIM/DMARC from Authentication-Results | Tested |
| EML-05 | Independent DMARC alignment evaluation | Tested |
| EML-06 | Rspamd spam/phishing scoring | Tested |
| EML-07 | ClamAV attachment malware scan | Tested |
| EML-08 | YARA phishing/malware pattern rules | Tested |
| EML-09 | Threat intel: URLhaus, OpenPhish, urlscan.io, AbuseIPDB (cached, corroborated) | Tested |
| EML-10 | Deterministic risk scoring with the 2-source corroboration rule | Tested |
| EML-11 | Official DMARC-pass senders are never scored as impersonation | Tested |
| EML-12 | Email scoring rules in the shared model | Tested |
| EML-13 | Upload API, storage of raw .eml, dedupe | Tested |
| EML-14 | Email alert with evidence and the module's output fields | Tested |
| EML-15 | Brand domain email posture (SPF/DMARC/DKIM/MTA-STS) | Tested |
| EML-16 | Detect duplicate/invalid/`p=none` DMARC and permissive SPF | Tested |
| EML-17 | Look-alike domains flagged when email-ready (SPF present) | Tested |
| EML-18 | DMARC aggregate report parsing (xml/gz/zip, XML-bomb safe) | Tested |
| EML-19 | IMAP reporting-mailbox intake | Tested |
| EML-20 | Dashboard: emails page, email alert view, email-security panel | Verified |

---

## 3. The complete process for each capability

### 3.1 Capability A: analysing one email

An email reaches the platform in one of two working ways today:

1. **Upload** by an analyst on the Emails page (`.eml`, `.msg` or `.txt`).
2. **Reporting mailbox**: Celery Beat polls an IMAP mailbox (for example `phishing@examplebank.com`) every 5 minutes.

```
  Analyst uploads file                       IMAP mailbox (every 5 min, Celery Beat)
          |                                              |
          v                                              v
  POST /api/v1/emails                         poll_reporting_mailbox()
  - size <= 25 MB, .eml/.msg/.txt             - fetch UNSEEN, mark \Seen
  - quick parse: is it an email?              - uses the oldest active brand
  - store_raw_email() -> MinIO + row "queued" - process_email() runs inline
  - analyse_email.delay(id)                                |
  - returns 202 + email detail                             |
          |                                                |
          v                                                |
  Celery task analyse_email  (retries 2x, 120 s apart;     |
    still failing -> status "failed" + reason)             |
  - load raw bytes from MinIO                              |
          |                                                |
          +-----------------------+------------------------+
                                  v
                          analyse_stored()
                                  |
   1. parse()            headers, text, HTML, URLs, attachments, forwarded original
   2. authenticate()     header SPF/DKIM/DMARC + our own DMARC alignment check
   3. URL intel          URLhaus, OpenPhish, urlscan.io for every URL; count agreeing sources
   4. live page check    first 5 URLs opened in the isolated browser, website pipeline
   5. attachments        ClamAV, YARA, URLhaus hash, macros, executables, double extensions
   6. sender checks      look-alike similarity, brand terms, Reply-To mismatch, language
   7. engines + IP       Rspamd score/symbols, AbuseIPDB for the sender IP, domain age (WHOIS)
   8. Signals            13 true/false facts
                                  |
                                  v
                    record_detection(channel "upload"/"mailbox") -> score()
                    -> finding (module "email") + observation; alert if risk >= "Alert from"
                    + evidence stored, indicators table rewritten, row "analysed"
```

**Step by step.**

1. **Upload checks** (`api/emails.py: upload_email`). The brand must exist (404 otherwise). Files over 25 MB get 413. Only `.eml`, `.msg`, `.txt` names are accepted (422). The file is parsed once quickly; if the parser produced warnings and found no From, Subject or Message-ID, the API rejects it with "This file does not look like an email message" (422).
2. **Store raw** (`service.store_raw_email`). A **fingerprint** is computed: the Message-ID header, or the SHA-256 of the raw bytes if there is no Message-ID. If the brand already has a row with this fingerprint, that row is reused and set back to `queued` (deduplication). Otherwise the raw message is saved to object storage (MinIO) under `emails/<brand>/<fingerprint>-<sha>.eml` and a new `email_messages` row is created.
3. **Queue.** The API commits, calls `analyse_email.delay()`, and answers **202 Accepted** with the current detail. If the message broker is down, the error is swallowed and the email stays `queued`.
4. **Celery worker** (`workers/tasks.py: analyse_email`) loads the raw bytes from storage and calls `analyse_stored()`.
5. **Parse** (`parser.parse`). Converts Outlook `.msg` to standard format with `extract-msg`, then reads headers and parts with Python's built-in `email` library. If the email is a *forward* that carries the original as an attachment (`message/rfc822`), the **original** is analysed instead and the forwarder is recorded (`forwarded_by`). URLs are pulled from text, HTML links and the `List-Unsubscribe` header, then unwrapped (Microsoft Safe Links, Google redirects, Proofpoint URL Defense, up to 3 levels) and "re-fanged" (`hxxps://evil[.]com` becomes `https://evil.com`). Attachments are hashed (SHA-256), capped at 50 per email and 30 MB each, and ZIP member names are listed. The sender IP is the first *public* IP found in the Received chain, reading from the oldest header. The parser never raises; problems become warnings.
6. **Authenticate** (`auth.authenticate`). Two opinions: (a) the SPF, DKIM, DMARC and ARC words in the receiver's `Authentication-Results` header; (b) our own DMARC check: look up `_dmarc.<from-domain>` via DNS (Cloudflare 1.1.1.1 and Google 8.8.8.8), then decide pass/fail from whether the header's SPF or DKIM pass is *aligned* with the From domain (strict or relaxed as the record says). Results: `pass`, `fail`, `none` (no record) or `temperror` (DNS failed). The analysis uses the header's DMARC verdict when present and falls back to our own.
7. **URL reputation** (`intel.url_reputation`). Each URL is checked against URLhaus, OpenPhish and urlscan.io. `intel.corroborated()` counts how many *different* tools said malicious. The highest count across all URLs is kept.
8. **Live page check** (`analysis._live_page_phishing`). The first 5 URLs are opened in the platform's isolated headless Chromium (`core/browser.capture`, which first checks the destination is not a private address) and analysed by the same page checker used for phishing websites. A page counts as a hit if it has login/payment wording, the brand's favicon, or a logo match of 85 or more. A hit adds **one extra source** to the highest corroboration count and saves the screenshot as evidence.
9. **Attachments** (`attachments.analyse_attachment`). Each file goes to ClamAV and YARA and its hash to URLhaus. "Malware" means ClamAV found a signature or URLhaus knows the hash. "Suspicious" means any of: executable/script extension, double extension (`invoice.pdf.exe`), Office file with macros (oletools), archive containing an executable, or a YARA match. Nothing is ever executed.
10. **Sender and content checks.** Look-alike: any sender, Reply-To, Return-Path or link domain that is not official and is more than 80% similar to a brand label. Brand impersonation: brand terms appear in the subject/body (using the shared relevance check, D-25) and the sender is not official. Reply-To mismatch. Credential/payment/urgency language (for example "verify", "password", "OTP", "suspended", "within 24 hours").
11. **Engines and IP.** The whole raw message goes to Rspamd. The sender IP goes to AbuseIPDB. The youngest WHOIS creation date among the non-official sender and link domains is found.
12. **Score and store** (`core/findings.record_detection`). The 13 facts become a `Signals` object inside a `Detection`, the shared `score()` function turns them into points and a level, and the finding with key `email:<fingerprint>` is created or updated. Because an email is not part of a scan, the call has no scan ID; the observation records the channel instead: `upload` for a file uploaded on the dashboard, `mailbox` for one read from the phishing mailbox. Evidence is stored, the `email_indicators` rows for this email are replaced, the email row is linked to the finding (`email_messages.finding_id`) and marked `analysed` with a summary ("Likely phishing", "Suspicious" or "Low risk").

**Candidate or Finding? (SP2, D-33)** An analysed email is always a **Finding** (the same holds for posture and DMARC results), because the module only reports what it has fully checked. Whether it becomes an **alert** depends on the brand's "Alert from" level (default Medium, D-34): a "Low risk" email is kept on the Emails and Findings pages but does not enter the alert queue. Uploading the same email again adds an observation to the same finding; a new alert is raised only if the risk level rises (D-36).

### 3.2 Capability B: brand domain posture

```
Celery Beat 03:00 daily  -> schedule_all(runners=["email_posture"])
                                   |
                                   v
                     PostureModule.run(brand)        (scan component "DNS TXT lookups")
                     for each official domain + allow-listed email domain:
                                   |
          +-------------+----------+-----------+--------------------+
          v             v                      v                    v
   TXT _dmarc.<d>   TXT <d> (v=spf1)   TXT <selector>._domainkey.<d>   TXT _mta-sts.<d>
   0/1/2+ records   none/many/+all/~all  14 common selectors tried     present?
          |             |                      |                    |
          +-------------+----------+-----------+--------------------+
                                   v
                 no problems -> nothing;  otherwise Detection "posture:<domain>"
                                   v
     record_detection() -> score() -> finding module "email_posture"
                           (alert if risk >= brand "Alert from" level)
```

For Example Bank, `posture.evaluate("examplebank.com")` checks:

- **DMARC**: missing, more than one record (receivers then ignore DMARC), no `p=` tag, or `p=none`. A malformed extra record is reported as an issue.
- **SPF**: missing, more than one record (invalid), `+all` (anyone may send), or `~all` (softfail: spoofed mail is only marked).
- **DKIM**: the tool cannot list all DKIM keys (DNS does not allow that), so it tries 14 common selector names: `default, selector1, selector2, google, k1, s1, s2, dkim, mail, smtp, mandrill, mailgun, zoho, amazonses`.
- **MTA-STS**: whether a `_mta-sts` TXT record exists.

Like every scan runner, the posture runner reports its work as a scan component (D-31): "DNS TXT lookups" is
`ok` for each domain checked, `failed` with the domain and error when a lookup crashes, and `skipped` when the
brand has no official or email domains. The run state (`completed`, `completed_with_errors`, ...) follows from it.

### 3.3 Capability C: look-alike domains that can send email

This lives inside the domain pipeline (`modules/domains/module.py`), not a separate scan.

```
domain pipeline finds registered look-alike  "examplebank-secure.com"
        |
        v
_email_records(): TXT examplebank-secure.com     -> SPF records
                  TXT _dmarc.examplebank-secure.com -> DMARC records
        |
        v
posture.domain_can_send(spf)  -> True if any record starts "v=spf1"
        |
        v
Signals(lookalike_can_send=True)  (+10)   details: "SPF Record", "DMARC Record",
                                                    "Email-ready" = SPF present OR MX present
```

Note the difference: MX records mean the domain can *receive* mail (already scored by the MX rule); an SPF record means it is configured to *send*.

### 3.4 Capability D: DMARC aggregate reports

```
Example Bank DNS:  _dmarc.examplebank.com  "...; rua=mailto:dmarc@examplebank.com"
        |
Gmail / Outlook / Yahoo send daily XML (often .gz or .zip) to dmarc@examplebank.com
        |
Celery Beat, minute 15 of every hour -> poll_dmarc_mailbox()
        |
        v
IMAP fetch UNSEEN -> attachments ending .xml/.gz/.zip
        |
        v
dmarc.parse_report()   unzip/gunzip, parse with defusedxml (refuses XML bombs)
        |              metadata: reporter, report id, domain, policy, date range
        |              one row per source IP: count, disposition, SPF, DKIM, header_from
        v
match report domain to a brand's official domains (unknown domain -> ignored)
        |
        v
store_and_findings():  every row -> dmarc_reports table (deduplicated)
                       rows where SPF and DKIM both did not pass ->
                       Detection "dmarc:<domain>:<ip>"  (auth_fail_brand_from, +30)
        |
        v
record_detection() -> finding module "dmarc" (scan runner: with scan ID;
                      DMARC mailbox: channel "mailbox") -> alert if risk >= "Alert from"
```

A row passes when the report says DKIM pass *or* SPF pass. Passing rows are stored but create no finding (they are legitimate senders such as the bank's own mail provider).

---

## 4. Tools

| Tool | What it is | What we use it for | Why this tool (and rejected alternatives) | Where in the code |
|---|---|---|---|---|
| Python `email` library | Built-in MIME parser | Reading headers, bodies, attachments | Standard, no extra dependency. **mail-parser** was proposed but not used: stdlib already covers it (D-28). | `email/parser.py` |
| extract-msg | Library that reads Outlook `.msg` files | Converting `.msg` to standard email bytes | Only open-source option for the Outlook format | `parser._to_eml` |
| dnspython | DNS client | DMARC, SPF, DKIM, MTA-STS lookups | Already used by the domain pipeline | `auth.dmarc_lookup`, `posture._resolve_txt` |
| Rspamd | Open-source spam filtering server, run as its own container | Independent whole-message spam/phish score and rule names ("symbols") | Fast, maintained, many built-in rules. **SpamAssassin** dropped because Rspamd covers the same ground (D-28). | `engines.rspamd_check` |
| ClamAV (`clamd`) | Open-source antivirus daemon, own container | Malware signatures in attachments | Free, daily signature updates, runs as a separate process | `engines.clamav_scan` |
| YARA (`yara-python`) | Pattern-matching engine for files | Bundled phishing/maldoc rules in `backend/rules/yara/phishing.yar` | Industry standard for analyst-written rules; runs in-process | `engines.yara_scan` |
| oletools | Static analyser for Microsoft Office files | Detecting VBA macros | Reads macros without running them | `attachments._has_macros` |
| URLhaus (abuse.ch) | Free database of malware URLs and payload hashes | URL lookups and attachment hash lookups | Free and allows commercial use. **VirusTotal** not used: its free API licence forbids commercial use (D-28). | `intel.urlhaus_url`, `intel.urlhaus_hash` |
| OpenPhish community feed | Free text list of live phishing URLs | Exact URL matches | Replaces **PhishTank**, which is not issuing new API keys (D-28) | `intel.openphish_hit` |
| urlscan.io | Service that scans web pages in a sandbox and stores verdicts | Looking up an existing malicious verdict for the URL | Independent of our own browser check | `intel.urlscan_lookup` |
| AbuseIPDB | Crowd-sourced database of abusive IP addresses | Sender IP reputation | Free key, 1,000 checks/day | `intel.abuseipdb_check` |
| Redis | In-memory store (already used by Celery) | 24-hour cache of intel answers; 6-hour cache of the OpenPhish feed | Saves API quota | `intel._cached` |
| defusedxml | Hardened XML parser | DMARC report parsing | Blocks XML-bomb and external-entity attacks. **parsedmarc** not used: it pulls in Elasticsearch/Kafka (D-28). | `dmarc.parse_report` |
| Playwright + page checker | Headless browser and the website-pipeline analyser | Opening linked pages, screenshot, logo/favicon/keyword checks | Reuses the existing phishing-website pipeline | `analysis._live_page_phishing` |
| RapidFuzz similarity | String-similarity library (shared helper) | Look-alike sender/link domains | Shared with domain monitoring | `core/similarity.best_similarity` |
| PostgreSQL | The platform's relational database | `email_messages`, `email_indicators`, `dmarc_reports` | The platform already uses it; **MongoDB** was proposed and rejected (D-28) | `db/models.py` |
| MinIO (S3) | Object storage | Raw `.eml` files, attachments, screenshots | Shared evidence store | `core/evidence.py` |
| Celery + Beat | Background job queue and scheduler | Analysis, mailbox polling, daily posture scan | Shared platform worker | `workers/tasks.py`, `workers/celery_app.py` |

Also installed but **not currently called** by the email code: `dkimpy`, `pyspf` and `checkdmarc` (listed in `pyproject.toml`; see section 12).

---

## 5. How each tool works internally, simply

**Python email parser.** An email is a text file with headers on top and a body below. Modern emails are "multipart": the body is split into parts (plain text, HTML, each attachment), each with its own type and encoding (often Base64). The parser walks this tree and decodes each part.

**Rspamd.** We POST the raw message to its `/checkv2` endpoint. Rspamd runs many small tests ("symbols", for example `PHISHING`, `FORGED_SENDER`, `DMARC_POLICY_REJECT`), each adding a weight, and returns a total score plus a recommended action (`no action`, `add header`, `rewrite subject`, `reject`). We treat the message as Rspamd-phishy if the action is `reject`, `add header` or `rewrite subject`, or if any fired symbol name contains one of: `PHISHING, PHISHED, DMARC_POLICY_REJECT, DMARC_POLICY_QUARANTINE, SPOOF, FORGED_SENDER, FAKE_REPLY, URL_PHISHED, CLAM_VIRUS`.

**ClamAV.** We open a network socket to `clamd` on port 3310, send the `zINSTREAM` command, stream the file in 64 KB chunks (up to 40 MB) and read the one-line reply. `... FOUND` means a signature matched (we record its name); `... OK` means clean.

**YARA.** A rule is a list of strings plus a condition, for example "contains `password` AND contains `verify` AND contains a `<form`". All `.yar`/`.yara` files in `YARA_RULES_DIR` are compiled once and kept in memory. The bundled file has three rules: `credential_harvest_form`, `brand_login_lookalike` and `obfuscated_script_in_email`. Only attachments are scanned with YARA.

**oletools.** Old and macro-enabled Office files are containers. `VBA_Parser` looks inside for a VBA macro stream and reports whether one exists, without running it.

**URLhaus.** We POST the URL (or the SHA-256 hash) with our Auth-Key. A `query_status` of `ok` means URLhaus has it on record, which we treat as malicious.

**OpenPhish.** We download the whole feed (one URL per line), keep it in Redis for 6 hours, and check for an exact match (with or without a trailing slash).

**urlscan.io.** We search past scans for `page.url:"<url>"` and read the newest result's overall verdict.

**AbuseIPDB.** We ask for the IP's "abuse confidence score" (0 to 100) over the last 90 days. 75 or more counts as malicious.

**Caching and failures.** Every intel answer that succeeded is cached in Redis for 24 hours under a hashed key. If a key is missing, the service errors, times out or returns a non-200 status, the tool returns the status `not_checked` and is listed on the alert. Rspamd and ClamAV return `not_checked` when their container cannot be reached; ClamAV also when `CLAMAV_ENABLED=false`; YARA when no rules are found.

**DMARC aggregate XML.** Each report has `report_metadata` (who sent it, date range), `policy_published` (the domain's policy) and many `record` elements, each with a `row` (source IP, count, evaluated DKIM/SPF/disposition) and `identifiers` (header From).

---

## 6. Code map

Files in call order for capability A, then B, C and D. Paths are relative to `backend/app/`.

| Order | File | Key functions | Role |
|---|---|---|---|
| 1 | `api/emails.py` | `upload_email`, `list_emails`, `get_email`, `_detail` | REST endpoints under `/api/v1/emails` |
| 2 | `modules/email/intake/mailbox.py` | `poll_reporting_mailbox`, `poll_dmarc_mailbox`, `_extract_report_attachments` | Mailbox pollers |
| 3 | `modules/email/intake/imap.py` | `ImapSource.fetch_new` | Reads UNSEEN messages over IMAP SSL |
| 4 | `modules/email/intake/graph.py`, `gmail.py` | `GraphSource`, `GmailSource`, `source_from_config` | Optional Microsoft 365 / Google adapters (not yet wired to a poller) |
| 5 | `modules/email/service.py` | `store_raw_email`, `fingerprint`, `process_email`, `analyse_stored`, `email_detail` | Storage, dedupe, orchestration |
| 6 | `workers/tasks.py` | `analyse_email`, `poll_mailbox`, `poll_dmarc`, `schedule_all` | Celery tasks |
| 7 | `workers/celery_app.py` | `beat_schedule` | Mailbox every 5 min, DMARC hourly at :15, posture daily 03:00 |
| 8 | `modules/email/parser.py` | `parse`, `_to_eml`, `_collect_parts`, `_fill_headers`, `_public_ip`, `_merge_urls` | Raw bytes to `ParsedEmail` |
| 9 | `modules/email/urls.py` | `extract_urls`, `unwrap`, `deobfuscate`, `extract_images` | Link extraction and unwrapping |
| 10 | `modules/email/model.py` | `ParsedEmail`, `UrlRef`, `Attachment`, `ToolVerdict` | Shared data shapes |
| 11 | `modules/email/analysis.py` | `analyse`, `_live_page_phishing`, `_language_flags`, `_domain_age_days` | Builds the Signals, details, indicators, evidence |
| 12 | `modules/email/auth.py` | `authenticate`, `dmarc_lookup`, `_aligned` | SPF/DKIM/DMARC verdicts |
| 13 | `modules/email/intel.py` | `url_reputation`, `corroborated`, `urlhaus_url`, `urlhaus_hash`, `openphish_hit`, `urlscan_lookup`, `abuseipdb_check` | Threat intel with Redis cache |
| 14 | `modules/email/attachments.py` | `analyse_attachment`, `_has_macros`, `_archive_has_executable` | Static attachment checks |
| 15 | `modules/email/engines.py` | `rspamd_check`, `clamav_scan`, `yara_scan` | Engine adapters |
| 16 | `core/scoring.py` | `Signals`, `RULE_POINTS`, `score` | Points and risk level |
| 17 | `core/findings.py` | `record_detection`, `_store_evidence`, `meets_rule` | Finding create/update, observation, timeline, alert rule, evidence |
| 18 | `modules/email/posture.py` | `PostureModule.run`, `evaluate`, `domain_can_send` | Capability B (and helper for C) |
| 19 | `modules/domains/module.py` | `_email_records`, `check_domain` | Capability C |
| 20 | `modules/email/dmarc.py` | `parse_report`, `store_and_findings` | Capability D |
| 21 | `modules/registry.py` | `OUTPUT_FIELDS`, `MODULE_LABELS`, `RUNNERS` | Columns and labels |

---

## 7. Scoring

### 7.1 How scoring works

All modules share one function, `core/scoring.score()`. A module reports *facts* (true/false signals); the function adds the points of every fact that is true, caps the total at 100, and maps it to a level: **Low 0-29, Medium 30-59, High 60-79, Critical 80-100**. All three email modules may use all four levels. The website-only score caps from D-29 do not apply to email modules. Every fired rule is saved on the alert so the analyst sees "Why this score".

### 7.2 Email analysis rules (module `email`)

| Rule | Points | Fires when |
|---|---|---|
| `known_malicious_url` | 40 | Some URL is flagged malicious by **2 or more different sources** (live page hit counts as one) |
| `single_source_url_hit` | 15 | The highest count is exactly 1 source |
| `malware_attachment` | 40 | ClamAV signature found, or attachment hash known to URLhaus |
| `suspicious_attachment` | 20 | A non-malware attachment has an executable/script type, double extension, macros, an executable inside an archive, or a YARA match |
| `auth_fail_brand_from` | 30 | From domain is an official brand domain and DMARC verdict is `fail` |
| `lookalike_sender` | 25 | A non-official sender, Reply-To, Return-Path or link domain is more than 80% similar to the brand, and the sender is not official |
| `brand_impersonation` | 20 | Brand terms appear in subject/body and the sender is not official |
| `reply_to_mismatch` | 10 | Reply-To domain differs from the From domain and is not official |
| `credential_or_payment_language` | 15 | Phishing keywords or urgency phrases found |
| `young_domain` | 10 | Youngest non-official sender/link domain is under 30 days old (WHOIS) |
| `bad_sender_ip` | 10 | AbuseIPDB confidence 75 or more |
| `rspamd_phish` | 10 | Rspamd action/symbols indicate phishing |
| `live_phishing_page` | 20 | A linked page looked like phishing in our browser check |

### 7.3 Posture, look-alike and DMARC rules

| Rule | Points | Used by |
|---|---|---|
| `posture_dmarc_missing` | 40 | No DMARC, duplicate records, or no `p=` tag |
| `posture_dmarc_none` | 20 | `p=none` |
| `posture_spf_missing` | 40 | No SPF, multiple SPF records, or `+all` |
| `posture_spf_softfail` | 10 | `~all` |
| `posture_dkim_missing` | 10 | None of the 14 common selectors found |
| `posture_mta_sts_missing` | 5 | No `_mta-sts` record |
| `lookalike_can_send` | 10 | Look-alike domain publishes SPF (domain modules) |
| `auth_fail_brand_from` | 30 | DMARC report row failing SPF and DKIM (module `dmarc`) |

So a DMARC report alert scores 30 (Medium). A brand domain with no DMARC, no SPF, no DKIM and no MTA-STS scores 40+40+10+5 = 95 (Critical). A domain with `p=none` and `~all` but DKIM and MTA-STS in place scores 20+10 = 30 (Medium).

### 7.4 The three precision safeguards

1. **Two-source corroboration.** `intel.corroborated()` counts *distinct* tools that said malicious. One feed alone gives only 15 points (`single_source_url_hit`), never the 40 of `known_malicious_url`. This stops one wrong feed entry from making an email Critical on its own.
2. **Official senders passing DMARC are never impersonators.** `official_sender` is true when the From domain is one of the brand's official domains and the DMARC verdict is `pass`. Then `lookalike_sender` and `brand_impersonation` cannot fire. A genuine Example Bank newsletter that mentions "Example Bank" and "verify your account" gets at most the language points (15, Low).
3. **Unreachable tools are "not checked", never guessed.** A missing key, a down container or an error returns `not_checked`, contributes 0 points, and is listed in the alert's **Not Checked** field and in the email's `not_checked` list (tool and target).

### 7.5 Worked example

An email arrives at `phishing@examplebank.com`:

```
From: Example Bank Security <alerts@exarnplebank.com>
Reply-To: help@examplebank-support.net
Subject: Your account is suspended - verify within 24 hours
Body: "...log in here: https://exarnplebank.com/login ..."
Authentication-Results: mx.examplebank.com; spf=pass smtp.mailfrom=exarnplebank.com; dkim=none; dmarc=none
```

Configuration: URLhaus key set, urlscan.io key **not** set, AbuseIPDB key set, Rspamd and ClamAV running. No attachment.

| Check | Result | Rule | Points |
|---|---|---|---|
| URLhaus | URL listed | | |
| OpenPhish | not listed | | |
| urlscan.io | no key, "not checked" | | |
| Live page | login page, logo match 90, counts as +1 source | `live_phishing_page` | 20 |
| Corroboration | URLhaus (1) + live page (1) = 2 sources | `known_malicious_url` | 40 |
| Sender | `exarnplebank.com` is over 80% similar to "examplebank", not official | `lookalike_sender` | 25 |
| Brand terms | "Example Bank" in the text, sender not official | `brand_impersonation` | 20 |
| Reply-To | `examplebank-support.net` differs from From and is not official | `reply_to_mismatch` | 10 |
| Language | "suspended", "verify", "log in", "within 24 hours" | `credential_or_payment_language` | 15 |
| WHOIS | domain created 6 days ago | `young_domain` | 10 |
| AbuseIPDB | confidence 20 | (no rule) | 0 |
| Rspamd | `add header` | `rspamd_phish` | 10 |
| DMARC fail on brand domain | From is not an official domain | (no rule) | 0 |

Arithmetic: 20 + 40 + 25 + 20 + 10 + 15 + 10 + 10 = **150**, capped at **100**. Level **Critical**. Verdict summary: "Likely phishing". Alert title: "Likely phishing email from alerts@exarnplebank.com: Your account is suspended - verify within 24 hours". Not Checked: `urlscan`.

**Same email, but no live page and only URLhaus?** Then the count is 1: `single_source_url_hit` 15 instead of 40, no `live_phishing_page`. Total 15 + 25 + 20 + 10 + 15 + 10 + 10 = 105, still capped at 100 (Critical), because many independent facts agree. By contrast, a generic email that does not mention the bank, from an ordinary domain, with one URLhaus-listed link and the word "verify" would score only 15 + 15 (language) = 30, Medium.

**A genuine Example Bank email** from `alerts@examplebank.com` with `dmarc=pass` and the words "verify your account": official sender, so only `credential_or_payment_language` fires: **15, Low**.

---

## 8. Output fields shown to analysts

From `OUTPUT_FIELDS` in `modules/registry.py`.

**Phishing Email Analysis (`email`)**

| Field | Meaning |
|---|---|
| Subject, From, Sender Domain | From the (original) email headers |
| Reply-To, Return-Path | Where replies and bounces go |
| Sender IP | First public IP in the Received chain |
| Risk Level | Low / Medium / High / Critical |
| Verdict | Likely phishing / Suspicious / Low risk (from the email row) |
| SPF, DKIM | Receiver's header verdicts |
| DMARC | Header verdict plus "(independent: ...)" our own result |
| Rspamd | Rspamd action, or `not_checked`/`error` |
| URLs, Malicious URLs | Count of URLs; URLs flagged by at least one source |
| Attachments, Malicious Attachments | Count; names flagged malware or suspicious |
| Brand Match | Brand terms found |
| Look-alike Domains | Non-official sender/link domains |
| Language Flags | Up to 12 matched phishing/urgency words |
| Not Checked | Tools that could not give an answer |
| Channel, Received | Intake channel (`upload` or `mailbox`) and time received (from the email row) |

The alert details also carry an "Official Sender" true/false value, which the frontend displays.

**Email Domain Security (`email_posture`)**: Domain, Risk Level, DMARC Record, DMARC Policy, DMARC Issues, SPF Record, SPF Issues, DKIM Selectors Found, MTA-STS, Summary.

**DMARC Spoofing Reports (`dmarc`)**: Domain, Source IP, Reporting Organisation, Messages, SPF, DKIM, Disposition, Risk Level, Report Period.

Look-alike domain alerts (capability C) gain the details "SPF Record", "DMARC Record" and "Email-ready".

---

## 9. Evidence stored

| What | Where | Notes |
|---|---|---|
| Raw email (`.eml`) | MinIO `emails/<brand>/<fingerprint>-<sha12>.eml`, SHA-256 on the row | Stored once per fingerprint |
| Email row | `email_messages` | Fingerprint, channel, Message-ID, subject, From, Reply-To, Return-Path, sender IP, sent time, status, `auth` JSON (summary + not-checked list), linked finding (`finding_id`) |
| Indicators | `email_indicators` | One row per URL and per attachment, with every tool's verdict (status, malicious, score, details, timestamp) and the malicious-source count; replaced on re-analysis |
| Metadata evidence | finding evidence | From, Reply-To, Return-Path, subject, sender IP, Message-ID, parser warnings |
| Attachments | finding evidence (file) | Bytes, SHA-256, full analysis report, and the warning "Untrusted attachment. Do not open." |
| Screenshots | finding evidence (image) | Linked pages that looked like phishing |
| Posture | finding evidence (metadata) | DMARC and SPF records, DKIM selectors found, MTA-STS flag |
| DMARC rows | `dmarc_reports` table + finding evidence (metadata) | Every source row is stored, passing or failing; the raw report file itself is not kept |

Evidence is deduplicated per finding: an identical file (same SHA-256) or identical metadata is not stored twice. Each new item is linked to the finding and to the observation that captured it.

---

## 10. Configuration

From `backend/app/config.py` and `deploy/.env.example`. Everything is optional: with no keys the module still parses, scores and alerts, and shows the missing tools as "not checked".

| Variable | Default | Purpose |
|---|---|---|
| `RSPAMD_URL` | `http://rspamd:11333` | Rspamd container address |
| `RSPAMD_PORT` | 11333 | Host port (docker compose) |
| `CLAMAV_HOST`, `CLAMAV_PORT` | `clamav`, 3310 | ClamAV daemon |
| `CLAMAV_ENABLED` | true | Turn ClamAV off (it needs about 1.2-1.5 GB RAM) |
| `YARA_RULES_DIR` | `rules/yara` | Folder of `.yar` files |
| `URLHAUS_AUTH_KEY` | empty | URLhaus URL and hash lookups |
| `URLSCAN_API_KEY` | empty | urlscan.io lookups |
| `ABUSEIPDB_API_KEY` | empty | Sender IP reputation |
| `OPENPHISH_FEED_URL` | `https://openphish.com/feed.txt` | Feed address (no key needed) |
| `IMAP_HOST`, `IMAP_PORT`, `IMAP_USER`, `IMAP_PASSWORD`, `IMAP_MAILBOX` | empty, 993, -, -, INBOX | Phishing reporting mailbox |
| `DMARC_IMAP_HOST`, `DMARC_IMAP_PORT`, `DMARC_IMAP_USER`, `DMARC_IMAP_PASSWORD`, `DMARC_IMAP_MAILBOX` | empty, 993, -, -, INBOX | DMARC report mailbox |
| `MS_GRAPH_TENANT`, `MS_GRAPH_CLIENT_ID`, `MS_GRAPH_CLIENT_SECRET`, `MS_GRAPH_USER`, `MS_GRAPH_FOLDER` | empty, Inbox | Microsoft 365 adapter |
| `GMAIL_SERVICE_ACCOUNT_JSON`, `GMAIL_DELEGATED_USER`, `GMAIL_LABEL` | empty, INBOX | Google Workspace adapter |
| `EMAIL_POSTURE_ENABLED` | true | Defined in settings; not currently read by any code |
| `REDIS_URL` | `redis://localhost:6379/0` | Intel cache (shared) |

To enable capability D, Example Bank must also add the DMARC mailbox to `rua=` in its `_dmarc.examplebank.com` record.

---

## 11. How it is tested

Every test file is tagged with the requirement IDs it proves (`pytest.mark.req(...)`). External services are replaced with fixed answers so tests are repeatable. Test emails live in `backend/tests/fixtures/emails/` (`official.eml`, `lookalike.eml`, `forwarded.eml`, `malformed.eml`) and use a fictional test brand.

| Test file (`backend/tests/`) | IDs | What it proves |
|---|---|---|
| `unit/test_email_parser.py` | EML-01/02/03 | Headers and sender, URL unwrapping and de-obfuscation, attachment hashing and ZIP listing, forwarded original, malformed and garbage input do not crash, attachment limit |
| `unit/test_email_auth.py` | EML-04/05 | Header verdicts read; DMARC fail/pass with alignment; no record is `none`; DNS failure is `temperror`, not a crash |
| `unit/test_email_engines.py` | EML-06/07/08 | Rspamd flags phishing, clean is clean, down is `not_checked`; ClamAV detect/clean/disabled; YARA rule matches |
| `unit/test_email_intel.py` | EML-09 | URLhaus known/unknown, OpenPhish hit, urlscan malicious, AbuseIPDB high confidence, no key and quota errors are `not_checked`, corroboration counts distinct tools |
| `unit/test_email_analysis.py` | EML-10/11 | Look-alike phish with two sources is Critical; official email is not impersonation (score under 30); single source is not "known malicious"; ClamAV malware; DMARC fail on brand From |
| `unit/test_email_scoring.py` | EML-12 | Each of the 20 email/posture rules gives exactly its points; all four levels allowed; a typical phish scores 100 |
| `api/test_emails_api.py` | EML-13/14, RDA-21 | Upload creates a finding and alert with evidence; same email twice updates one finding; non-email rejected; unknown brand; official email is Low; an analysis that fails after its retries is marked `failed` with the reason, not left `queued` |
| `unit/test_email_posture.py` | EML-15/16 | Duplicate DMARC treated as missing; softfail and `p=none`; missing SPF and DMARC is high risk; well-configured domain raises no finding |
| `unit/test_lookalike_email.py` | EML-17 | SPF means can send; MX only means receive only; unrelated TXT is not SPF |
| `unit/test_dmarc.py` | EML-18 | Plain XML, gzip and zip reports parse; XML bomb rejected |
| `unit/test_email_intake.py` | EML-19 | IMAP returns unseen messages; second poll skips seen ones |

**Accuracy measurement.** `backend/scripts/email_accuracy.py` runs real labelled emails (`<folder>/phish/*.eml` and `<folder>/legit/*.eml`) through the same parser, analysis and scoring, counts High/Critical as "flagged", and writes precision, recall, F1 and a confusion matrix to `docs/reports/EMAIL-ACCURACY.md`. Run it as `python -m scripts.email_accuracy <folder> [--brand "Brand Name"]`, ideally on the deployed stack with all keys configured. As of 2026-10-09 that report file has not yet been generated; it needs the owner's labelled sample emails.

---

## 12. Known limitations and missing capabilities

- **No "zero error" claim.** No phishing detector is error-free. The module makes every decision explainable (each rule, each tool verdict and timestamp) and measures accuracy with `scripts/email_accuracy.py` instead of promising perfection. No accuracy figures exist yet.
- **No PhishTank** (no new API keys issued) and **no VirusTotal** (free licence forbids commercial use). **No Google Web Risk.** A paid licence could add either later (D-28).
- **Detection depends on keys.** Without URLhaus, urlscan.io and AbuseIPDB keys, those tools are "not checked"; corroboration then relies on OpenPhish and the live page check.
- **Independent DMARC check is partial.** Our own evaluation looks up the DMARC record but takes the SPF/DKIM pass/fail words from the receiver's `Authentication-Results` header; it does not re-verify DKIM signatures or SPF itself. `dkimpy`, `pyspf` and `checkdmarc` are installed but not called (`dkim_verified` is always empty). An uploaded email with no `Authentication-Results` header, From an official domain that has a DMARC record, will be judged DMARC `fail`.
- **ARC** is read from the header but not used or shown.
- **Microsoft 365 and Google Workspace adapters exist but are not connected.** The mailbox poller only uses IMAP, so the channels are `upload` and `mailbox` in practice.
- **Mailbox emails go to one brand.** The reporting-mailbox poller assigns every email to the oldest active brand.
- **Reply-To only.** The `reply_to_mismatch` rule checks Reply-To; Return-Path is used for look-alike checks but not for the mismatch rule.
- **YARA scans attachments only**, not the email body.
- **Live page check covers the first 5 URLs** only. A hit needs login/payment wording, favicon match or logo score of 85 or more; it does not use the D-29 brand-evidence rule.
- **DKIM posture is a guess.** Only 14 common selectors are tried; a bank using a custom selector will be reported as "no DKIM".
- **MTA-STS check is shallow.** It only checks that the `_mta-sts` TXT record exists, not the HTTPS policy file. BIMI (mentioned in the spec) is not checked.
- **DMARC**: only aggregate (rua) reports, only via the DMARC IMAP mailbox (no upload endpoint); forensic (ruf) reports are not parsed; the raw report file is not kept as evidence.
- **Broker down at upload leaves the email "queued".** Fixed in SP1 for the worker side: when the Celery task still fails after its retries, the row is marked `failed` with the reason (`backend/app/workers/tasks.py`, D-31). If the message broker itself is down at upload time, the task is never queued and the row stays `queued` until it is re-analysed.
- **Rspamd image is `rspamd/rspamd:latest`**, not a pinned version.
- **No dedicated architecture document.** `docs/architecture/09-EMAIL.md` is referenced in the spec's build order but does not exist yet; this chapter and the spec (`docs/superpowers/specs/2026-10-08-phishing-email-design.md`) are the current references.

---

## Key takeaways

- The module answers four questions: is this email phishing (A), can our own domains be spoofed (B), which look-alikes can send mail (C), and who is spoofing us according to DMARC reports (D).
- An uploaded email returns 202 immediately; a Celery worker parses it, checks authentication, runs Rspamd, ClamAV, YARA and four threat-intel sources, opens the links in an isolated browser, and turns 13 facts into a score.
- Scoring is a fixed points table shared with every module: Low 0-29, Medium 30-59, High 60-79, Critical 80-100, with every fired rule shown.
- Three safeguards keep it honest: a URL needs two independent sources to be "known malicious", official senders passing DMARC are never impersonators, and any tool that could not answer is shown as "not checked" and scores 0.
- Gaps are documented, not hidden: no PhishTank, VirusTotal or Google Web Risk, partial independent DMARC verification, M365/Gmail adapters not wired, and no measured accuracy yet.
