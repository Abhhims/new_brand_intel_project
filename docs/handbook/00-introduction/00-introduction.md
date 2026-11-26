# Chapter 00 - Introduction to Brand Intelligence

In this chapter:
- What "brand intelligence" and "brand protection" mean, in plain words.
- The ten kinds of brand abuse the platform looks for, each with a short example.
- Who uses the platform (Beyond Cloud analysts) and what their working day looks like.
- What the platform does, and what it deliberately does not do.
- A glossary of the terms used across the whole handbook.

## 1. What is brand intelligence?

A **brand** is the name, logo, website, apps and social accounts that people recognise as one company.
When customers see "Example Bank" and its blue logo, they trust it.

Criminals know this. They copy the brand to fool people. They register a website that looks like
`examplebank.com`, publish a fake "Example Bank" app, or open a Telegram account called
"Example Bank Support". Then they collect passwords, card numbers or money from customers who think
they are talking to the real bank. This is called **brand abuse**.

**Brand intelligence** is the work of finding brand abuse on the internet, early, before many people are
fooled. **Brand protection** is the wider job: finding the abuse, proving it with evidence, deciding how
serious it is, and then getting it removed.

Doing this by hand is slow. Every day thousands of new websites, apps and accounts appear. A person cannot
check all of them. The Beyond Cloud Brand Intelligence platform automates the searching, checking,
evidence collection and scoring. People stay in charge of the final judgement.

## 2. The kinds of brand abuse

The platform looks for ten kinds of abuse. The examples below use the fictional Example Bank.

### 2.1 Look-alike domains (typosquatting)

A **domain** is a website name, such as `examplebank.com`. **Typosquatting** means registering a domain
that is a small misspelling of a real one, hoping people will not notice.

Example: a criminal registers `exampelbank.com` (two letters swapped), `examp1ebank.com` (the letter "l"
replaced with the digit "1") and `examplebank-login.com` (a word added). Nothing may be on these
domains yet. But registering them is often the first step of an attack, so the platform reports them early.
Chapter 03 explains this.

### 2.2 Email-enabled look-alike domains (MX records)

An **MX record** ("mail exchanger" record) is a setting in the internet's address book (DNS) that says
"this domain can receive email". A look-alike domain with an MX record is ready to send and receive
email.

Example: `examplebank-support.com` has an MX record. A criminal can now send emails from
`help@examplebank-support.com` asking customers to "confirm their account", and receive the replies. The
platform moves the domain's stage to "MX" to show this. Chapter 03 explains this.

### 2.3 Phishing websites

**Phishing** is tricking someone into giving away secrets (passwords, one-time codes, card numbers) by
pretending to be someone they trust. A phishing website copies the look of the real site.

Example: `examp1ebank.com` goes live. It shows the Example Bank logo and a login box that asks for
customer ID, password and the one-time password sent by SMS. Anything typed goes to the criminal. The
platform visits the site in a safe, isolated browser, takes a screenshot, looks for the logo and login
words, and flags it as **Suspected Phishing**. Chapter 03 explains this.

### 2.4 Fake APKs

An **APK** is the installation file for an Android app. Many websites ("APK mirrors") offer APK files for
download outside the Google Play store.

Example: a mirror site offers "Example Bank 5.2 (Premium Unlocked).apk". It looks like the real app, but it
was rebuilt by a stranger and contains code that steals SMS messages. The platform finds the listing,
downloads the file into safe storage (never runs it), and checks who signed it. The real app is always
signed with Example Bank's own key; a fake one is not. Chapter 04 explains this.

### 2.5 Rogue store apps

A **rogue app** is an app in an official app store (here: Google Play) that uses the brand without
permission.

Example: an app called "Example Bank Loan Helper" by a publisher called "QuickFin Apps" appears on Google
Play. It is not published by Example Bank. It may be a scam, or it may just mislead customers. The platform
compares the publisher with Example Bank's official publisher name and raises an alert. Chapter 05
explains this.

### 2.6 Social media impersonation

**Impersonation** means pretending to be someone else. On social media, criminals open accounts that look
official and offer "support".

Example: a Telegram channel `@examplebank_support` uses the Example Bank logo as its profile picture and
says "Official help desk. Send us your account number to fix your issue." The platform finds accounts like
this, compares the profile picture with the official logo, and raises an alert. Chapter 06 explains this.

### 2.7 Sensitive document exposure

Sometimes internal documents end up on the public internet: a spreadsheet uploaded to a public server, or a
PDF that a search engine has indexed.

Example: a search finds `examplebank-customer-list-2026.xlsx` on a file-sharing site. It contains the words
"Confidential" and "Example Bank" and 400 email addresses. That is a data leak. The platform finds such
documents through web search, downloads them safely and reads the text. Chapter 07 explains this.

### 2.8 Logo misuse

Even without a look-alike domain, a website can use the official logo to look trustworthy.

Example: `best-loans-today.com` shows the Example Bank logo next to "Partner of Example Bank - apply now".
Example Bank has no such partner. The platform compares images on suspicious websites with the official
logo using image fingerprints. Chapter 08 explains this.

### 2.9 Phishing email

Phishing often starts with an email. The platform can analyse emails that customers or staff report.

Example: a customer forwards an email from `alerts@examplebank-secure.com` with the subject "Your account
is locked - verify within 24 hours". It links to a fake login page and has a Word attachment with a macro.
The platform checks the sender, the links (with several threat-intelligence services), the attachment
(with antivirus and rule scanners) and the linked page. It also checks Example Bank's own email security
settings, so criminals cannot easily send email that appears to come from `examplebank.com` itself.
Chapter 09 explains this.

### 2.10 Social media brand misuse

Not every scam needs a fake account that looks official. Criminals also post videos, posts and paid ads that
use the brand name or logo to push a "helpline" number, a WhatsApp link or a UPI payment ID.

Example: a YouTube video called "Example Bank customer care number - KYC update" shows the Example Bank logo
and lists a WhatsApp number in its description. Viewers who call are asked for their card details. The
platform searches YouTube, Facebook, Instagram, X, Threads, Meta ads, Pinterest, TikTok, LinkedIn and
Telegram, keeps the link, a thumbnail and a screenshot, and points out the exact phone number, WhatsApp link
or UPI ID being pushed. Chapter 14 explains this.

## 3. Who uses the platform

The platform is an **internal tool** for **Beyond Cloud analysts**. Beyond Cloud is a security service
provider. Its analysts monitor brands on behalf of client companies. Clients do not log in; there is no
customer portal in this phase (out of scope, OOS-05).

There are two roles (decision D-15):

| Role | What they can do |
|---|---|
| **Admin** | Everything an analyst can do, plus: add, edit and delete brands; upload official logos; edit the allowlist of official domains, apps, publishers and handles; create and manage user accounts |
| **Analyst** | View brands, alerts and findings, start scans, review evidence, record decisions on findings (also in bulk, and mark something Legitimate to add it to the allowlist), upload emails for analysis, export alerts to CSV or PDF |

There is no self-registration. The first admin account is created automatically when the platform starts
for the first time (`backend/scripts/bootstrap.py`). The admin then creates analyst accounts (D-27).

### 3.1 A typical day for an analyst

1. **Morning check.** The platform scanned every brand overnight (02:00 UTC). The analyst opens the
   dashboard. The "Brand exposure today" panel and the charts show how many new alerts appeared, and how
   many are High or Critical. Two tiles show what was kept but not alerted: "Candidates" (discovered, not yet
   analysed) and "Findings below alert level".
2. **Triage the queue.** The analyst opens the Alerts page and filters by brand, module, risk level and
   decision. Critical and High alerts come first. An alert only appears when an analysed finding reached the
   brand's "Alert from" level, or when something important changed (for example a look-alike site went live).
3. **Review one alert.** The alert detail page says why the alert was raised ("First reached High", "Website
   went live"), and shows the module's fields (for a domain: registrar, creation date, MX records, page title
   and so on), the **"Why this score"** panel, the evidence gallery (screenshots, favicon, WHOIS data, HTML),
   one row per scan that saw it, and the timeline.
4. **Decide.** The analyst records a decision on the finding: Investigating, then Confirmed Threat, False
   Positive, Legitimate or Ignored, and finally Resolved for a confirmed threat that was dealt with (D-35). A
   note is required for False Positive, Legitimate and Ignored. Each change is stored with who did it, when
   and why. A decided finding stays quiet on later scans unless something meaningful changes; then it is
   reopened (D-36).
5. **Act outside the platform.** For confirmed abuse, the analyst informs the client and starts a takedown
   with the registrar, hosting company, app store or social network. The platform does not file takedowns
   itself (OOS-01).
6. **Report.** The analyst exports the filtered alerts as CSV or PDF for the client.
7. **Ad hoc work.** When a client adds a new domain or app, an admin updates the brand and the analyst
   presses **Run scan now**. When a suspicious email is reported, the analyst uploads it on the Emails page.

Alerts appear in the dashboard only. The platform does not send email or chat notifications in this phase
(D-14).

## 4. What the platform does

| Capability | Short description | Chapter |
|---|---|---|
| Brand onboarding | Store a brand's name, keywords, official domains, app packages, publishers, social handles, email domains, app signing certificates and logos | 01 |
| Look-alike domain discovery | Generate thousands of misspellings, search certificate logs, check which ones are registered | 03 |
| Email readiness | Check MX and SPF records on look-alike domains | 03 |
| Phishing site detection | Visit live look-alikes safely, screenshot them, look for logo, favicon, brand name and login words | 03 |
| Fake APK detection | Search APK mirror sites, download files safely, compare names, icons and signing certificates | 04 |
| Rogue app detection | Search Google Play for apps that use the brand but are not from the official publisher | 05 |
| Social impersonation | Search Telegram, X, Facebook, Instagram and LinkedIn for impersonating accounts | 06 |
| Social media brand misuse | Find posts, videos, ads and channels on YouTube, Facebook, Instagram, X, Threads, Meta ads, Pinterest, TikTok, LinkedIn and Telegram that use the brand, with fake contact details and scam wording flagged (D-38) | 14 |
| Document exposure | Search for public PDF, DOCX, XLSX and PPTX files that mention the brand | 07 |
| Logo misuse | Look for the official logo on suspicious websites | 08 |
| Phishing email analysis | Analyse uploaded or mailbox emails; check the brand's own SPF, DKIM, DMARC and MTA-STS; read DMARC reports | 09 |
| Risk scoring | One points table for every module, with levels Low, Medium, High, Critical | 02 |
| Evidence | Screenshots, files and metadata stored in object storage with SHA-256 hashes | 01 |
| Findings, alerts and workflow | Candidate, Finding and Alert stages; per-brand "Alert from" level; one observation per scan and a timeline; seven analyst decisions; CSV and PDF export (D-33 to D-37) | 10 |
| Scheduling | Daily full scan, six-hourly domain re-check, mailbox polling | 01 |
| Honest scan status | Every scan lists which parts ran, which were not configured or unavailable, and which failed; the Integrations page shows every tool and its last result (D-31) | 01, 10 |

## 5. What the platform does not do

These items are **out of scope** for Phase 1. They are listed in `docs/requirements/01-requirements-register.md`
section B.

| ID | Not done | What that means in practice |
|---|---|---|
| OOS-01 | Automated takedown filing | Analysts request removals themselves |
| OOS-02 | AI-based phishing content classification | Decisions come from fixed, explainable rules, not a machine-learning model |
| OOS-03 | Mobile app reverse engineering | APKs are never decompiled or run. Only listing data, the manifest, the icon and the signing certificate are read (D-12, D-26) |
| OOS-04 | Dark web crawling | Only the public internet is searched |
| OOS-05 | Multi-tenant customer portal | Clients cannot log in; one organisation (Beyond Cloud) uses it for many brands |

Other limits that come from decisions, not from the out-of-scope list:

- **Google Play only.** Other app stores are not monitored in Phase 1 (D-13).
- **No notifications.** Alerts are shown in the dashboard only (D-14).
- **No scraping behind logins.** Social media accounts are found through public search and public pages
  (D-10, D-23). The platform does not solve CAPTCHAs or disguise itself to avoid bot protection.
- **Real data only.** The product shows only data from live scans and has no demo mode. Simulated test data
  exists only inside the automated tests (D-27, D-30, D-32).
- **Unknown is never "no".** When a source could not be checked (not configured, unavailable, or a lookup
  failed), the scan says so. "No threats detected." is only shown after a scan has actually completed (D-31).
- **No "zero error" claim.** No detector is perfect. The platform shows why it decided something, so an
  analyst can check it (D-28).

## 6. Glossary

| Term | Meaning |
|---|---|
| **Alert** | A record raised when a finding reaches the brand's "Alert from" risk level for the first time, or later changes in a meaningful way. It carries a trigger and a reason ("First reached High (70)", "Website went live"). The alert queue is the analyst's to-do list (D-34, D-36). |
| **Alert from** | A brand setting: the lowest risk level that raises an alert (Low, Medium, High or Critical; default Medium). |
| **Allowlist** | The brand's list of official things: domains, email domains, app packages, publishers, social handles, signing certificates. Anything on it is treated as genuine. |
| **APK** | Android Package. The installation file of an Android app. |
| **Brand context** | A read-only snapshot of a brand (terms, allowlist, logo fingerprints) that a module uses during a scan. |
| **Candidate** | Something a module discovered that might be abuse, but could not analyse further, for example a registered look-alike domain with no website and no mail server. It is stored, but never raises an alert (D-33). |
| **Celery** | A Python tool for running jobs in the background. The website asks for a scan; Celery runs it later on a worker. |
| **Celery beat** | The Celery scheduler. It starts jobs at fixed times, like an alarm clock. |
| **Celery worker** | A background process that takes jobs from a queue and runs them. This platform has two: a normal worker and a browser worker. |
| **Certificate Transparency (CT)** | Public logs of every HTTPS certificate issued. New phishing sites usually get a certificate, so searching these logs finds them early. The platform uses crt.sh. |
| **Clamp** | Forcing a score into a module's allowed range, for example raising a fake-app score to at least Medium. |
| **DKIM** | DomainKeys Identified Mail. A digital signature on email that proves which domain sent it. |
| **DMARC** | Domain-based Message Authentication, Reporting and Conformance. A DNS setting that tells receivers what to do with email that fails SPF and DKIM checks, and asks them to send reports. |
| **DNS** | Domain Name System. The internet's address book that turns names like `examplebank.com` into server addresses and mail settings. |
| **Decision** | What the analyst decided about a finding: New, Investigating, Confirmed Threat, False Positive, Legitimate, Ignored or Resolved (D-35). "Reopened" is not a decision but a timeline event when a decided finding goes back to New. |
| **Entity key** | The identity of a finding, for example the domain name. A re-scan that finds the same entity adds an observation to the same finding instead of creating a new one. |
| **Evidence** | Proof stored with a finding: screenshots, favicons, HTML, files, WHOIS, DNS and certificate data. Each item records the scan (observation) that captured it. |
| **Favicon** | The small icon shown in a browser tab. Phishing sites often copy the real one. |
| **Finding** | One suspicious thing (a domain, app, account, post, document, web page or email) that a module analysed and backed with evidence. It has a score, a risk level and a decision, and becomes an alert only when it reaches the brand's "Alert from" level (D-33, D-34). In the code, what a module yields is called a `Detection`. |
| **Meaningful change** | A change between two scans that matters enough to raise a new alert: website went live, login form appeared, official logo appeared, domain gained a mail server, APK signed by a non-official certificate, app listed again, Candidate became Finding, or risk level went up (D-36). |
| **Observation** | One sighting of a finding by one scan (or one email upload), with what was seen and the score at that moment. |
| **Integration** | An external tool or service the platform uses, such as a web search API, crt.sh, Telegram or a threat-intelligence feed. The Integrations page shows whether each one is configured and how it last ran. |
| **Homoglyph** | A character that looks like another, such as the digit `1` and the letter `l`, or the Cyrillic `а` and the Latin `a`. |
| **MX record** | A DNS record that says which server receives email for a domain. A look-alike with an MX record can receive email. |
| **Parked page** | A placeholder page shown on a domain that is not in use, often "This domain is for sale". |
| **Perceptual hash** | A short fingerprint of an image that stays almost the same when the image is resized or re-saved. Two logos are compared by how many fingerprint bits differ. The platform uses pHash and dHash. |
| **Phishing** | Tricking people into giving away passwords, codes or card data by pretending to be a trusted company. |
| **Risk level** | Low, Medium, High or Critical, derived from the risk score. |
| **Risk score** | A number from 0 to 100 built by adding points for each scoring rule that fired. |
| **Rogue app** | An app in an official store that uses the brand but is not published by the brand. |
| **Scan component** | One part of a scan run, such as "DNS resolution" or "Telegram API". Each component reports Completed, Skipped, Not configured, Unavailable or Failed. |
| **Scan state** | The overall result of a scan run: Queued, Running, Completed, Partially completed, Completed with errors, Failed or Cancelled. |
| **S3 / object storage** | A storage service for files, reached over the S3 protocol. Here it is RustFS running in a container; it could be AWS S3. |
| **Safe fetcher** | The single piece of code that is allowed to download anything from the internet. It blocks requests to internal addresses and limits size and speed. |
| **Signal** | A fact a module observed that the scoring uses, for example "MX present" or "official logo found". |
| **SHA-256** | A cryptographic fingerprint of a file. Two files with the same SHA-256 are identical. |
| **Signing certificate** | The key an Android developer uses to sign an app. Only the real developer has it, so it proves where an APK came from. |
| **SPF** | Sender Policy Framework. A DNS record listing which servers may send email for a domain. |
| **SSRF** | Server-Side Request Forgery. An attack that tricks a server into making requests to its own internal network. The safe fetcher prevents it. |
| **Suspected Phishing** | A flag on a domain alert: the site is live, looks like the brand's domain, shows the brand, is not parked, and has a login form, payment words, the brand favicon or the logo (D-04, D-29). |
| **Timeline** | The history of a finding: discovered, promoted, changed, rescored, alerted, decided, reopened. |
| **Typosquatting** | Registering a misspelled version of a real domain to catch people who mistype or misread it. |
| **WHOIS / RDAP** | Public records of who registered a domain, through which registrar, and when. RDAP is the modern version of WHOIS. |

## Key takeaways

- Brand abuse means criminals copying a company's name, logo, website, apps or accounts to fool its customers.
- The platform finds ten kinds of abuse automatically and stores evidence for each one.
- It is an internal tool for Beyond Cloud analysts, with two roles: Admin and Analyst.
- Every finding gets a 0-100 score and a level from one shared, explainable points table. Only analysed findings at or above the brand's "Alert from" level become alerts; candidates and low findings are kept, not alerted.
- Every scan reports what it could and could not check; a source that was down is never shown as "nothing found".
- People make the final call: analysts record a decision on each finding (Confirmed Threat, False Positive, Legitimate, Ignored, Resolved and so on) and request takedowns themselves.
- Takedowns, AI classification, app reverse engineering, dark web crawling and a client portal are out of scope.
