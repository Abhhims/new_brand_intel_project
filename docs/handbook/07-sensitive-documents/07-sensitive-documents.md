# Chapter 07 - Sensitive Document Monitoring

In this chapter:
- What a document exposure is, and why a single forgotten spreadsheet can become a data breach.
- How the module finds public documents that mention the brand, through search engines and public file-sharing links.
- How each document is downloaded safely, its type detected, its text extracted (never run), and checked for brand words, official domains, email addresses and sensitive words.
- How "Exposure Confidence", "Hosted On Official Domain" and the risk score are worked out, and what the module cannot see yet.

## 1. What this module detects and why it matters

### Plain words first

Companies produce many documents: PDFs, Word files (DOC, DOCX), Excel spreadsheets (XLS, XLSX), PowerPoint
decks (PPT, PPTX) and CSV exports. Sometimes one ends up on the public internet by mistake:

- an employee shares a file with "anyone with the link" on Google Drive, OneDrive or Dropbox, and the link
  gets posted somewhere;
- a file is uploaded to a public web folder or a public cloud storage bucket (Amazon S3);
- a partner or vendor publishes a file that contains the brand's data.

Search engines then **index** the file: they read it and make it findable. Anyone who searches for
`"Example Bank" filetype:xlsx` can find it.

A **document exposure** is such a file that is reachable without logging in and that relates to the brand.
Some are harmless (a public brochure). Some are serious (a customer list, a salary sheet, internal
passwords).

### An attack story

1. An Example Bank HR employee shares `Example_Bank_Internal_Salary_Review_2026.pdf` with a recruiting agency
   using a public link.
2. The agency pastes the link on a public job forum. A search engine indexes the PDF.
3. A criminal searches `"Example Bank" filetype:pdf confidential`. The PDF lists names, salaries and twelve
   `@examplebank.com` email addresses.
4. The criminal sends convincing "salary revision" phishing emails to every name on the list.

This module would find the PDF, download it into the evidence store, see "Confidential", "Salary", twelve
email addresses and the official domain, and raise a **Critical** alert.

## 2. Requirements it covers

| ID | Requirement | How the module covers it |
|---|---|---|
| OBJ-05 | Detect exposure of sensitive documents related to monitored brands | The whole module |
| DOC-01 | Source: search-engine-indexed documents | `filetype:` searches |
| DOC-02 | Source: public file-sharing links | `site:` search over 8 sharing services |
| DOC-03 | Source: exposed PDF/DOC/XLS/PPT accessible without authentication | Download without login; `Accessible Without Login` |
| DOC-04 | Brand keyword match | `Brand Match` (D-25 rules) |
| DOC-05 | Domain match | `Domains Found` |
| DOC-06 | Email address pattern match | `Emails Found`, `Brand Emails` |
| DOC-07 | Filename pattern analysis (confidential, internal, salary, customer, ...) | `Sensitive Patterns` (filename, title, snippet and content) |
| DOC-08 | Output: Document Name, File Type, URL, Brand Match, Exposure Confidence (L/M/H), Risk Level (M/H/C) | `OUTPUT_FIELDS[documents]` |
| AC-07 | Detects indexed document containing brand keyword | Acceptance test |

Related decisions: D-03 (Medium/High/Critical only), D-06 (document scoring rules and Exposure Confidence),
D-18 (files are stored, hashed and never opened or run), D-25 (short abbreviations; company name does not
trigger "private"; "Hosted On Official Domain").

## 3. How it works

### The process, step by step

1. **A scan starts.** Daily at 02:00 UTC, or by hand. The `documents` runner runs on the normal worker queue.
2. **Build the searches.** The first three brand terms are joined, for example `("Example Bank" OR
   "examplebank" OR "ExamplePay")`. Seven searches are run, each asking for up to 20 results:

   ```
   (<terms>) filetype:pdf
   (<terms>) filetype:docx
   (<terms>) filetype:xlsx
   (<terms>) filetype:pptx
   (<terms>) filetype:doc
   (<terms>) filetype:xls
   (<terms>) (site:drive.google.com OR site:docs.google.com OR site:onedrive.live.com OR site:1drv.ms
              OR site:dropbox.com OR site:box.com OR site:s3.amazonaws.com OR site:sharepoint.com)
   ```

   Each result URL is kept once. A result on one of the sharing sites is labelled "public-share-link",
   anything else "search-engine". Each search is reported on the scan component named after the provider, for
   example "Web search - Brave Search API". If search becomes unavailable, the remaining searches are skipped
   and the component shows `unavailable` with the reason. If not a single search worked, nothing was checked,
   so the scan ends `failed` instead of looking clean (D-31).
3. **Turn share links into download links.** A Google Drive `/file/d/<id>` link becomes
   `https://drive.google.com/uc?export=download&id=<id>`. A Dropbox link gets `dl=1`. Other links are used as
   they are.
4. **Download through the safe fetcher.** The file is fetched into memory (default limit 25 MB). It counts
   as **accessible** only if the answer is HTTP 200, has content, and is **not** an HTML page. An HTML page
   usually means a login wall or a preview page, not the file.
5. **Detect the real file type** from the first bytes of the file (its "magic bytes"), not just from the name.
6. **Extract the text.** Only text is read; macros and embedded objects are never run.
7. **Check brand relevance.** The module joins the "surface" (file name, search title, search snippet) with
   the extracted text and asks `BrandContext.relevance` whether it refers to the brand (D-25). It also checks
   whether any official domain or email domain appears. If neither, the document is ignored (DOC-04).
8. **Find emails, domains and sensitive words.**
   - Email addresses in the text, by pattern.
   - Official domains found in the text, or as the domain of an email address found.
   - Sensitive words (see the table in section 5) in the surface and text. Before this, the brand's own name
     and terms, and the phrase "private limited" / "pvt ltd", are removed, so "Example Bank Private Limited"
     does not trigger "private".
9. **Work out Exposure Confidence** (D-06, section 7).
10. **Check where it is hosted.** If the URL's host is an official domain (or a subdomain of one), the field
    `Hosted On Official Domain` is True. This helps analysts tell a file the brand published on purpose from
    a leak.
11. **Build the detection** (a `Detection`) and pass it to `record_detection` (`backend/app/core/findings.py`),
    which scores it, clamps it to Medium/High/Critical, creates or updates one finding per document URL,
    records an observation for this scan, and raises an alert only when the alert rule is met.

### Candidate or Finding? (SP2, D-33)

A document that **could not be downloaded**, or whose Exposure Confidence is **Low**, is stored as a
**Candidate**: it is listed on the Findings page but never alerts, whatever its score. A document that was
downloaded and checked with Medium or High confidence is a **Finding** (`analysed = accessible and confidence
!= "Low"` in `backend/app/modules/documents/module.py`). Document scores are clamped to at least Medium, so a
Finding always reaches the default "Alert from" level (Medium); a brand set to "High" only gets alerts for High
and Critical documents.

On a re-scan, a document that moves from Candidate to Finding (for example a link that now downloads) is a
**meaningful change** ("Analysis found evidence") and can raise an alert; so can a rise in risk level (D-36).

### Flow diagram

```
 Daily schedule / manual scan
            |
            v
 7 web searches: (<terms>) filetype:pdf|docx|xlsx|pptx|doc|xls  +  (<terms>) (site:<8 sharing sites>)
            |                                                  <-- backend/app/core/search.py
            v
 Unique URLs, labelled "search-engine" or "public-share-link"
            |
            v
 Share link -> direct download link (Google Drive, Dropbox)
            |
            v
 Safe fetcher download (max 25 MB)                             <-- backend/app/core/fetch.py
            |
   200 + content + not HTML?  --no--> accessible = False (no file, no text)
            | yes
            v
 Magic-byte type detection -> text extraction (no macros)
            |
            v
 Brand relevant (surface + text) OR official domain referenced? --no--> ignore
            | yes
            v
 Emails, official domains, sensitive words (company name removed first)
            |
            v
 Exposure Confidence (Low / Medium / High)    Hosted On Official Domain (True / False)
            |
            v
 Signals -> Detection -> record_detection (Medium/High/Critical) -> finding + observation
   + file evidence -> alert if Finding and risk >= brand "Alert from" level
```

## 4. Tools and libraries used

| Tool | What it is | What we use it for | Why this tool (and alternatives rejected) | Where in the code |
|---|---|---|---|---|
| Web search (Brave, SerpAPI or DuckDuckGo) | Search engines | Finding indexed documents and share links | Search engines already index public documents. Bing's public page was rejected because it ignores `filetype:` and `site:`; no CAPTCHA solving (D-23). | `backend/app/core/search.py` |
| Safe fetcher | The platform's only way to reach the internet | Downloading the document | Required for every outbound request (D-18) | `backend/app/core/fetch.py` |
| zipfile (standard library) | Reads ZIP archives | Telling DOCX, XLSX and PPTX apart (they are ZIP files inside) | Standard | `backend/app/modules/documents/module.py` (`sniff_type`) |
| python-magic (libmagic) | File-type detection from content | Detecting CSV and plain text | Available in the Linux container image; skipped on Windows | `sniff_type` |
| pdfminer.six | PDF text extraction library | Text from PDFs (first 50 pages) | Text only, no rendering or script running. The design spec also listed `pypdf`; only pdfminer is used. No rejection recorded. | `extract_text` |
| python-docx | Word DOCX reader | Paragraph and table text | Reads XML only; never runs macros | `extract_text` |
| openpyxl | Excel XLSX reader | Cell values (first 20 sheets, 5,000 rows each), read-only, cached values | Never runs macros or formulas | `extract_text` |
| python-pptx | PowerPoint PPTX reader | Text from slide shapes | Reads XML only | `extract_text` |
| Regular expressions | Pattern matching | Emails, domains, sensitive words, legacy Office strings | Simple and transparent | `module.py` (`EMAIL_RE`, `DOMAIN_RE`, `SENSITIVE_PATTERNS`) |
| hashlib | Hash functions | SHA-256 of the file | Standard | `backend/app/core/evidence.py` |
| boto3 + S3-compatible storage | Object storage | Keeping the downloaded file and metadata | RustFS by default (D-22) | `backend/app/core/evidence.py` |

## 5. How each tool works internally, explained simply

### Web search with filetype and site

`filetype:pdf` asks the search engine for PDF files only. `site:drive.google.com` asks for pages from that
site only. Combined with the brand terms in quotes, these searches find documents the engine has already
read. The provider order (Brave, then SerpAPI, then free DuckDuckGo), the pace of one free search every 12
seconds, and the 15-minute pause after a refusal are described in `backend/app/core/search.py` and in
Chapter 04. Without an API key, only a few of the seven searches may run before free search pauses (D-23).

### Magic bytes

Most file formats start with a fixed signature:

| First bytes | Meaning | Type reported |
|---|---|---|
| `%PDF` | PDF | PDF |
| `PK` (a ZIP) containing `word/` | Word 2007+ | DOCX |
| `PK` containing `xl/` | Excel 2007+ | XLSX |
| `PK` containing `ppt/` | PowerPoint 2007+ | PPTX |
| `D0 CF 11 E0` (old Office container) | Word, Excel or PowerPoint 97-2003 | DOC, XLS or PPT (from the extension) |
| libmagic says text / csv (Linux only) | Text | CSV or TXT |
| anything else | - | The extension in upper case, or UNKNOWN |

Checking the content stops a file named `.pdf` that is really something else from fooling the extractor.

### Text extraction

| Type | How text is read | Limits |
|---|---|---|
| PDF | pdfminer.six reads the text layer | 50 pages |
| DOCX | python-docx: every paragraph and every table cell | - |
| XLSX | openpyxl in read-only mode, cached cell values | 20 sheets, 5,000 rows per sheet |
| PPTX | python-pptx: every shape that has a text frame | - |
| CSV, TXT | Decoded as UTF-8 | - |
| DOC, XLS, PPT (old binary) | Runs of 4+ printable characters only | - |

All text is capped at 2,000,000 characters. If a file is damaged or password-protected, extraction returns
nothing and the event is logged. Nothing is ever executed: no macros, no embedded objects, no formulas
recalculated.

### Brand relevance (D-25)

`BrandContext.relevance` treats long brand words such as "Example Bank" as strong (they count alone) and
short abbreviations such as "EXB" as weak (they count only with a context word such as "example"). Because
documents are long, this rule matters: "EXB" appears in many unrelated files.

### Sensitive patterns (DOC-07)

The list in `SENSITIVE_PATTERNS`: confidential, internal, internal use only, restricted, private, salary,
payroll, compensation, ctc, customer, customers, client list, employee, password, credentials, invoice, bank
statement, account number, pan, aadhaar, ssn, kyc, not for distribution, strictly, secret, audit, board.

Each must appear as a whole word (not inside a longer word). They are searched in the file name, the search
title, the snippet and the extracted text together.

## 6. Code map

| File | Responsibility |
|---|---|
| `backend/app/modules/documents/module.py` | Sources, share-link conversion, type detection, text extraction, analysis |
| `backend/app/modules/base.py` | `BrandContext`, `relevance` |
| `backend/app/core/similarity.py` | `brand_terms_in_text` |
| `backend/app/core/search.py` | Web search |
| `backend/app/core/fetch.py` | Safe download |
| `backend/app/core/evidence.py` | SHA-256 and storage |
| `backend/app/core/scoring.py` | Document points (D-06) and clamp |
| `backend/app/core/findings.py` | Findings, observations, timeline, alert rule, evidence |
| `backend/app/modules/registry.py` | Output fields |

Key functions in call order:

1. `execute_scan` -> `get_runner("documents")` -> `DocumentsModule()`.
2. `DocumentsModule.run` -> `LiveDocSource.results(ctx, self.report)` -> `search.search` (seven times). The
   automated tests inject `FixtureDocSource` from `backend/tests/support/fixture_sources.py` instead (D-32).
   Every download is reported on the "Download & text extraction" component (a file that could not be fetched
   at all counts as failed); a crash while analysing one result is reported on "Document analysis".
3. For each result: `DocumentsModule.analyse` -> `_download_url` -> `try_fetch` -> `sniff_type` ->
   `extract_text` -> `ctx.relevance` -> `EMAIL_RE` / `DOMAIN_RE` -> sensitive patterns -> Exposure
   Confidence -> `Signals` -> `Detection`.
4. `record_detection` -> `score(signals, ModuleName.documents)` -> `meets_rule`.

## 7. Signals collected and how they become the risk score

The §6 points table in the requirements had no rules for documents, so decision D-06 added four:

| Signal | When this module sets it | Points |
|---|---|---|
| `doc_brand_keyword` | Always (the document passed the brand check) | +30 |
| `doc_official_domain` | An official domain or brand email domain is found in the text | +20 |
| `doc_sensitive_pattern` | At least one sensitive word found | +30 |
| `doc_many_emails` | 5 or more email addresses in the text | +20 |

The total is capped at 100. The module clamp (D-03) allows Medium, High and Critical, so a document finding is
never Low: the minimum is 30.

### Exposure Confidence (D-06)

This is a separate Low/Medium/High label for "how sure are we that real data is exposed". The code decides it
in this order:

| Condition | Exposure Confidence |
|---|---|
| The file could not be downloaded (login wall, HTML preview, error, too large) | Low |
| Downloaded, and a sensitive word was found or 5+ email addresses | High |
| Downloaded, and a brand term is found in the extracted text | Medium |
| Downloaded, but the brand appears only in the name, title or snippet | Low |

Exposure Confidence does not change the points. It helps the analyst decide what to look at first.

### Hosted On Official Domain (D-25)

True when the file's host is one of the brand's official domains or a subdomain of it, for example
`www.examplebank.com/docs/annual-report.pdf`. It does not change the score and does not suppress the finding.
It tells the analyst "this is probably a file the bank published itself" (check whether it should be public)
versus "this is on someone else's server" (a possible leak).

### Worked example

The salary PDF from the story, found on a Google Drive public link:

| Check | Result | Points |
|---|---|---|
| Brand relevant | "Example Bank" in name and text | +30 |
| Official domain in text | `examplebank.com` (from the email addresses) | +20 |
| Sensitive words | confidential, internal, salary, employee | +30 |
| Email addresses | 12 (5 or more) | +20 |
| Total | 100 | **100, Critical** |
| Exposure Confidence | downloaded + sensitive words | High |
| Hosted On Official Domain | `drive.google.com` | False |

A public home-loan brochure on `examplebank.com` whose text mentions only "Example Bank" and no sensitive
words: +30 for the brand, so **30, Medium**; Exposure Confidence Medium; Hosted On Official Domain True. If the
brochure also says "contact loans@examplebank.com", the official domain adds +20: **50, Medium**.

## 8. Output fields shown to analysts

From `OUTPUT_FIELDS[ModuleName.documents]` in `backend/app/modules/registry.py`:

| Field | Meaning |
|---|---|
| Document Name | File name from the URL (decoded), or the search title |
| File Type | PDF, DOCX, XLSX, PPTX, DOC, XLS, PPT, CSV, TXT, or the extension |
| URL | Where the document was found |
| Brand Match | The brand terms found (D-25 rules) |
| Exposure Confidence | Low, Medium or High (section 7) |
| Risk Level | Medium, High or Critical |
| Sensitive Patterns | The sensitive words found |
| Emails Found | How many distinct email addresses are in the text |
| Domains Found | Official domains seen in the text or in email addresses |
| SHA256 | Hash of the downloaded file (empty if not downloaded) |
| Discovery Source | "Search Engine" or "Public Share Link" |
| Hosted On Official Domain | True when the file is on the brand's own domain |

Extra detail fields also stored: `Brand Emails` (up to 20 addresses on official domains),
`Accessible Without Login` (True / False) and `Size (bytes)`.

## 9. Evidence stored

| Evidence | Kind | When |
|---|---|---|
| Search title, snippet, URL, HTTP status and the first 1,500 characters of extracted text | `metadata` | Always |
| The downloaded file, with URL, SHA-256 and detected type | `file` | When the file was accessible |

Files are stored in the evidence bucket as attachments, so a browser downloads them rather than opening them
(D-18). The same file (same SHA-256) is not stored twice for one finding (D-21); each new item is linked to the finding and to the
observation (scan) that captured it. Because these files may contain
personal data, access to evidence should be limited to analysts who need it.

## 10. Settings and configuration

There are no settings specific to this module. It depends on:

| Variable | Default | Effect |
|---|---|---|
| `BRAVE_SEARCH_API_KEY` | empty | Reliable search (recommended) |
| `SERPAPI_API_KEY` | empty | Alternative search API |
| `FREE_SEARCH_FALLBACK` | `true` | DuckDuckGo public page when no key |
| `FREE_SEARCH_INTERVAL_SECONDS` | `12.0` | Gap between free searches |
| `FETCH_MAX_BYTES` | 25 MB | Largest document that will be downloaded |
| `FETCH_TIMEOUT_SECONDS` | `15.0` | Timeout per request |
| `FETCH_RATE_PER_HOST_PER_MINUTE` | `30` | Requests per minute to one host |

Brand settings that matter: keywords (the first three are searched), official domains and email domains
(for `Domains Found`, `Brand Emails` and `Hosted On Official Domain`) and the brand name (removed before
sensitive-word matching).

## 11. How it is tested

| Test | File | What it proves | Markers |
|---|---|---|---|
| `test_ac07_indexed_document_with_brand_keyword` | `backend/tests/modules/test_acceptance.py` | A salary-review PDF is typed PDF, matches the brand, has High Exposure Confidence, "confidential" and "salary" patterns, 5+ emails, the official domain, and is Critical. A customer-list XLSX is typed XLSX and labelled "Public Share Link". A public brochure DOCX is Medium with Medium confidence. | AC-07, DOC-01 to DOC-08, OBJ-05 |
| Relevance tests | `backend/tests/unit/test_relevance.py` | Abbreviation collisions are ignored | DOC-04, D-25 |
| Scoring tests | `backend/tests/unit/test_scoring.py` | Document rules and the Medium/High/Critical clamp | - |
| `test_documents_scan_fails_when_every_search_is_unavailable` | `backend/tests/unit/test_runner_reporting.py` | With every search unavailable the run is `failed`, not a clean result | RDA-03, RDA-17, RDA-21 |

The acceptance test uses simulated search results (`backend/tests/fixtures/sources/documents_search.json`)
and four test documents in `backend/tests/fixtures/site/docs/` for a fictional test brand.

## 12. Known limitations and missing capabilities

| Limitation | Effect |
|---|---|
| No document metadata | Author, company, creation date and the software used are not read from the file properties. These often reveal who leaked a file. |
| No embedded URLs | Links inside the document are not extracted or checked. |
| Many share links are not downloadable | OneDrive, Box, SharePoint and Google Docs links usually return an HTML page, so the file is "not accessible": no text, Low confidence. Large Google Drive files may also return a warning page. |
| Only text is read | Scanned PDFs (images of text) give no text; there is no OCR. Images inside documents are not checked for the logo. |
| Limits on size and length | Files over 25 MB, PDF pages after 50, and spreadsheet rows after 5,000 per sheet are not read. |
| Broad sensitive words | Words such as "customer", "board", "audit", "invoice" and "pan" appear in many harmless files and raise the score by +30. |
| Brand word always gives +30 | Every finding starts at Medium, including public brochures on the official site. "Hosted On Official Domain" helps triage but does not lower the score. |
| No PPT, CSV or other file-type searches | Searches cover pdf, docx, xlsx, pptx, doc and xls. CSV and PPT are recognised only if found another way (for example on a share link). |
| Only the first three brand terms are searched | Other keywords are not used. |
| Free search is best-effort | Without an API key, only some of the seven searches may run per scan (D-23). |
| No personal-data classification | Emails are counted, but names, phone numbers, account numbers and ID numbers are not detected as values (only the words "account number", "pan", "aadhaar" and similar). |
| No paste sites or code repositories | Pastebin-style sites and public code repositories are not searched. |

## Key takeaways

- A document exposure is a brand-related file reachable on the internet without logging in.
- The module finds documents with `filetype:` and share-site searches, downloads them through the safe
  fetcher, detects the type from the bytes and extracts text only. Nothing is ever opened in Office or run.
- It reports brand terms, official domains, email counts and sensitive words, plus Exposure Confidence
  (how sure we are that real data is exposed) and Hosted On Official Domain (published versus leaked).
- Points follow D-06 (+30 brand, +20 official domain, +30 sensitive words, +20 for 5+ emails); levels are
  clamped to Medium, High or Critical.
- File properties and links inside documents are not yet examined.
