# Beyond Cloud Brand Intelligence Handbook

In this handbook:
- What the Beyond Cloud Brand Intelligence platform is, who uses it and why.
- How every part of the system works, from a scan starting to a risk score on the dashboard.
- One chapter per detection module, plus chapters on scoring, tools, operations and known gaps.
- Every statement describes the code as it is on 2026-10-09. Three pieces of work were completed that day:
  roadmap sub-project 1 (SP1, honest scan status, decisions D-31 and D-32), sub-project 2 (SP2, the finding
  model: candidates, findings, alerts, observations and analyst decisions, D-33 to D-37), and the new social
  media brand-misuse monitor (D-38).

## Purpose

This handbook explains the platform to someone who has never heard of brand intelligence and has never
seen this code. It is written in plain language. Technical terms are explained the first time they appear,
and Chapter 00 has a glossary.

The handbook does not replace the technical notes in `docs/architecture/` and `docs/guides/`. It builds a
complete mental model first, and points to those notes and to the code for detail.

## Who it is for

| Reader | What they get from it |
|---|---|
| New analyst at Beyond Cloud | What each alert means, how the score is built, how to work an alert |
| New developer | Where every piece of code lives and how the parts connect |
| Project owner or manager | What the platform does and does not do, and its known gaps |
| Client or auditor (with care) | How decisions are made and why the results can be trusted |

## How to read it

- **Everyone:** read Chapter 00 (introduction) and Chapter 01 (architecture) first. Then read Chapter 02
  (risk scoring), because every module chapter refers to it.
- **Analysts:** then read Chapter 10 (dashboard and workflow) and the module chapters for the alerts you see most.
- **Developers:** then read Chapter 11 (tools reference) and Chapter 12 (operations and testing).
- **Planners:** Chapter 13 (gaps and roadmap) lists what is missing or planned.
- **Whoever sets up the platform:** Chapter 14, section 10, explains step by step how to get each social media
  API key and where to put it.

Code is referenced with paths such as `backend/app/core/scoring.py`. Decisions are referenced by their ID,
such as D-29, from `docs/decisions/DECISION-LOG.md`. Requirements are referenced by ID, such as TYP-01, from
`docs/requirements/01-requirements-register.md`.

All examples use a fictional brand, **Example Bank**, with the official website `examplebank.com`. It is
not a real company.

## Chapters

Each chapter lives in its own folder: `docs/handbook/<folder>/<folder>.md`.

| No. | Folder | What it covers |
|---|---|---|
| 00 | `00-introduction` | What brand abuse is, who uses the platform, what it does and does not do, glossary |
| 01 | `01-architecture` | Containers, technology choices, folder map, data model, and the full scan-to-dashboard process, including scan states and scan components |
| 02 | `02-risk-scoring` | The points table, risk levels, module ranges, score caps, email scoring, worked examples |
| 03 | `03-domain-monitoring` | Typosquat, MX record and active phishing detection (the domain pipeline) |
| 04 | `04-fake-apk` | Finding fake Android APK files on mirror sites and checking their signatures |
| 05 | `05-rogue-apps` | Unauthorised apps on Google Play that use the brand |
| 06 | `06-social-impersonation` | Fake social media accounts on Telegram, X, Facebook, Instagram and LinkedIn |
| 07 | `07-sensitive-documents` | Public documents (PDF, DOCX, XLSX, PPTX) that mention the brand or leak data |
| 08 | `08-logo-misuse` | The official logo used on websites that are not the brand's |
| 09 | `09-phishing-email` | Reported phishing emails, the brand's own email security, DMARC reports |
| 10 | `10-dashboard-and-workflow` | The web dashboard, coverage banner, error panels, alert queue, alert detail, Findings page, analyst decisions, timeline, exports, Scans and Integrations pages |
| 11 | `11-tools-reference` | Every library, service and data source used, and what it is used for |
| 12 | `12-operations-and-testing` | Running, configuring, monitoring and testing the platform |
| 13 | `13-gaps-and-roadmap` | Known limitations, what SP1 and SP2 fixed, and planned improvements (SP3 to SP5) |
| 14 | `14-social-media-monitoring` | Posts, videos, ads and channels that misuse the brand on YouTube, Facebook, Instagram, X, Threads, Meta ads, Pinterest, TikTok, LinkedIn and Telegram; fake contact details; which API keys to get and how |

## How to turn the handbook into a PDF

Every chapter is plain GitHub Markdown: headings, tables, lists and fenced code blocks only. No images,
no HTML and no diagrams that need special software. This keeps conversion simple.

**Option 1: paste into a word processor**

1. Open Word or Google Docs.
2. Open each chapter file in order, from `00-introduction` to `14-social-media-monitoring`.
3. Copy the rendered text (for example from the GitHub file view) and paste it in.
4. Export or download the document as PDF.

Tip: set fenced code blocks (the ASCII diagrams) to a monospaced font such as Consolas or Courier New,
so the diagrams stay aligned.

**Option 2: pandoc**

[pandoc](https://pandoc.org) converts Markdown to PDF in one command. Run it from the repository root:

```
pandoc docs/handbook/*/*.md -o handbook.pdf
```

The folder names start with a number, so the shell sorts the chapters in the right order. pandoc needs a
PDF engine (for example a LaTeX installation, or `--pdf-engine=weasyprint`). To include this index page
as well, list it first:

```
pandoc docs/handbook/README.md docs/handbook/*/*.md -o handbook.pdf
```

## Key takeaways

- The handbook has 15 chapters. Each one is a single Markdown file in its own numbered folder.
- Read 00, 01 and 02 first. Every other chapter builds on them.
- Examples use the fictional Example Bank (`examplebank.com`).
- Code paths, decision IDs (D-xx) and requirement IDs point to the source of each fact.
- Paste the chapters into Word or Google Docs in order, or run pandoc, to get a PDF.
