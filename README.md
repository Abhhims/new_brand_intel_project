# Beyond Cloud Brand Intelligence Automation Platform

An internal platform for Beyond Cloud analysts. It continuously monitors digital channels for abuse of client
brands — look-alike and phishing domains, email-enabled domains, fake APKs, rogue Google Play apps, social media
impersonation, exposed sensitive documents and unauthorised logo use — scores every finding with one risk model,
stores evidence, and gives analysts a dashboard and review workflow.

| | |
|---|---|
| **Requirements** | [`docs/requirements/00-source-requirements.md`](docs/requirements/00-source-requirements.md) (verbatim) · [`01-requirements-register.md`](docs/requirements/01-requirements-register.md) (every requirement with an ID) |
| **Test / UAT report** | [`docs/reports/UAT-REPORT.md`](docs/reports/UAT-REPORT.md) — pass/fail per requirement, generated from the tests |
| **Decisions** | [`docs/decisions/DECISION-LOG.md`](docs/decisions/DECISION-LOG.md) — every choice not spelled out in the requirements, with demo talking points |
| **Design** | [`docs/superpowers/specs/2026-10-06-beyond-cloud-brand-intel-design.md`](docs/superpowers/specs/2026-10-06-beyond-cloud-brand-intel-design.md) |
| **Guides** | [Deployment](docs/guides/DEPLOYMENT.md) · [Brand configuration](docs/guides/BRAND-CONFIGURATION.md) · [Data model](docs/guides/DATA-MODEL.md) · [Operations](docs/guides/OPERATIONS.md) · [API](docs/api/API-GUIDE.md) |
| **Demo** | [`docs/demo/DEMO-GUIDE.md`](docs/demo/DEMO-GUIDE.md) — script, talking points and Q&A |
| **Architecture, module by module** | [`docs/architecture/README.md`](docs/architecture/README.md) — files, tools, data flow and risk calculation for each module |

## Quick start (Docker)

```bash
cp deploy/.env.example deploy/.env          # then edit the values marked CHANGE
docker compose -f deploy/docker-compose.yml --profile app up -d --build
```

Open **http://localhost:3000** and sign in with `BOOTSTRAP_ADMIN_EMAIL` / `BOOTSTRAP_ADMIN_PASSWORD` from `.env`
(created on first start when no user exists). Add your brand under **Brands**, then press **Run scan now**.
Only the admin creates further accounts (**Users**). API docs: **http://localhost:8010/docs**.

## What is inside

```
backend/     FastAPI API, Celery workers, detection modules, tests        (Python 3.12, uv)
  app/core/      safe fetcher, scoring, similarity, imaging, evidence, alerts, browser, auth
  app/modules/   domains (typosquat + MX + phishing), apk, rogue_app, social, documents, logo
  app/api/       REST endpoints          app/workers/  Celery app, scan engine, schedules
  scripts/       bootstrap admin, Telegram login, email accuracy, generate UAT report
  tests/         unit, module acceptance (AC-01…08), API (AC-10), browser end-to-end (AC-09)
  tests/support/  test-only code: simulated sources, test-brand seeding, APK/email fixture builders
  tests/fixtures/ test-only data: fictional test brand, simulated sources, test website
frontend/    Next.js analyst dashboard                                     (TypeScript, Tailwind, shadcn/ui)
deploy/      docker-compose.yml, Dockerfiles, .env.example
docs/        requirements, decisions, design, guides, API, reports, demo
```

## Modules

| Module (requirement §) | Finds | Main sources |
|---|---|---|
| Typosquat (§3.1) | Registered look-alike domains | dnstwist patterns × monitored TLDs, DNS, WHOIS/RDAP, Certificate Transparency |
| MX records (§3.1) | Look-alikes able to send/receive email | DNS MX |
| Active phishing (§3.1) | Live look-alike sites, login/payment pages | HTTP/TLS probe, headless browser screenshot, favicon hash, page keywords |
| Fake APK (§3.2) | APKs imitating official apps | Web search over APK sites, listing pages, APK manifest (never executed) |
| Rogue apps (§3.3) | Unauthorised Google Play listings | Google Play search, publisher allowlist, icon match, state tracking |
| Social impersonation (§3.4) | Fake accounts on X, Facebook, Instagram, LinkedIn, Telegram | Telegram API, site-restricted web search, profile image match |
| Sensitive documents (§3.5) | Public PDF/Office files about the brand | filetype/share-link web search, download + text extraction |
| Logo on websites (§3.6) | Unauthorised use of the logo | Headless browser image extraction, perceptual hashing |

The product uses **live sources only** — there is no demo mode (D-32). Simulated sources exist only inside the test
suite (`backend/tests/support/fixture_sources.py`, data in `backend/tests/fixtures/`) and are injected into the real
module runners by the automated acceptance tests, which run in their own test database (D-09, D-27, D-30, D-32).

Every scan run reports **which parts ran** (per-component results) and ends `completed`, `partially_completed`,
`completed_with_errors`, `failed` or `cancelled` — a source that could not be checked is never shown as "nothing
found" (D-31). The **Integrations** page shows every external tool, whether it is configured and how it last ran.

## Running tests

```bash
docker compose -f deploy/docker-compose.yml --profile test up -d postgres redis minio fixtures
cd backend
python -m uv run pytest                                  # unit + acceptance + API tests
python -m uv run python -m scripts.uat_report            # → docs/reports/UAT-REPORT.md
```

See [Operations](docs/guides/OPERATIONS.md) for the browser end-to-end tests and local development without Docker.
