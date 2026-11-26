# Architecture Guide — read in this order

The technical overview is here; the module-by-module explanations (which files, which tools and how they work,
where the data comes from, how risk is calculated, what is stored, which tests prove it) live in the handbook,
one folder per chapter.

| # | Document | What it explains |
|---|---|---|
| 0 | [00-OVERVIEW.md](00-OVERVIEW.md) | The big picture: services, folders, how a scan flows end to end, the data model |
| 1 | [Handbook 01 — Architecture](../handbook/01-architecture/01-architecture.md) | Containers, technology choices, the complete scan-to-dashboard process, scan states and components |
| 2 | [Handbook 02 — Risk scoring](../handbook/02-risk-scoring/02-risk-scoring.md) | Every scoring rule, levels, caps, worked examples |
| 3 | [Handbook 03 — Domain monitoring](../handbook/03-domain-monitoring/03-domain-monitoring.md) | Typosquat + MX + Active Phishing (one pipeline) |
| 4 | [Handbook 04 — Fake APK](../handbook/04-fake-apk/04-fake-apk.md) | Fake APK monitoring, including signing-certificate checks |
| 5 | [Handbook 05 — Rogue apps](../handbook/05-rogue-apps/05-rogue-apps.md) | Google Play rogue app monitoring and status tracking |
| 6 | [Handbook 06 — Social impersonation](../handbook/06-social-impersonation/06-social-impersonation.md) | X, Facebook, Instagram, LinkedIn, Telegram |
| 7 | [Handbook 07 — Sensitive documents](../handbook/07-sensitive-documents/07-sensitive-documents.md) | Sensitive document exposure |
| 8 | [Handbook 08 — Logo misuse](../handbook/08-logo-misuse/08-logo-misuse.md) | Brand logo on websites |
| 9 | [Handbook 09 — Phishing email](../handbook/09-phishing-email/09-phishing-email.md) | Email analysis, domain email security, DMARC reports (D-28) |
| 10 | [Handbook 10 — Dashboard and workflow](../handbook/10-dashboard-and-workflow/10-dashboard-and-workflow.md) | REST API, roles, alert workflow, exports, the Next.js dashboard, Integrations page |
| 11 | [Handbook 11 — Tools reference](../handbook/11-tools-reference/11-tools-reference.md) | Every tool, why it was chosen, what happens when it is unavailable |

Related documents: requirements and IDs in `docs/requirements/`, every design choice in
`docs/decisions/DECISION-LOG.md` (D-xx numbers), operations in `docs/guides/`.

Note (2026-10-09): the earlier per-module files `01-CORE-ENGINE.md` … `09-EMAIL.md` in this folder are no longer
present; their content is covered, in more depth, by the handbook chapters above.
