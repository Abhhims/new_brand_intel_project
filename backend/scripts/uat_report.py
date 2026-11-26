"""Generate docs/reports/UAT-REPORT.md (DEL-07) from the requirements register + automated test results.

    python -m pytest                     # writes reports/requirements-results.json
    python -m scripts.uat_report         # writes ../docs/reports/UAT-REPORT.md

Each requirement ID in docs/requirements/01-requirements-register.md gets one status:
  PASS     every automated test tagged with the ID passed
  FAIL     at least one tagged test failed
  VERIFIED no automated test, but the listed artefact exists (documents, files, configuration)
  N/A      out-of-scope items (confirmed not built)
  DEFERRED moved to Phase 2 by a recorded decision
  OPEN     no evidence yet
"""

from __future__ import annotations

import json
import re
import subprocess
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REGISTER = ROOT / "docs" / "requirements" / "01-requirements-register.md"
RESULTS = ROOT / "backend" / "reports" / "requirements-results.json"
OUT = ROOT / "docs" / "reports" / "UAT-REPORT.md"

# Requirements proven by an artefact rather than a test: ID -> (description, path relative to repo root)
ARTEFACTS: dict[str, tuple[str, str]] = {
    "FND-01": ("Repository with backend, frontend, deploy, docs, fixtures", "backend/pyproject.toml"),
    "FND-02": ("Alembic migrations create the schema (used by every integration test run)", "backend/app/alembic/versions"),
    "FND-09": ("PostgreSQL + Redis services", "deploy/docker-compose.yml"),
    "FND-10": ("S3-compatible evidence store service", "deploy/docker-compose.yml"),
    "FND-14": ("Performance notes and measured timings", "docs/guides/OPERATIONS.md"),
    "FND-15": ("Deployment guide and production configuration checks", "docs/guides/DEPLOYMENT.md"),
    "DSH-20": ("Responsive layout (phone/tablet screenshots in the demo guide)", "docs/demo/DEMO-GUIDE.md"),
    "OBJ-08": ("Production-ready: deployment guide, secrets checks, health checks", "docs/guides/DEPLOYMENT.md"),
    "DEL-01": ("Web application", "frontend/package.json"),
    "DEL-02": ("Source code repository", "README.md"),
    "DEL-03": ("Schema & migration scripts", "docs/guides/DATA-MODEL.md"),
    "DEL-04": ("API documentation", "docs/api/API-GUIDE.md"),
    "DEL-05": ("Deployment guide", "docs/guides/DEPLOYMENT.md"),
    "DEL-06": ("Configuration guide for new brands", "docs/guides/BRAND-CONFIGURATION.md"),
    "DEL-07": ("Test / UAT report", "docs/reports/UAT-REPORT.md"),
    "RDA-23": ("Beginner-friendly handbook, one folder per chapter", "docs/handbook/README.md"),
    "DEL-08": ("Sample monitoring data: fictional test brand + simulated sources, inside the test suite only (D-32)",
               "backend/tests/support/seed_test_brand.py"),
    "EML-20": ("Email dashboard pages (upload, list, detail, brand email-security panel)",
               "frontend/src/app/(app)/emails/page.tsx"),
}


# Requirements deferred to Phase 2 with a recorded decision (owner delegated choices on 2026-10-06)
DEFERRED: dict[str, str] = {
}


def parse_register() -> list[dict]:
    rows, section = [], ""
    for line in REGISTER.read_text(encoding="utf-8").splitlines():
        if line.startswith("## "):
            section = line[3:].strip()
            continue
        m = re.match(r"^\|\s*([A-Z]+-\d+)\s*\|\s*(.+?)\s*\|", line)
        if m and not m.group(1).startswith(("CONFLICT", "GAP")):
            rows.append({"id": m.group(1), "text": m.group(2), "section": section})
    return rows


def load_results() -> tuple[dict[str, list[dict]], dict]:
    if not RESULTS.exists():
        return {}, {}
    data = json.loads(RESULTS.read_text(encoding="utf-8"))
    by_req: dict[str, list[dict]] = defaultdict(list)
    for r in data["results"]:
        for rid in r["requirements"]:
            by_req[rid].append(r)
    return by_req, data


def status_for(rid: str, tests: list[dict]) -> tuple[str, str]:
    if rid.startswith("OOS-"):
        return "N/A", "Out of scope for Phase 1 — confirmed not built"
    if rid in DEFERRED:
        return "DEFERRED", DEFERRED[rid]
    tests = [t for t in tests if t["outcome"] != "skipped"]  # skipped (e.g. e2e without a running stack) proves nothing
    if tests:
        failed = [t for t in tests if t["outcome"] != "passed"]
        names = ", ".join(sorted({t["test"].split("::")[-1] for t in tests}))
        return ("FAIL" if failed else "PASS"), names
    if rid in ARTEFACTS:
        desc, rel = ARTEFACTS[rid]
        return ("VERIFIED" if (ROOT / rel).exists() else "OPEN"), f"{desc} — `{rel}`"
    return "OPEN", "No evidence yet"


def git_rev() -> str:
    try:
        return subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True, text=True,
                              timeout=5).stdout.strip() or "uncommitted"
    except OSError:
        return "unknown"


REGISTER_STATUS = {"PASS": "Tested ✅", "VERIFIED": "Verified ✅", "FAIL": "Failing ❌", "OPEN": "Open",
                   "DEFERRED": "Deferred (decision)"}
_STATUS_WORDS = ("Open", "Designed", "Built", "Tested", "Verified", "Failing", "Deferred", "Accepted")


def update_register(statuses: dict[str, str]) -> None:
    """Write each ID's tested status into the Status column of the register (owner sign-off = 'Accepted')."""
    lines = REGISTER.read_text(encoding="utf-8").splitlines()
    out = []
    for line in lines:
        m = re.match(r"^\|\s*([A-Z]+-\d+)\s*\|", line)
        if m and m.group(1) in statuses:
            cells = line.rstrip().rstrip("|").split("|")
            last = cells[-1].strip()
            if last.startswith(_STATUS_WORDS) and not last.startswith("Accepted"):
                cells[-1] = f" {REGISTER_STATUS.get(statuses[m.group(1)], last)} "
                line = "|".join(cells) + "|"
        out.append(line)
    REGISTER.write_text("\n".join(out) + "\n", encoding="utf-8")


def main() -> None:
    reqs = parse_register()
    by_req, data = load_results()
    results = data.get("results", [])
    counts: dict[str, int] = defaultdict(int)
    lines_by_section: dict[str, list[str]] = defaultdict(list)
    statuses: dict[str, str] = {}
    for r in reqs:
        st, evidence = status_for(r["id"], by_req.get(r["id"], []))
        statuses[r["id"]] = st
        counts[st] += 1
        icon = {"PASS": "✅ PASS", "FAIL": "❌ FAIL", "VERIFIED": "✅ VERIFIED", "N/A": "➖ N/A", "OPEN": "⚠️ OPEN",
                "DEFERRED": "⏸ DEFERRED"}[st]
        lines_by_section[r["section"]].append(f"| {r['id']} | {r['text']} | {icon} | {evidence} |")

    ac = [r for r in reqs if r["id"].startswith("AC-")]
    ac_lines = []
    for r in ac:
        st, evidence = status_for(r["id"], by_req.get(r["id"], []))
        ac_lines.append(f"| {r['id']} | {r['text']} | {'✅' if st == 'PASS' else '❌'} {st} | {evidence} |")

    passed = sum(1 for t in results if t["outcome"] == "passed")
    failed = sum(1 for t in results if t["outcome"] not in ("passed", "skipped"))
    total = len(reqs)
    done = counts["PASS"] + counts["VERIFIED"] + counts["N/A"]
    out = [
        "# Test / UAT Report — Beyond Cloud Brand Intelligence Platform",
        "",
        f"- **Generated:** {datetime.now(UTC):%Y-%m-%d %H:%M} UTC from automated test results of "
        f"{data.get('generated_at', 'n/a')[:16].replace('T', ' ')} UTC",
        f"- **Code version:** `{git_rev()}`",
        f"- **Automated tests:** {passed} passed, {failed} failed, "
        f"{len(results) - passed - failed} skipped ({len(results)} total)",
        f"- **Requirements:** {done} of {total} satisfied — {counts['PASS']} passed by automated tests, "
        f"{counts['VERIFIED']} verified by artefact, {counts['N/A']} out of scope; "
        f"{counts['DEFERRED']} deferred by decision, {counts['FAIL']} failing, {counts['OPEN']} open",
        "",
        "How to reproduce: start the infrastructure (`docs/guides/DEPLOYMENT.md`), then in `backend/` run "
        "`python -m uv run pytest` and `python -m uv run python -m scripts.uat_report`. Requirement IDs come from "
        "`docs/requirements/01-requirements-register.md`; decisions (D-xx) from `docs/decisions/DECISION-LOG.md`.",
        "",
        "## 1. Minimum acceptance criteria (§9)",
        "",
        "| ID | Criterion | Result | Proven by |",
        "|---|---|---|---|",
        *ac_lines,
        "",
        "## 2. Every requirement",
        "",
    ]
    for section, lines in lines_by_section.items():
        out += [f"### {section}", "", "| ID | Requirement | Result | Evidence |", "|---|---|---|---|", *lines, ""]
    out += ["## 3. Automated test log", "", "| Test | Result | Requirements | Seconds |", "|---|---|---|---|"]
    for t in sorted(results, key=lambda x: x["test"]):
        out.append(f"| `{t['test']}` | {t['outcome']} | {', '.join(t['requirements']) or '—'} | {t['duration']} |")
    out += ["", "## 4. Manual UAT checklist (analyst sign-off)", "",
            "Run through `docs/demo/DEMO-GUIDE.md` and tick each item.", "",
            "| # | Check | Tester | Date | Result |", "|---|---|---|---|---|",
            "| 1 | Log in as analyst; dashboard tiles and charts show today's numbers | | | |",
            "| 2 | Add a new brand with logo, favicon, domains, packages, publishers, handles | | | |",
            "| 3 | Run a scan; scan appears in Scans with statistics | | | |",
            "| 4 | Alert queue filters (brand, module, risk, status, dates, search) give expected rows | | | |",
            "| 5 | Open a phishing alert: screenshot, SSL, WHOIS, favicon evidence visible | | | |",
            "| 6 | Move an alert New → Under Review → Confirmed → Closed with notes; history shows each step | | | |",
            "| 7 | Mark a look-alike as False Positive | | | |",
            "| 8 | Export CSV and PDF with filters applied | | | |",
            "| 9 | Admin creates an analyst user; analyst cannot edit brands | | | |",
            "| 10 | Layout usable on a phone and a tablet | | | |", ""]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(out), encoding="utf-8")
    update_register(statuses)
    print(f"uat_report: {OUT} — {done}/{total} satisfied, {counts['FAIL']} failing, {counts['OPEN']} open")


if __name__ == "__main__":
    main()
