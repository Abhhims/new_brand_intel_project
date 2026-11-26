"""Measure phishing-email detection accuracy on a labelled set and write docs/reports/EMAIL-ACCURACY.md.

    python -m scripts.email_accuracy <folder> [--brand "Brand Name"]

<folder> contains two subfolders: phish/*.eml (known phishing) and legit/*.eml (known good). An email is counted
as "flagged" when its risk level is High or Critical. Prints precision, recall and a confusion matrix.

External engines/intel are used if configured; unreachable ones contribute nothing (they are reported as coverage
gaps), so run this on the deployed stack for the most representative numbers.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sqlalchemy import select

from app.core.scoring import score
from app.db.models import Brand, ModuleName
from app.db.session import session_scope
from app.modules.base import BrandContext
from app.modules.email.analysis import analyse
from app.modules.email.parser import parse

ROOT = Path(__file__).resolve().parents[2]
FLAGGED_LEVELS = {"High", "Critical"}


def _ctx(brand_name: str | None) -> BrandContext:
    with session_scope() as db:
        stmt = select(Brand)
        if brand_name:
            stmt = stmt.where(Brand.name == brand_name)
        brand = db.scalar(stmt.order_by(Brand.created_at))
        if brand is None:
            sys.exit("No brand found — create one first, or pass --brand")
        from sqlalchemy.orm import selectinload

        brand = db.scalar(select(Brand).where(Brand.id == brand.id)
                          .options(selectinload(Brand.assets), selectinload(Brand.allowlist)))
        return BrandContext.from_brand(brand)


def _level(path: Path, ctx: BrandContext) -> str:
    parsed = parse(path.read_bytes(), path.name)
    analysis = analyse(parsed, path.read_bytes(), ctx)
    return score(analysis.signals, ModuleName.email).level.value


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("folder")
    ap.add_argument("--brand", default=None)
    args = ap.parse_args()
    folder = Path(args.folder)
    ctx = _ctx(args.brand)

    phish = sorted((folder / "phish").glob("*.eml"))
    legit = sorted((folder / "legit").glob("*.eml"))
    if not phish and not legit:
        sys.exit(f"No .eml files under {folder}/phish or {folder}/legit")

    tp = sum(1 for p in phish if _level(p, ctx) in FLAGGED_LEVELS)
    fn = len(phish) - tp
    fp = sum(1 for p in legit if _level(p, ctx) in FLAGGED_LEVELS)
    tn = len(legit) - fp
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    out = ROOT / "docs" / "reports" / "EMAIL-ACCURACY.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    from datetime import UTC, datetime

    out.write_text(
        f"# Phishing Email Detection Accuracy\n\n"
        f"- Generated: {datetime.now(UTC):%Y-%m-%d %H:%M} UTC\n"
        f"- Sample: {len(phish)} phishing, {len(legit)} legitimate (brand: {ctx.name})\n"
        f"- Flagged = risk level High or Critical\n\n"
        f"| | Flagged | Not flagged |\n|---|---|---|\n"
        f"| **Actually phishing** | {tp} (true positive) | {fn} (false negative) |\n"
        f"| **Actually legitimate** | {fp} (false positive) | {tn} (true negative) |\n\n"
        f"- **Precision:** {precision:.0%}  (of flagged emails, how many were really phishing)\n"
        f"- **Recall:** {recall:.0%}  (of phishing emails, how many we caught)\n"
        f"- **F1:** {f1:.0%}\n\n"
        f"No detector is perfect; this measures the current rules on the supplied set. "
        f"Re-run after adding samples or configuring more threat-intel sources.\n",
        encoding="utf-8")
    print(f"phish={len(phish)} legit={len(legit)} | precision={precision:.0%} recall={recall:.0%} f1={f1:.0%}")
    print(f"written: {out}")


if __name__ == "__main__":
    main()
