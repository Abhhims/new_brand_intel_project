"""Assess the confidence (D-47) of every stored finding from the evidence it already has. Nothing is re-fetched,
risk scores and decisions are not touched, no alerts are raised. Run: python -m scripts.assess_confidence
"""

from collections import Counter

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.core.confidence import assess
from app.core.findings import CAPTURE_KINDS
from app.db.models import Finding, FindingStage
from app.db.session import session_scope


def main() -> None:
    levels: Counter = Counter()
    with session_scope() as db:
        findings = db.scalars(select(Finding).options(selectinload(Finding.evidence))).all()
        for f in findings:
            conf = assess(f.module, (f.signals or {}).get("rules", {}), f.details or {},
                          analysed=f.stage == FindingStage.finding,
                          captured=any(e.kind.value in CAPTURE_KINDS for e in f.evidence))
            f.signals = {**(f.signals or {}), "confidence": conf.as_dict()}
            f.details = {**(f.details or {}), "Confidence": conf.label}
            levels[(f.module.value, conf.level)] += 1
    print(f"assess_confidence: {len(findings)} findings assessed")
    for (module, level), n in sorted(levels.items()):
        print(f"  {module:14} {level:7} {n}")


if __name__ == "__main__":
    main()
