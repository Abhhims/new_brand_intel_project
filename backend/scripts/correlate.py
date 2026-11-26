"""Correlate stored findings (SP4, D-49): extract the indicators of every finding from the evidence it already has,
then re-assess confidence with the links found, and print each brand's campaigns. Nothing is re-fetched; risk
scores, decisions and alerts are not touched. Run: python -m scripts.correlate
"""

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.core import correlation
from app.core.confidence import assess
from app.core.findings import CAPTURE_KINDS
from app.db.models import Brand, Finding, FindingStage
from app.db.session import session_scope


def main() -> None:
    with session_scope() as db:
        findings = db.scalars(select(Finding).options(selectinload(Finding.evidence))).all()
        for f in findings:
            evidence = [(e.kind.value, e.meta or {}) for e in f.evidence]
            correlation.store(db, f, correlation.extract(f.module, f.entity_key, f.details or {}, evidence))
        linked = 0
        for f in findings:
            links = correlation.strong_link_count(db, f)
            linked += bool(links)
            conf = assess(f.module, (f.signals or {}).get("rules", {}), f.details or {},
                          analysed=f.stage == FindingStage.finding,
                          captured=any(e.kind.value in CAPTURE_KINDS for e in f.evidence), links=links)
            f.signals = {**(f.signals or {}), "confidence": conf.as_dict()}
            f.details = {**(f.details or {}), "Confidence": conf.label}
        print(f"correlate: {len(findings)} findings, {linked} linked to at least one other by a strong identifier")
        for brand in db.scalars(select(Brand)).all():
            camps = correlation.campaigns(db, brand.id)
            print(f"  {brand.name}: {len(camps)} campaigns")
            for c in camps[:10]:
                shared = "; ".join(f"{s['label']}: {s['value']} ({s['findings']})" for s in c["shared"][:3])
                print(f"    {c['size']:3} findings — {shared}")


if __name__ == "__main__":
    main()
