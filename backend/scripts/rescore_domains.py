"""Re-score existing look-alike domain findings (typosquat, MX, phishing) with the current rules (D-44, D-45).

The stored observations of each finding are scored again; only the MX records are looked up again (a null MX
"0 ." no longer counts as email-enabled; when the lookup fails the stored records are kept). Findings whose domain
is now on the brand's allowlist are closed as Legitimate. A level change is written to the finding's timeline; no
alerts are raised and no notifications are sent. Run: python -m scripts.rescore_domains
"""

from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import fields

from sqlalchemy import select

from app.core.findings import DOMAIN_MODULES, _event, close_authorized
from app.core.scoring import CAP_REASONS, Signals, email_risk, score
from app.db.models import Brand, Finding
from app.db.session import session_scope
from app.modules.domains.infra import LiveInfra

BOOL_SIGNALS = {f.name for f in fields(Signals) if f.type in (bool, "bool")}


def main() -> None:
    infra = LiveInfra()
    changed, levels, closed = 0, Counter(), 0
    with session_scope() as db:
        for brand in db.scalars(select(Brand)).all():
            closed += close_authorized(db, brand.id, DOMAIN_MODULES)
        findings = db.scalars(select(Finding).where(Finding.module.in_(DOMAIN_MODULES))).all()
        with ThreadPoolExecutor(max_workers=32) as pool:  # MX lookups in parallel; scoring below is instant
            lookups = dict(zip([f.id for f in findings],
                               pool.map(lambda f: infra._records(f.entity_key, "MX"), findings), strict=True))
        for f in findings:
            d, rules = f.details or {}, (f.signals or {}).get("rules", {})
            records, definitive = lookups[f.id]
            mx = [r for r in records if len(r.split()) == 2] if definitive else (d.get("MX Records") or [])
            live = d.get("Website Live") is True
            signals = Signals(**{name: True for name in rules if name in BOOL_SIGNALS and name != "mx_present"},
                              **{"mx_present": bool(mx), "typo_similarity": f.similarity, "page_live": live,
                                 "brand_on_page": d.get("Brand Evidence On Page") is True,
                                 "parked_page": d.get("Parked Page") is True})
            result = score(signals, f.module)
            levels[result.level.value] += 1
            if result.level != f.risk_level:
                _event(db, f, "rescored", f"Risk {f.risk_level.value} → {result.level.value} ({result.score}) — "
                                         "domain scoring rules D-44/D-45", from_status=f.risk_level.value,
                       to_status=result.level.value)
                changed += 1
            f.score, f.risk_level, f.signals = result.score, result.level, result.as_dict()
            f.details = {**d, "Risk Level": result.level.value, "MX Records": mx, "MX Enabled": bool(mx),
                         "Email Risk": email_risk(bool(mx), live).value,
                         "Email-ready": "lookalike_can_send" in rules or bool(mx),
                         "Score Cap": CAP_REASONS.get(result.cap or "")}
    print(f"rescore_domains: {len(findings)} findings checked, {changed} changed level, {closed} closed as "
          f"allowlisted; now {dict(levels)}")


if __name__ == "__main__":
    main()
