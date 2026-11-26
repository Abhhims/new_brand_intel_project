"""Re-analyse and re-score existing social media findings with the current rules (social_media module only).

The stored title / description of each finding is checked again (fake contact details, fake customer-care claims,
scam wording, brand abuse — including look-alike lettering), then scored. A finding that now meets its brand's
alert level, and was not alerted at that level before, gets an alert (trigger "rescore"); no notifications are sent.
An open finding that the current rules would no longer report (e.g. a short brand name next to a phone number, with
no scam wording: "Navi Mumbai" shops, D-45) is set to Ignored with a note on its timeline; analysts can reopen it.
Run: python -m scripts.rescore_social
"""

from collections import Counter
from datetime import UTC, datetime

from sqlalchemy import delete, func, select
from sqlalchemy.orm import selectinload

from app.core.findings import LEVEL_ORDER, OPEN_DECISIONS, _event, close_authorized, meets_rule
from app.core.scoring import SOCIAL_REASONS, score
from app.db.models import Alert, Brand, EvidenceKind, Finding, FindingDecision, ModuleName
from app.db.session import session_scope
from app.modules.base import BrandContext
from app.modules.social_media.analysis import SCORED_CONTACTS, contact_details, normalize, scam_phrases, strong_phrases
from app.modules.social_media.module import headline_for, social_signals


def _metadata(f: Finding) -> dict:
    metas = [e for e in f.evidence if e.kind == EvidenceKind.metadata and e.meta]
    return max(metas, key=lambda e: e.captured_at).meta if metas else {}


def main() -> None:
    now = datetime.now(UTC)
    changed, alerted, levels, ignored = 0, 0, Counter(), 0
    with session_scope() as db:
        findings = db.scalars(select(Finding).where(Finding.module == ModuleName.social_media)
                              .options(selectinload(Finding.evidence))).all()
        brands = {b.id: b for b in db.scalars(select(Brand).options(selectinload(Brand.assets),
                                                                     selectinload(Brand.allowlist))).all()}
        contexts = {bid: BrandContext.from_brand(b) for bid, b in brands.items()}
        for bid in brands:
            close_authorized(db, bid, (ModuleName.social_media,))
        # idempotent: alerts raised by an earlier run of this script are replaced by this run's
        ids = [f.id for f in findings]
        db.execute(delete(Alert).where(Alert.finding_id.in_(ids), Alert.trigger == "rescore"))
        last = dict(db.execute(select(Alert.finding_id, func.max(Alert.created_at))
                               .where(Alert.finding_id.in_(ids)).group_by(Alert.finding_id)).all())
        for f in findings:
            f.last_alert_at = last.get(f.id)
        db.flush()
        for f in findings:
            meta, rules = _metadata(f), (f.signals or {}).get("rules", {})
            text = normalize(" ".join(x for x in (meta.get("title") or f.details.get("Title"), meta.get("text"),
                                                  meta.get("author"), meta.get("author_handle")) if x))
            contacts = contact_details(text)
            scored = {k: v for k, v in contacts.items() if k in SCORED_CONTACTS}
            phrases = scam_phrases(text)
            ctx = contexts[f.brand_id]
            rel = ctx.relevance(text, name=normalize(meta.get("author") or meta.get("title") or ""))
            scam_context = bool(rel.weak_hits) and bool(strong_phrases(phrases) or (scored and phrases))
            if (f.decision in OPEN_DECISIONS and not (rel.relevant or scam_context)
                    and f.details.get("Logo Match") is not True):
                note = ("Closed automatically: no longer matches the brand rules (D-45) — short brand name "
                        f"{', '.join(rel.weak_hits)} without scam wording")
                _event(db, f, "decision", note, from_status=f.decision.value,
                       to_status=FindingDecision.ignored.value)
                f.decision, f.decision_note, f.decided_at = FindingDecision.ignored, note, now
                ignored += 1
            signals = social_signals(
                brand_in_content="brand_in_content" in rules,
                typo_similarity=f.similarity if "typo_similarity_gt_80" in rules else None,
                logo_match=f.details.get("Logo Match") is True, scored_contacts=scored, phrases=phrases,
                title=f"{meta.get('title') or f.details.get('Title') or ''} {meta.get('author') or ''}",
                paid_ad=f.details.get("Content Type") == "Ad")
            result = score(signals, ModuleName.social_media)
            levels[result.level.value] += 1
            prev_level = f.risk_level
            if result.level != prev_level:
                _event(db, f, "rescored", f"Risk {prev_level.value} → {result.level.value} ({result.score}) "
                                         "— social media criticality rules", from_status=prev_level.value,
                       to_status=result.level.value)
            platform = f.details.get("Platform") or ""
            ctype = (meta.get("type") or f.details.get("Content Type") or "post").lower()
            item_title = meta.get("title") or meta.get("author") or f.source_url or ""
            f.title = f"{headline_for(platform, ctype, signals)}: {item_title}"[:500]
            f.score, f.risk_level, f.signals = result.score, result.level, result.as_dict()
            f.details = {**f.details, "Risk Level": result.level.value,
                         "Criticality Reason": SOCIAL_REASONS[result.tier],
                         "Scam Contacts": [f"{k}: {v}" for k, vs in scored.items() for v in vs],
                         "Scam Phrases": phrases}
            changed += result.level != prev_level

            brand = brands[f.brand_id]
            prev_met = meets_rule(f.stage, prev_level, brand.alert_min_level)
            rose = LEVEL_ORDER.index(result.level) > LEVEL_ORDER.index(prev_level)
            if (f.decision in OPEN_DECISIONS and meets_rule(f.stage, result.level, brand.alert_min_level)
                    and (f.last_alert_at is None or not prev_met or rose)):
                reason = f"Re-scored to {result.level.value} ({result.score}): {SOCIAL_REASONS[result.tier]}"
                alert = Alert(finding_id=f.id, brand_id=f.brand_id, trigger="rescore", reason=reason,
                              score=result.score, risk_level=result.level, reasons=result.as_dict()["rules"],
                              created_at=now)
                db.add(alert)
                db.flush()
                f.last_alert_at = now
                _event(db, f, "alerted", reason, alert_id=alert.id)
                alerted += 1
    print(f"rescore_social: {len(findings)} findings checked, {changed} changed level, {alerted} alerts raised, "
          f"{ignored} no longer relevant (Ignored); "
          f"now {dict(levels)}")


if __name__ == "__main__":
    main()
