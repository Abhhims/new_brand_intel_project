"""Turn detections into findings, observations and alerts, and run the analyst workflow (SP2, D-33…D-36).

record_detection() is the only writer of findings/observations/alerts: match the entity, store an observation and its
evidence, compare with the previous state, update the finding, then decide whether to raise an alert.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

import structlog
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.allowlist import social_handle
from app.core import correlation
from app.core import evidence as store
from app.core.confidence import assess
from app.core.scoring import CAP_REASONS, CAPPED_MODULES, SOCIAL_REASONS, score
from app.db.models import (
    Alert,
    AllowKind,
    Brand,
    BrandAllow,
    Evidence,
    EvidenceKind,
    Finding,
    FindingDecision,
    FindingEvent,
    FindingStage,
    ModuleName,
    Observation,
    RiskLevel,
)
from app.modules.base import Detection

log = structlog.get_logger(__name__)

# One finding per suspicious domain; its module is the furthest stage reached (decision D-19)
DOMAIN_MODULES = (ModuleName.typosquat, ModuleName.mx, ModuleName.phishing)
LEVEL_ORDER = [RiskLevel.low, RiskLevel.medium, RiskLevel.high, RiskLevel.critical]

D = FindingDecision
OPEN_DECISIONS = (D.new, D.investigating)
CLOSED_DECISIONS = (D.false_positive, D.legitimate, D.ignored, D.resolved)
NOTE_REQUIRED = (D.false_positive, D.legitimate, D.ignored)

# Analyst workflow (D-35). "Reopened" is an event: a closed decision moved back to New.
ALLOWED_TRANSITIONS: dict[FindingDecision, set[FindingDecision]] = {
    D.new: {D.investigating, D.confirmed_threat, D.false_positive, D.legitimate, D.ignored},
    D.investigating: {D.new, D.confirmed_threat, D.false_positive, D.legitimate, D.ignored},
    D.confirmed_threat: {D.investigating, D.resolved},
    D.false_positive: {D.new, D.investigating},
    D.legitimate: {D.new, D.investigating},
    D.ignored: {D.new, D.investigating},
    D.resolved: {D.new, D.investigating},
}

# Meaningful changes (D-36): fact -> text shown when it turns True
CHANGE_TEXT = {
    "live": "Website went live",
    "login_form": "Login/payment form detected",
    "logo_match": "Official logo detected",
    "mx": "Domain can now receive email",
    "signer_mismatch": "APK signed by a non-official certificate",
    "listed": "App listed again",
    "intel_listed": "Listed by threat intelligence",
}

# Evidence that was captured directly (counts towards confidence, D-47)
CAPTURE_KINDS = {"screenshot", "html", "file"}

# Legitimate -> allowlist kind (D-35)
ALLOW_KIND_FOR = {
    ModuleName.typosquat: AllowKind.domain, ModuleName.mx: AllowKind.domain, ModuleName.phishing: AllowKind.domain,
    ModuleName.rogue_app: AllowKind.package, ModuleName.apk: AllowKind.package,
    ModuleName.social: AllowKind.social_handle,
}


class InvalidTransition(ValueError):
    pass


# ------------------------------------------------------------------------------------------------ state and diff
def derive_state(det: Detection, module: ModuleName) -> dict:
    """Comparable facts of this observation. None = unknown (never compared)."""
    s = det.signals
    state: dict = {"logo_match": bool(s.official_logo or s.social_image_match)}
    if module in DOMAIN_MODULES or module == ModuleName.logo:
        state["live"] = bool(s.page_live) or module == ModuleName.logo
        state["login_form"] = bool(s.login_payment_keywords)
    if module in DOMAIN_MODULES:
        state["mx"] = bool(s.mx_present)
    state.update(det.state or {})  # module knows best (e.g. capture failed -> live None, listed False)
    return state


def diff_state(old: dict, new: dict) -> list[str]:
    """Meaningful changes between two observations: a known False becoming True."""
    return [text for fact, text in CHANGE_TEXT.items() if old.get(fact) is False and new.get(fact) is True]


def merge_state(old: dict, new: dict) -> dict:
    """Unknown values keep the last known value."""
    return {**old, **{k: v for k, v in new.items() if v is not None}}


def meets_rule(stage: FindingStage, level: RiskLevel, brand_min: RiskLevel) -> bool:
    """D-34: only analysed findings at or above the brand's alert level become alerts."""
    return stage == FindingStage.finding and LEVEL_ORDER.index(level) >= LEVEL_ORDER.index(brand_min)


# ------------------------------------------------------------------------------------------------ evidence
def _store_evidence(db: Session, finding: Finding, observation: Observation, items) -> int:
    """Store new evidence only: an identical file (same SHA256) or identical metadata seen before for this finding is
    not stored again, so daily re-scans don't pile up duplicates."""
    stored = 0
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
    existing = db.scalars(select(Evidence).where(Evidence.finding_id == finding.id)).all()
    seen_files = {(e.kind.value, e.sha256) for e in existing if e.sha256}
    seen_meta = {(e.kind.value, json.dumps(e.meta, sort_keys=True, default=str)) for e in existing if not e.sha256}
    for i, item in enumerate(items):
        if item.data:
            if (item.kind, store.sha256(item.data)) in seen_files:
                continue
        elif (item.kind, json.dumps(item.meta or {}, sort_keys=True, default=str)) in seen_meta:
            continue
        row = Evidence(finding_id=finding.id, observation_id=observation.id, kind=EvidenceKind(item.kind),
                       meta=item.meta or {}, content_type=item.content_type)
        if item.data:
            ext = store.extension_for(item.content_type, item.name)
            key = f"findings/{finding.brand_id}/{finding.id}/{ts}-{i:02d}-{item.kind}.{ext}"
            obj = store.put(key, item.data, item.content_type)
            row.storage_key, row.sha256, row.size, row.content_type = obj.storage_key, obj.sha256, obj.size, obj.content_type
        db.add(row)
        stored += 1
    return stored


def _kind(item) -> str:
    return str(getattr(item.kind, "value", item.kind))


def _event(db: Session, finding: Finding, kind: str, note: str | None = None, **kw) -> FindingEvent:
    ev = FindingEvent(finding_id=finding.id, kind=kind, note=note, **kw)
    db.add(ev)
    return ev


# ------------------------------------------------------------------------------------------------ engine
def record_detection(db: Session, brand_id: uuid.UUID, module: ModuleName, det: Detection,
                     scan_id: uuid.UUID | None = None, channel: str = "scan") -> tuple[Finding, Alert | None, bool]:
    """Persist one detection. Returns (finding, alert raised or None, created)."""
    brand = db.get(Brand, brand_id)
    result = score(det.signals, module)
    now = datetime.now(UTC)
    stage = FindingStage.finding if det.analysed else FindingStage.candidate
    state = derive_state(det, module)
    modules = DOMAIN_MODULES if module in DOMAIN_MODULES else (module,)
    finding = db.scalar(select(Finding).where(Finding.brand_id == brand_id, Finding.module.in_(modules),
                                              Finding.entity_key == det.entity_key))
    created = finding is None
    if created:
        finding = Finding(id=uuid.uuid4(), brand_id=brand_id, module=module, entity_key=det.entity_key,
                          stage=stage, decision=D.new, first_seen=now, score=result.score,
                          risk_level=result.level, title=det.title[:500], state={})
        db.add(finding)
        db.flush()
    # SP4 (D-49): stable identifiers from this finding's own evidence; shared ones link it to other findings
    correlation.store(db, finding, correlation.extract(module, det.entity_key, det.details,
                                                       [(_kind(e), e.meta or {}) for e in det.evidence]))
    conf = assess(module, result.fired, det.details, analysed=det.analysed,
                  captured=any(_kind(e) in CAPTURE_KINDS for e in det.evidence),
                  links=correlation.strong_link_count(db, finding))
    scored = {**result.as_dict(), "confidence": conf.as_dict()}  # risk and confidence, kept apart (D-47)

    prev_state = dict(finding.state or {})
    prev_level, prev_stage = finding.risk_level, finding.stage
    prev_met = (not created) and meets_rule(prev_stage, prev_level, brand.alert_min_level)

    observation = Observation(finding_id=finding.id, scan_id=scan_id, channel=channel, observed_at=now, stage=stage,
                              module=module, score=result.score, risk_level=result.level,
                              signals=scored, state=state, details=det.details)
    db.add(observation)
    db.flush()

    # ---- timeline: what changed since the previous observation
    changes: list[str] = []
    if created:
        _event(db, finding, "discovered", f"{stage.value} found by {module.value} module, risk "
                                          f"{result.level.value} ({result.score})", observation_id=observation.id,
               to_status=stage.value)
    else:
        if prev_stage == FindingStage.candidate and stage == FindingStage.finding:
            changes.append("Analysis found evidence (Candidate → Finding)")
            _event(db, finding, "promoted", changes[-1], observation_id=observation.id,
                   from_status=prev_stage.value, to_status=stage.value)
        for text in diff_state(prev_state, state):
            changes.append(text)
            _event(db, finding, "changed", text, observation_id=observation.id)
        for fact in ("live", "listed"):
            if prev_state.get(fact) is True and state.get(fact) is False:
                kind = "app_status" if fact == "listed" else "changed"
                _event(db, finding, kind, "App no longer listed on Google Play" if fact == "listed"
                       else "Website no longer live", observation_id=observation.id)
        if prev_level != result.level:
            up = LEVEL_ORDER.index(result.level) > LEVEL_ORDER.index(prev_level)
            text = f"Risk {prev_level.value} → {result.level.value} ({result.score})"
            _event(db, finding, "rescored", text, observation_id=observation.id,
                   from_status=prev_level.value, to_status=result.level.value)
            if up:
                changes.append(text)
        if module != finding.module and module in DOMAIN_MODULES and finding.module in DOMAIN_MODULES:
            # stages only move forward: a phishing site that goes offline stays a phishing finding
            if DOMAIN_MODULES.index(module) > DOMAIN_MODULES.index(finding.module):
                _event(db, finding, "stage", f"Stage {finding.module.value} → {module.value}",
                       observation_id=observation.id)
                finding.module = module

    # ---- update the finding (a Finding never goes back to Candidate)
    if stage == FindingStage.finding:
        finding.stage = FindingStage.finding
    finding.title = det.title[:500]
    finding.similarity = det.similarity
    finding.score = result.score
    finding.risk_level = result.level
    finding.suspected_phishing = det.suspected_phishing
    finding.signals = scored
    finding.details = {**det.details, "Risk Level": result.level.value, "Confidence": conf.label}
    if module in CAPPED_MODULES:
        finding.details["Score Cap"] = CAP_REASONS.get(result.cap or "")  # D-29
    if module == ModuleName.social_media:
        finding.details["Criticality Reason"] = SOCIAL_REASONS.get(result.tier or "")
    finding.state = merge_state(prev_state, state)
    finding.source_url = det.source_url
    finding.last_seen = now
    db.flush()
    _store_evidence(db, finding, observation, det.evidence)

    # ---- alert decision (D-36)
    alert = None
    if meets_rule(finding.stage, finding.risk_level, brand.alert_min_level):
        trigger, reason = None, None
        if finding.decision in OPEN_DECISIONS:
            if finding.last_alert_at is None or not prev_met:
                trigger, reason = "first_crossing", f"First reached {finding.risk_level.value} ({finding.score})"
            elif changes:
                trigger, reason = "change", "; ".join(changes)
        elif finding.decision == D.confirmed_threat and changes:
            trigger, reason = "change", "; ".join(changes)
        elif finding.decision in CLOSED_DECISIONS and changes:
            _event(db, finding, "reopened", "Re-opened: " + "; ".join(changes), observation_id=observation.id,
                   from_status=finding.decision.value, to_status=D.new.value)
            finding.decision = D.new
            trigger, reason = "reopen", "; ".join(changes)
        if trigger:
            alert = Alert(finding_id=finding.id, brand_id=brand_id, scan_id=scan_id, observation_id=observation.id,
                          trigger=trigger, reason=reason, score=finding.score, risk_level=finding.risk_level,
                          reasons=result.as_dict().get("rules", {}), created_at=now)
            db.add(alert)
            db.flush()
            finding.last_alert_at = now
            _event(db, finding, "alerted", reason, observation_id=observation.id, alert_id=alert.id)
    db.flush()
    log.info("detection_recorded", finding_id=str(finding.id), module=module.value, created=created,
             stage=finding.stage.value, level=finding.risk_level.value, alerted=bool(alert), entity=det.entity_key)
    return finding, alert, created


def mark_state(db: Session, brand_id: uuid.UUID, module: ModuleName, entity_key: str, facts: dict, note: str,
               kind: str = "changed") -> Finding | None:
    """Record a state change of an entity that was NOT seen in this scan (e.g. a Play listing that disappeared),
    without re-scoring it. Returns the finding, or None when the entity was never a finding."""
    finding = db.scalar(select(Finding).where(Finding.brand_id == brand_id, Finding.module == module,
                                              Finding.entity_key == entity_key))
    if finding is None:
        return None
    finding.state = {**(finding.state or {}), **facts}
    if module == ModuleName.rogue_app and facts.get("listed") is False:
        finding.details = {**finding.details, "App Status": "Removed"}
    _event(db, finding, kind, note)
    db.flush()
    return finding


# ------------------------------------------------------------------------------------------------ analyst workflow
def set_decision(db: Session, finding: Finding, to: FindingDecision, user_id: uuid.UUID | None,
                 note: str | None = None, add_to_allowlist: bool = False) -> FindingEvent:
    note = (note or "").strip() or None
    if to == finding.decision:
        raise InvalidTransition(f"Finding is already {to.value}")
    if to not in ALLOWED_TRANSITIONS[finding.decision]:
        allowed = ", ".join(sorted(s.value for s in ALLOWED_TRANSITIONS[finding.decision]))
        raise InvalidTransition(f"Cannot move from {finding.decision.value} to {to.value}. Allowed: {allowed}")
    if to in NOTE_REQUIRED and not note:
        raise InvalidTransition(f"A note is required when marking a finding {to.value}")
    reopening = to == D.new and finding.decision in CLOSED_DECISIONS
    event = _event(db, finding, "reopened" if reopening else "decision", note, user_id=user_id,
                   from_status=finding.decision.value, to_status=to.value)
    finding.decision, finding.decided_by, finding.decided_at, finding.decision_note = to, user_id, datetime.now(UTC), note
    if to == D.legitimate and add_to_allowlist:
        kind = ALLOW_KIND_FOR.get(finding.module)
        if kind is None:
            raise InvalidTransition(f"{finding.module.value} findings cannot be added to the allowlist")
        value = allowlist_value(finding)
        exists = db.scalar(select(BrandAllow).where(BrandAllow.brand_id == finding.brand_id,
                                                    BrandAllow.kind == kind, BrandAllow.value == value))
        if not exists:
            db.add(BrandAllow(brand_id=finding.brand_id, kind=kind, value=value))
            _event(db, finding, "decision", f"Added to allowlist ({kind.value}: {value})", user_id=user_id)
    db.flush()
    return event


def allowlist_value(finding: Finding) -> str:
    key = finding.entity_key
    if finding.module == ModuleName.rogue_app:
        return key.split(":", 1)[1]  # play:<package>
    if finding.module == ModuleName.apk:
        return str(finding.details.get("Package Name") or key.split(":", 1)[-1])
    if finding.module == ModuleName.social:
        return key.split(":", 1)[-1]  # <platform>:<handle>
    return key


def close_authorized(db: Session, brand_id: uuid.UUID, modules: tuple[ModuleName, ...]) -> int:
    """Close open findings whose entity has since become an official / allowlisted asset (D-45).

    Exact value only (plus subdomains of an official domain), so one allowlisted domain never hides a different
    look-alike. Fake APKs are never closed this way: a repackaged APK keeps the official package name, and only its
    signing certificate tells it apart (D-26). Returns how many findings were closed."""
    modules = tuple(m for m in modules if m != ModuleName.apk)
    if not modules:
        return 0
    allowed: dict[AllowKind, set[str]] = {}
    for row in db.scalars(select(BrandAllow).where(BrandAllow.brand_id == brand_id)):
        value = social_handle(row.value) if row.kind == AllowKind.social_handle else row.value  # 'x.com/h' -> 'h'
        allowed.setdefault(row.kind, set()).add(value.lower())
    closed = 0
    for finding in db.scalars(select(Finding).where(Finding.brand_id == brand_id, Finding.module.in_(modules),
                                                    Finding.decision.in_(OPEN_DECISIONS))):
        kind = ALLOW_KIND_FOR.get(finding.module)
        values = allowed.get(kind, set()) if kind else set()
        value = allowlist_value(finding).lower()
        hit = value in values or (kind == AllowKind.domain and any(value.endswith("." + v) for v in values))
        if not hit:
            continue
        note = f"Closed automatically: {value} is now on the brand's allowlist ({kind.value})"
        _event(db, finding, "decision", note, from_status=finding.decision.value, to_status=D.legitimate.value)
        finding.decision, finding.decided_by = D.legitimate, None
        finding.decided_at, finding.decision_note = datetime.now(UTC), note
        closed += 1
    db.flush()
    return closed
