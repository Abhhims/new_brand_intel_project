"""Related findings and campaigns (SP4, D-49, RDA-14/16): links come only from identifiers shared in evidence."""

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import correlation
from app.core.security import current_user
from app.db.models import Brand, Finding, User
from app.db.session import get_db
from app.schemas.api import CampaignFindingOut, CampaignOut, RelatedFindingOut

router = APIRouter(tags=["correlation"])
MAX_CAMPAIGN_FINDINGS = 200


@router.get("/findings/{finding_id}/related", response_model=list[RelatedFindingOut])
def related_findings(finding_id: uuid.UUID, _: User = Depends(current_user), db: Session = Depends(get_db)):
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(404, "Finding not found")
    links = correlation.related(db, finding)
    others = {f.id: f for f in db.scalars(select(Finding).where(Finding.id.in_({x.finding_id for x in links})))}
    out = [RelatedFindingOut(finding_id=o.id, module=o.module, entity_key=o.entity_key, title=o.title,
                             risk_level=o.risk_level, score=o.score, decision=o.decision, kind=x.kind,
                             label=x.label, value=x.value, strong=x.strong, seen_in=x.source)
           for x in links if (o := others.get(x.finding_id))]
    return sorted(out, key=lambda r: (not r.strong, -r.score))


@router.get("/brands/{brand_id}/campaigns", response_model=list[CampaignOut])
def brand_campaigns(brand_id: uuid.UUID, _: User = Depends(current_user), db: Session = Depends(get_db)):
    if db.get(Brand, brand_id) is None:
        raise HTTPException(404, "Brand not found")
    groups = correlation.campaigns(db, brand_id)
    ids = {uuid.UUID(i) for g in groups for i in g["finding_ids"][:MAX_CAMPAIGN_FINDINGS]}
    rows = {f.id: f for f in db.scalars(select(Finding).where(Finding.id.in_(ids)))} if ids else {}
    return [CampaignOut(size=g["size"], shared=g["shared"], findings=sorted(
        (CampaignFindingOut(finding_id=f.id, module=f.module, entity_key=f.entity_key, title=f.title,
                            risk_level=f.risk_level, score=f.score, decision=f.decision)
         for i in g["finding_ids"][:MAX_CAMPAIGN_FINDINGS] if (f := rows.get(uuid.UUID(i)))),
        key=lambda c: -c.score)) for g in groups]
