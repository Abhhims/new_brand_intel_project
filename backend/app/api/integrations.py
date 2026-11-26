"""Integration status: which tools are configured and how each last ran (RDA-03, D-31). Never returns secrets."""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.integrations import status_list
from app.core.security import current_user
from app.db.models import User
from app.db.session import get_db
from app.schemas.api import IntegrationOut

router = APIRouter(prefix="/integrations", tags=["integrations"])


@router.get("", response_model=list[IntegrationOut])
def list_integrations(_: User = Depends(current_user), db: Session = Depends(get_db)):
    return status_list(db)
