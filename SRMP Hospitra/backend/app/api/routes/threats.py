from __future__ import annotations

from fastapi import APIRouter, status

from app.api.dependencies import Actor, DbSession, Pagination
from app.core.constants import CatalogueSource
from app.schemas.common import Page
from app.schemas.threat import ThreatCreate, ThreatRead, ThreatUpdate
from app.services import threat_service

router = APIRouter(prefix="/threats", tags=["threats & vulnerabilities"])


@router.get("", response_model=Page[ThreatRead], summary="Threat catalogue with documented vulnerability pairings")
def list_threats(db: DbSession, page: Pagination, search: str | None = None, active: bool | None = None,
                 source_type: CatalogueSource | None = None):
    items, total = threat_service.list_threats(db, page, search=search, active=active, source_type=source_type)
    return Page(items=items, total=total, limit=page.limit, offset=page.offset)


@router.post("", response_model=ThreatRead, status_code=status.HTTP_201_CREATED, summary="Add a threat (default: Proposed)")
def create_threat(payload: ThreatCreate, db: DbSession, actor: Actor):
    return threat_service.create_threat(db, payload, actor)


@router.get("/{threat_id}", response_model=ThreatRead, summary="Threat detail")
def get_threat(threat_id: str, db: DbSession):
    return threat_service.get_threat_read(db, threat_id)


@router.patch("/{threat_id}", response_model=ThreatRead, summary="Update a threat's description or active status")
def update_threat(threat_id: str, payload: ThreatUpdate, db: DbSession, actor: Actor):
    return threat_service.update_threat(db, threat_id, payload, actor)
