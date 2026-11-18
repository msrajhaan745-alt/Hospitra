from __future__ import annotations

from fastapi import APIRouter, status

from app.api.dependencies import Actor, DbSession, Pagination
from app.core.constants import CatalogueSource
from app.schemas.common import Page
from app.schemas.vulnerability import VulnerabilityCreate, VulnerabilityRead, VulnerabilityUpdate
from app.services import threat_service

router = APIRouter(prefix="/vulnerabilities", tags=["threats & vulnerabilities"])


@router.get("", response_model=Page[VulnerabilityRead], summary="Vulnerability catalogue with documented threat pairings")
def list_vulnerabilities(db: DbSession, page: Pagination, search: str | None = None, active: bool | None = None,
                         source_type: CatalogueSource | None = None):
    items, total = threat_service.list_vulnerabilities(db, page, search=search, active=active, source_type=source_type)
    return Page(items=items, total=total, limit=page.limit, offset=page.offset)


@router.post("", response_model=VulnerabilityRead, status_code=status.HTTP_201_CREATED,
             summary="Add a vulnerability (default: Proposed)")
def create_vulnerability(payload: VulnerabilityCreate, db: DbSession, actor: Actor):
    return threat_service.create_vulnerability(db, payload, actor)


@router.get("/{vulnerability_id}", response_model=VulnerabilityRead, summary="Vulnerability detail")
def get_vulnerability(vulnerability_id: str, db: DbSession):
    return threat_service.get_vulnerability_read(db, vulnerability_id)


@router.patch("/{vulnerability_id}", response_model=VulnerabilityRead,
              summary="Update a vulnerability's description or active status")
def update_vulnerability(vulnerability_id: str, payload: VulnerabilityUpdate, db: DbSession, actor: Actor):
    return threat_service.update_vulnerability(db, vulnerability_id, payload, actor)
