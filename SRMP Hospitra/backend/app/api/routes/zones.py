from __future__ import annotations

from fastapi import APIRouter

from app.api.dependencies import DbSession
from app.core.constants import ZoneType
from app.schemas.network_zone import ZoneRead
from app.services import network_service

router = APIRouter(prefix="/zones", tags=["network"])


@router.get("", response_model=list[ZoneRead], summary="List security zones (24 = 3 branches × 8)")
def list_zones(db: DbSession, branch_id: str | None = None, zone_type: ZoneType | None = None):
    return network_service.list_zones(db, branch_id=branch_id, zone_type=zone_type)


@router.get("/{zone_id}", response_model=ZoneRead, summary="Zone detail")
def get_zone(zone_id: str, db: DbSession):
    return network_service.get_zone(db, zone_id)
