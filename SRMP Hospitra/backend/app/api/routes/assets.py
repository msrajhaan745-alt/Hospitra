from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, status

from app.api.dependencies import Actor, DbSession, Pagination
from app.core.constants import AssetStatus, AssetType, Criticality, ZoneType
from app.schemas.asset import AssetCreate, AssetDetail, AssetRead, AssetUpdate
from app.schemas.common import Page
from app.services import asset_service

router = APIRouter(prefix="/assets", tags=["assets"])

AssetSort = Literal[
    "asset_tag", "name", "asset_type", "ip_address", "owner", "criticality",
    "data_classification", "status", "last_seen_at", "branch", "zone",
]


@router.get("", response_model=Page[AssetRead], summary="Search and filter the asset inventory")
def list_assets(
    db: DbSession,
    page: Pagination,
    search: str | None = None,
    branch_id: str | None = None,
    zone_id: str | None = None,
    zone_type: ZoneType | None = None,
    asset_type: AssetType | None = None,
    criticality: Criticality | None = None,
    status: AssetStatus | None = None,
    sort: AssetSort = "asset_tag",
    order: Literal["asc", "desc"] = "asc",
):
    items, total = asset_service.list_assets(
        db, page, search=search, branch_id=branch_id, zone_id=zone_id, zone_type=zone_type,
        asset_type=asset_type, criticality=criticality, status=status, sort=sort, order=order,
    )
    return Page(items=items, total=total, limit=page.limit, offset=page.offset)


@router.post("", response_model=AssetRead, status_code=status.HTTP_201_CREATED, summary="Create an asset")
def create_asset(payload: AssetCreate, db: DbSession, actor: Actor):
    return asset_service.create_asset(db, payload, actor)


@router.get("/{asset_id}", response_model=AssetDetail, summary="Asset detail with risk context")
def get_asset(asset_id: str, db: DbSession):
    return asset_service.get_asset_detail(db, asset_id)


@router.patch("/{asset_id}", response_model=AssetRead, summary="Update an asset")
def update_asset(asset_id: str, payload: AssetUpdate, db: DbSession, actor: Actor):
    return asset_service.update_asset(db, asset_id, payload, actor)
