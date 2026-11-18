"""Branches and network zones (read-only in V1: the network model is fixed seed data)."""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.core.exceptions import NotFoundError
from app.models import Asset, Branch, NetworkZone
from app.schemas.branch import BranchDetail, BranchRead
from app.schemas.network_zone import ZoneRead


def _asset_counts_by_zone(db: Session) -> dict[str, int]:
    return dict(db.execute(select(Asset.zone_id, func.count()).group_by(Asset.zone_id)).all())


def _asset_counts_by_branch(db: Session) -> dict[str, int]:
    return dict(db.execute(select(Asset.branch_id, func.count()).group_by(Asset.branch_id)).all())


def zone_to_read(zone: NetworkZone, asset_count: int = 0) -> ZoneRead:
    return ZoneRead(
        id=zone.id,
        branch_id=zone.branch_id,
        branch_code=zone.branch.code,
        name=zone.name,
        code=zone.code,
        zone_type=zone.zone_type,
        vlan_id=zone.vlan_id,
        subnet_cidr=zone.subnet_cidr,
        description=zone.description,
        asset_count=asset_count,
    )


def list_branches(db: Session) -> list[BranchRead]:
    branches = db.scalars(select(Branch).options(selectinload(Branch.zones)).order_by(Branch.code)).all()
    counts = _asset_counts_by_branch(db)
    return [
        BranchRead.model_validate(b).model_copy(
            update={"zone_count": len(b.zones), "asset_count": counts.get(b.id, 0)}
        )
        for b in branches
    ]


def get_branch(db: Session, branch_id: str) -> BranchDetail:
    branch = db.get(Branch, branch_id)
    if branch is None:
        raise NotFoundError(f"Branch '{branch_id}' was not found.")
    zone_counts = _asset_counts_by_zone(db)
    zones = [zone_to_read(z, zone_counts.get(z.id, 0)) for z in branch.zones]
    base = BranchRead.model_validate(branch).model_dump()
    base.update(zone_count=len(zones), asset_count=sum(z.asset_count for z in zones), zones=zones)
    return BranchDetail(**base)


def list_zones(db: Session, *, branch_id: str | None = None, zone_type: str | None = None) -> list[ZoneRead]:
    stmt = select(NetworkZone).join(Branch).options(selectinload(NetworkZone.branch))
    if branch_id:
        stmt = stmt.where(NetworkZone.branch_id == branch_id)
    if zone_type:
        stmt = stmt.where(NetworkZone.zone_type == zone_type)
    stmt = stmt.order_by(Branch.code, NetworkZone.vlan_id)
    counts = _asset_counts_by_zone(db)
    return [zone_to_read(z, counts.get(z.id, 0)) for z in db.scalars(stmt)]


def get_zone(db: Session, zone_id: str) -> ZoneRead:
    zone = db.get(NetworkZone, zone_id)
    if zone is None:
        raise NotFoundError(f"Zone '{zone_id}' was not found.")
    count = db.scalar(select(func.count()).select_from(Asset).where(Asset.zone_id == zone_id)) or 0
    return zone_to_read(zone, count)
