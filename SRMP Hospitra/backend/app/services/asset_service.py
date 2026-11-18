"""Asset inventory: validated create/update, filtering and detail views.

Deleting assets is intentionally not supported: assets are referenced by risks, events,
detections, incidents and audit history, and removing them would break that history.
"""

from __future__ import annotations

import ipaddress

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, joinedload

from app.core.constants import ACTIVE_INCIDENT_STATUSES
from app.core.exceptions import ConflictError, DomainValidationError, NotFoundError
from app.models import Asset, Branch, Incident, NetworkZone, Risk, SecurityEvent, incident_assets
from app.schemas.asset import AssetCreate, AssetDetail, AssetRead, AssetRiskSummary, AssetUpdate
from app.services import audit_service
from app.services.common import PageParams, apply_changes, paginate

SORTABLE_COLUMNS = {
    "asset_tag": Asset.asset_tag,
    "name": Asset.name,
    "asset_type": Asset.asset_type,
    "ip_address": Asset.ip_address,
    "owner": Asset.owner,
    "criticality": Asset.criticality,
    "data_classification": Asset.data_classification,
    "status": Asset.status,
    "last_seen_at": Asset.last_seen_at,
    "branch": Branch.code,
    "zone": NetworkZone.vlan_id,
}


def asset_to_read(asset: Asset) -> AssetRead:
    return AssetRead(
        id=asset.id,
        asset_tag=asset.asset_tag,
        name=asset.name,
        asset_type=asset.asset_type,
        ip_address=asset.ip_address,
        operating_system=asset.operating_system,
        criticality=asset.criticality,
        data_classification=asset.data_classification,
        confidentiality=asset.confidentiality,
        integrity=asset.integrity,
        availability=asset.availability,
        status=asset.status,
        owner=asset.owner,
        branch_id=asset.branch_id,
        branch_code=asset.branch.code,
        branch_name=asset.branch.name,
        zone_id=asset.zone_id,
        zone_name=asset.zone.name,
        zone_code=asset.zone.code,
        zone_type=asset.zone.zone_type.value,
        vlan_id=asset.zone.vlan_id,
        last_seen_at=asset.last_seen_at,
        created_at=asset.created_at,
        updated_at=asset.updated_at,
    )


def _get(db: Session, asset_id: str) -> Asset:
    asset = db.get(Asset, asset_id, options=[joinedload(Asset.branch), joinedload(Asset.zone)])
    if asset is None:
        raise NotFoundError(f"Asset '{asset_id}' was not found.")
    return asset


def _validate_references(db: Session, branch_id: str, zone_id: str, ip_address: str) -> None:
    branch = db.get(Branch, branch_id)
    if branch is None:
        raise DomainValidationError(
            "Referenced branch does not exist.", [{"field": "branch_id", "message": "Unknown branch."}]
        )
    zone = db.get(NetworkZone, zone_id)
    if zone is None:
        raise DomainValidationError(
            "Referenced zone does not exist.", [{"field": "zone_id", "message": "Unknown zone."}]
        )
    if zone.branch_id != branch.id:
        raise DomainValidationError(
            "Zone does not belong to the selected branch.",
            [{"field": "zone_id", "message": f"Zone '{zone.name}' belongs to a different branch."}],
        )
    if ipaddress.IPv4Address(ip_address) not in ipaddress.IPv4Network(zone.subnet_cidr):
        raise DomainValidationError(
            "IP address is outside the zone subnet.",
            [{"field": "ip_address", "message": f"Must be within {zone.subnet_cidr} for zone '{zone.name}'."}],
        )


def _ensure_unique_tag(db: Session, asset_tag: str, exclude_id: str | None = None) -> None:
    stmt = select(Asset.id).where(Asset.asset_tag == asset_tag)
    if exclude_id:
        stmt = stmt.where(Asset.id != exclude_id)
    if db.scalar(stmt) is not None:
        raise ConflictError(
            f"Asset tag '{asset_tag}' is already in use.",
            [{"field": "asset_tag", "message": "Asset tags must be unique."}],
        )


def list_assets(
    db: Session,
    page: PageParams,
    *,
    search: str | None = None,
    branch_id: str | None = None,
    zone_id: str | None = None,
    zone_type: str | None = None,
    asset_type: str | None = None,
    criticality: str | None = None,
    status: str | None = None,
    sort: str = "asset_tag",
    order: str = "asc",
) -> tuple[list[AssetRead], int]:
    stmt = (
        select(Asset)
        .join(Branch, Asset.branch_id == Branch.id)
        .join(NetworkZone, Asset.zone_id == NetworkZone.id)
        .options(joinedload(Asset.branch), joinedload(Asset.zone))
    )
    if search:
        term = f"%{search.strip()}%"
        stmt = stmt.where(or_(Asset.name.ilike(term), Asset.asset_tag.ilike(term), Asset.ip_address.ilike(term)))
    if branch_id:
        stmt = stmt.where(Asset.branch_id == branch_id)
    if zone_id:
        stmt = stmt.where(Asset.zone_id == zone_id)
    if zone_type:
        stmt = stmt.where(NetworkZone.zone_type == zone_type)
    if asset_type:
        stmt = stmt.where(Asset.asset_type == asset_type)
    if criticality:
        stmt = stmt.where(Asset.criticality == criticality)
    if status:
        stmt = stmt.where(Asset.status == status)

    column = SORTABLE_COLUMNS.get(sort, Asset.asset_tag)
    stmt = stmt.order_by(column.desc() if order == "desc" else column.asc(), Asset.asset_tag.asc())
    items, total = paginate(db, stmt, page)
    return [asset_to_read(a) for a in items], total


def get_asset_detail(db: Session, asset_id: str) -> AssetDetail:
    asset = _get(db, asset_id)
    risks = db.scalars(
        select(Risk)
        .where(Risk.asset_id == asset_id)
        .options(joinedload(Risk.threat), joinedload(Risk.vulnerability))
        .order_by(Risk.risk_score.desc())
    ).all()
    open_incidents = db.scalar(
        select(func.count())
        .select_from(Incident)
        .join(incident_assets, incident_assets.c.incident_id == Incident.id)
        .where(incident_assets.c.asset_id == asset_id, Incident.status.in_(list(ACTIVE_INCIDENT_STATUSES)))
    ) or 0
    events = db.scalar(
        select(func.count())
        .select_from(SecurityEvent)
        .where(or_(SecurityEvent.source_asset_id == asset_id, SecurityEvent.destination_asset_id == asset_id))
    ) or 0
    data = asset_to_read(asset).model_dump()
    data["risks"] = [
        AssetRiskSummary(
            id=r.id,
            reference=r.reference,
            threat_code=r.threat.code,
            threat_name=r.threat.name,
            vulnerability_code=r.vulnerability.code,
            vulnerability_name=r.vulnerability.name,
            risk_score=r.risk_score,
            severity=r.severity,
            status=r.status.value,
        )
        for r in risks
    ]
    data["open_incident_count"] = open_incidents
    data["event_count"] = events
    return AssetDetail(**data)


def create_asset(db: Session, payload: AssetCreate, actor: str) -> AssetRead:
    _ensure_unique_tag(db, payload.asset_tag)
    _validate_references(db, payload.branch_id, payload.zone_id, payload.ip_address)
    asset = Asset(**payload.model_dump())
    db.add(asset)
    db.flush()
    audit_service.record(
        db,
        actor=actor,
        action="asset.created",
        entity_type="asset",
        entity_id=asset.id,
        details={"asset_tag": asset.asset_tag, "name": asset.name, "zone_id": asset.zone_id},
    )
    db.commit()
    return asset_to_read(_get(db, asset.id))


def update_asset(db: Session, asset_id: str, payload: AssetUpdate, actor: str) -> AssetRead:
    asset = _get(db, asset_id)
    changes = payload.model_dump(exclude_unset=True)
    # Reject explicit nulls for required fields (last_seen_at may be cleared).
    for field, value in changes.items():
        if value is None and field != "last_seen_at":
            raise DomainValidationError(
                "Field cannot be null.", [{"field": field, "message": "A value is required."}]
            )
    if "asset_tag" in changes:
        _ensure_unique_tag(db, changes["asset_tag"], exclude_id=asset.id)
    branch_id = changes.get("branch_id", asset.branch_id)
    zone_id = changes.get("zone_id", asset.zone_id)
    ip_address = changes.get("ip_address", asset.ip_address)
    if {"branch_id", "zone_id", "ip_address"} & changes.keys():
        _validate_references(db, branch_id, zone_id, ip_address)

    diff = apply_changes(asset, changes)
    if diff:
        audit_service.record(
            db,
            actor=actor,
            action="asset.updated",
            entity_type="asset",
            entity_id=asset.id,
            details={"asset_tag": asset.asset_tag, "changes": diff},
        )
        db.commit()
    db.expire(asset)
    return asset_to_read(_get(db, asset.id))
