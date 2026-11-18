from __future__ import annotations

from app.core.constants import ZoneType
from app.schemas.common import ORMModel


class ZoneRead(ORMModel):
    id: str
    branch_id: str
    branch_code: str
    name: str
    code: str
    zone_type: ZoneType
    vlan_id: int
    subnet_cidr: str
    description: str
    asset_count: int = 0


class ZoneRef(ORMModel):
    id: str
    name: str
    code: str
    zone_type: ZoneType
    vlan_id: int
    branch_code: str
