from __future__ import annotations

from datetime import datetime

from app.schemas.common import ORMModel
from app.schemas.network_zone import ZoneRead


class BranchRead(ORMModel):
    id: str
    code: str
    name: str
    role: str
    site_id: int
    location_label: str
    active: bool
    created_at: datetime
    zone_count: int = 0
    asset_count: int = 0


class BranchDetail(BranchRead):
    zones: list[ZoneRead] = []
