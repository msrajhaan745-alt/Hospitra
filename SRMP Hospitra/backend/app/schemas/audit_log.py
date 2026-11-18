from __future__ import annotations

from datetime import datetime
from typing import Any

from app.schemas.common import ORMModel


class AuditLogRead(ORMModel):
    id: str
    actor: str
    action: str
    entity_type: str
    entity_id: str | None
    details: dict[str, Any]
    timestamp: datetime
