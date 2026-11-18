from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter

from app.api.dependencies import DbSession, Pagination
from app.schemas.audit_log import AuditLogRead
from app.schemas.common import Page
from app.services import audit_service

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("", response_model=Page[AuditLogRead], summary="Audit history (newest first)")
def list_audit(
    db: DbSession,
    page: Pagination,
    entity_type: str | None = None,
    entity_id: str | None = None,
    action: str | None = None,
    actor: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
):
    items, total = audit_service.list_audit(
        db, page, entity_type=entity_type, entity_id=entity_id, action=action,
        actor=actor, since=since, until=until,
    )
    return Page(items=[AuditLogRead.model_validate(i) for i in items], total=total,
                limit=page.limit, offset=page.offset)


@router.get("/facets", summary="Distinct entity types and actions present in the audit log")
def audit_facets(db: DbSession) -> dict[str, list[str]]:
    return audit_service.distinct_values(db)
