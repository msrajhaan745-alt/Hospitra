from __future__ import annotations

from fastapi import APIRouter
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.api.dependencies import Actor, DbSession, Pagination
from app.core.constants import IncidentStatus, Severity
from app.schemas.common import Page
from app.schemas.incident import IncidentDetail, IncidentRead, IncidentUpdate
from app.services import incident_service, investigation_service
from app.websocket.manager import manager

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("", response_model=Page[IncidentRead], summary="Incidents (newest first)")
def list_incidents(
    db: DbSession,
    page: Pagination,
    search: str | None = None,
    status: IncidentStatus | None = None,
    severity: Severity | None = None,
    branch_id: str | None = None,
    active_only: bool = False,
):
    items, total = incident_service.list_incidents(
        db, page, search=search, status=status, severity=severity, branch_id=branch_id, active_only=active_only
    )
    return Page(items=items, total=total, limit=page.limit, offset=page.offset)


@router.get("/{incident_id}", response_model=IncidentDetail,
            summary="Incident detail: events, assets, detection, risk context, notes and history")
def get_incident(incident_id: str, db: DbSession):
    return investigation_service.incident_detail(db, incident_id)


def _update(db: Session, incident_id: str, payload: IncidentUpdate, actor: str) -> IncidentDetail:
    try:
        incident_service.update_incident(db, incident_id, payload, actor)
        db.commit()
    except Exception:
        db.rollback()
        raise
    return investigation_service.incident_detail(db, incident_id)


@router.patch("/{incident_id}", response_model=IncidentDetail,
              summary="Advance status (one step), assign, or add an investigation/containment/resolution note")
async def update_incident(incident_id: str, payload: IncidentUpdate, db: DbSession, actor: Actor):
    detail = await run_in_threadpool(_update, db, incident_id, payload, actor)
    await manager.broadcast("incident.updated", {
        "incident_id": detail.id, "incident_number": detail.incident_number, "status": detail.status.value,
    })
    return detail
