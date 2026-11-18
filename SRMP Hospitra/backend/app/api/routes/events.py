from __future__ import annotations

from datetime import datetime
from typing import Literal

from fastapi import APIRouter

from app.api.dependencies import DbSession, Pagination
from app.core.constants import EventType, Severity
from app.schemas.common import Page
from app.schemas.security_event import EventDetail, EventRead
from app.services import event_service, investigation_service

router = APIRouter(prefix="/events", tags=["events & detections"])


@router.get("", response_model=Page[EventRead], summary="Security events (newest first)")
def list_events(
    db: DbSession,
    page: Pagination,
    search: str | None = None,
    severity: Severity | None = None,
    event_type: EventType | None = None,
    branch_id: str | None = None,
    scenario_id: str | None = None,
    asset_id: str | None = None,
    detection_status: Literal["detected", "no_match", "not_evaluated"] | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    order: Literal["asc", "desc"] = "desc",
):
    items, total = event_service.list_events(
        db, page, search=search, severity=severity, event_type=event_type, branch_id=branch_id,
        scenario_id=scenario_id, asset_id=asset_id, detection_status_filter=detection_status,
        since=since, until=until, order=order,
    )
    return Page(items=items, total=total, limit=page.limit, offset=page.offset)


@router.get("/{event_id}", response_model=EventDetail,
            summary="Event detail: rule evaluations, explanation, evidence, risk context and incident")
def get_event(event_id: str, db: DbSession):
    return investigation_service.event_detail(db, event_id)
