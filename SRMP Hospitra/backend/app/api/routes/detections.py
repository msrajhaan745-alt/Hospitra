from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter

from app.api.dependencies import DbSession, Pagination
from app.core.constants import Severity
from app.schemas.common import Page
from app.schemas.detection import DetectionDetail, DetectionRead, RuleRead
from app.services import detection_service, investigation_service

router = APIRouter(prefix="/detections", tags=["events & detections"])


@router.get("", response_model=Page[DetectionRead], summary="Rule evaluation results (filter matched=true for alerts)")
def list_detections(
    db: DbSession,
    page: Pagination,
    matched: bool | None = None,
    rule_id: str | None = None,
    severity: Severity | None = None,
    branch_id: str | None = None,
    event_id: str | None = None,
    since: datetime | None = None,
):
    items, total = detection_service.list_detections(
        db, page, matched=matched, rule_id=rule_id, severity=severity, branch_id=branch_id,
        event_id=event_id, since=since,
    )
    return Page(items=items, total=total, limit=page.limit, offset=page.offset)


@router.get("/rules", response_model=list[RuleRead], summary="The deterministic detection rule catalogue (read-only)")
def list_rules():
    return [r.to_read() for r in detection_service.RULES]


@router.get("/{detection_id}", response_model=DetectionDetail, summary="Detection detail with rule and risk context")
def get_detection(detection_id: str, db: DbSession):
    return investigation_service.detection_detail(db, detection_id)
