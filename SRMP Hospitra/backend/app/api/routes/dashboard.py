from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query

from app.api.dependencies import DbSession
from app.services import dashboard_service

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary", summary="Command Centre summary (all values computed from persisted data)")
def dashboard_summary(db: DbSession, branch_id: str | None = None) -> dict:
    return dashboard_service.summary(db, branch_id)


@router.get("/event-trends", summary="Security events per UTC day, by severity")
def event_trends(db: DbSession, days: Annotated[int, Query(ge=1, le=30)] = 7, branch_id: str | None = None) -> dict:
    return dashboard_service.event_trends(db, days, branch_id)


@router.get("/risk-distribution", summary="Risk counts by severity, by branch and as a likelihood × impact matrix")
def risk_distribution(db: DbSession, branch_id: str | None = None) -> dict:
    return dashboard_service.risk_distribution(db, branch_id)
