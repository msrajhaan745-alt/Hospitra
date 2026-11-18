from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, status
from starlette.concurrency import run_in_threadpool

from app.api.dependencies import Actor, DbSession, Pagination
from app.core.constants import RiskStatus, Severity, Treatment
from app.schemas.common import Page
from app.schemas.control import RiskControlCreate, RiskControlUpdate
from app.schemas.risk import RiskCreate, RiskRead, RiskUpdate
from app.services import risk_service
from app.websocket.manager import manager

router = APIRouter(prefix="/risks", tags=["risks"])

RiskSort = Literal["reference", "risk_score", "severity", "residual_score", "residual_severity", "likelihood",
                   "overall_impact", "status", "treatment", "owner", "updated_at", "asset"]


@router.get("", response_model=Page[RiskRead], summary="Risk register (default: highest score first)")
def list_risks(
    db: DbSession,
    page: Pagination,
    search: str | None = None,
    branch_id: str | None = None,
    asset_id: str | None = None,
    threat_id: str | None = None,
    vulnerability_id: str | None = None,
    severity: Severity | None = None,
    residual_severity: Severity | None = None,
    control_id: str | None = None,
    status: RiskStatus | None = None,
    treatment: Treatment | None = None,
    sort: RiskSort = "risk_score",
    order: Literal["asc", "desc"] = "desc",
):
    items, total = risk_service.list_risks(
        db, page, search=search, branch_id=branch_id, asset_id=asset_id, threat_id=threat_id,
        vulnerability_id=vulnerability_id, severity=severity, residual_severity=residual_severity,
        control_id=control_id, status=status, treatment=treatment, sort=sort, order=order,
    )
    return Page(items=items, total=total, limit=page.limit, offset=page.offset)


@router.post("", response_model=RiskRead, status_code=status.HTTP_201_CREATED,
             summary="Create a risk (score and severity are calculated by the backend)")
async def create_risk(payload: RiskCreate, db: DbSession, actor: Actor):
    risk = await run_in_threadpool(risk_service.create_risk, db, payload, actor)
    await manager.broadcast("risk.changed", {"risk_id": risk.id, "reference": risk.reference, "action": "created"})
    return risk


@router.get("/{risk_id}", response_model=RiskRead, summary="Risk detail with its calculation")
def get_risk(risk_id: str, db: DbSession):
    return risk_service.get_risk(db, risk_id)


@router.patch("/{risk_id}", response_model=RiskRead, summary="Update risk inputs, treatment, owner or status")
async def update_risk(risk_id: str, payload: RiskUpdate, db: DbSession, actor: Actor):
    risk = await run_in_threadpool(risk_service.update_risk, db, risk_id, payload, actor)
    await manager.broadcast("risk.changed", {"risk_id": risk.id, "reference": risk.reference, "action": "updated"})
    return risk


# ---- V2: controls applied to a risk ------------------------------------------------------------

@router.post("/{risk_id}/controls", response_model=RiskRead, status_code=status.HTTP_201_CREATED,
             summary="Link a control to a risk (residual risk is recalculated)")
async def link_control(risk_id: str, payload: RiskControlCreate, db: DbSession, actor: Actor):
    risk = await run_in_threadpool(risk_service.link_control, db, risk_id, payload, actor)
    await manager.broadcast("risk.changed", {"risk_id": risk.id, "reference": risk.reference, "action": "control_linked"})
    return risk


@router.patch("/{risk_id}/controls/{control_id}", response_model=RiskRead,
              summary="Change a linked control's implementation status, effectiveness or notes")
async def update_control_link(risk_id: str, control_id: str, payload: RiskControlUpdate, db: DbSession, actor: Actor):
    risk = await run_in_threadpool(risk_service.update_control_link, db, risk_id, control_id, payload, actor)
    await manager.broadcast("risk.changed", {"risk_id": risk.id, "reference": risk.reference, "action": "control_updated"})
    return risk


@router.delete("/{risk_id}/controls/{control_id}", response_model=RiskRead,
               summary="Unlink a control from a risk (the control itself is kept)")
async def unlink_control(risk_id: str, control_id: str, db: DbSession, actor: Actor):
    risk = await run_in_threadpool(risk_service.unlink_control, db, risk_id, control_id, actor)
    await manager.broadcast("risk.changed", {"risk_id": risk.id, "reference": risk.reference, "action": "control_unlinked"})
    return risk
