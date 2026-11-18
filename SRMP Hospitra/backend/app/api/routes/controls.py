from __future__ import annotations

from fastapi import APIRouter, status

from app.api.dependencies import Actor, DbSession, Pagination
from app.core.constants import ControlType
from app.schemas.common import Page
from app.schemas.control import ControlCreate, ControlRead, ControlUpdate
from app.services import control_service

router = APIRouter(prefix="/controls", tags=["security controls"])


@router.get("", response_model=Page[ControlRead], summary="Security control library")
def list_controls(db: DbSession, page: Pagination, search: str | None = None, control_type: ControlType | None = None,
                  category: str | None = None, active: bool | None = None):
    items, total = control_service.list_controls(db, page, search=search, control_type=control_type,
                                                 category=category, active=active)
    return Page(items=items, total=total, limit=page.limit, offset=page.offset)


@router.get("/categories", response_model=list[str], summary="Distinct control categories")
def list_categories(db: DbSession):
    return control_service.categories(db)


@router.post("", response_model=ControlRead, status_code=status.HTTP_201_CREATED, summary="Add a control (Analyst/Admin)")
def create_control(payload: ControlCreate, db: DbSession, actor: Actor):
    return control_service.create_control(db, payload, actor)


@router.get("/{control_id}", response_model=ControlRead, summary="Control detail")
def get_control(control_id: str, db: DbSession):
    return control_service.get_control(db, control_id)


@router.patch("/{control_id}", response_model=ControlRead,
              summary="Update a control (type/active changes recalculate residual risk)")
def update_control(control_id: str, payload: ControlUpdate, db: DbSession, actor: Actor):
    return control_service.update_control(db, control_id, payload, actor)
