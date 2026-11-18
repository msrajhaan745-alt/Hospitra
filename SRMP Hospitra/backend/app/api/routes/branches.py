from __future__ import annotations

from fastapi import APIRouter

from app.api.dependencies import DbSession
from app.schemas.branch import BranchDetail, BranchRead
from app.services import network_service

router = APIRouter(prefix="/branches", tags=["network"])


@router.get("", response_model=list[BranchRead], summary="List the hospital branches")
def list_branches(db: DbSession):
    return network_service.list_branches(db)


@router.get("/{branch_id}", response_model=BranchDetail, summary="Branch detail with its zones")
def get_branch(branch_id: str, db: DbSession):
    return network_service.get_branch(db, branch_id)
