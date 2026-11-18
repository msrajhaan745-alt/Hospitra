from __future__ import annotations

from fastapi import APIRouter, status

from app.api.dependencies import AdminActor, AdminUser, DbSession, Pagination
from app.schemas.common import Page
from app.schemas.user import UserCreate, UserRead, UserUpdate
from app.services import user_service

router = APIRouter(prefix="/users", tags=["users (Admin)"])


@router.get("", response_model=Page[UserRead], summary="List user accounts (Admin)")
def list_users(db: DbSession, page: Pagination, _: AdminActor):
    items, total = user_service.list_users(db, page)
    return Page(items=items, total=total, limit=page.limit, offset=page.offset)


@router.post("", response_model=UserRead, status_code=status.HTTP_201_CREATED, summary="Create a user (Admin)")
def create_user(payload: UserCreate, db: DbSession, actor: AdminActor):
    return user_service.create_user(db, payload, actor)


@router.patch("/{user_id}", response_model=UserRead,
              summary="Change display name, role, active flag or reset password (Admin)")
def update_user(user_id: str, payload: UserUpdate, db: DbSession, admin: AdminUser):
    return user_service.update_user(db, user_id, payload, admin)
