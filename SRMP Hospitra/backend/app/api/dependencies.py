from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Query, Request
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.constants import ROLE_PERMISSIONS, Permission
from app.db.session import get_db
from app.models import User, UserSession
from app.services import user_service
from app.services.common import PageParams

DbSession = Annotated[Session, Depends(get_db)]


def page_params(
    limit: Annotated[int, Query(ge=1, le=settings.max_page_limit, description="Page size (max 200).")] = settings.default_page_limit,
    offset: Annotated[int, Query(ge=0, description="Number of records to skip.")] = 0,
) -> PageParams:
    return PageParams(limit=limit, offset=offset)


Pagination = Annotated[PageParams, Depends(page_params)]


# ---- authentication (V2) ---------------------------------------------------------------------

def current_session(request: Request, db: DbSession) -> tuple[User, UserSession]:
    resolved = user_service.resolve_session(db, request.cookies.get(settings.session_cookie_name))
    if resolved is None:
        raise user_service.AuthenticationError("Sign in to continue. If no sign-in screen appears, reload the page.")
    return resolved


CurrentSession = Annotated[tuple[User, UserSession], Depends(current_session)]


def current_user(session: CurrentSession) -> User:
    return session[0]


CurrentUser = Annotated[User, Depends(current_user)]


def require(permission: Permission):
    def dependency(user: CurrentUser) -> User:
        if permission not in ROLE_PERMISSIONS[user.role]:
            raise user_service.PermissionDeniedError(
                f"Your role ({user.role.value}) does not permit this action.",
                {"required_permission": permission.value, "role": user.role.value},
            )
        return user

    return dependency


def operate_actor(user: Annotated[User, Depends(require(Permission.OPERATE))]) -> str:
    """Username of a signed-in Analyst or Admin (recorded as the audit actor)."""
    return user.username


def admin_actor(user: Annotated[User, Depends(require(Permission.ADMIN))]) -> str:
    return user.username


Actor = Annotated[str, Depends(operate_actor)]
AdminActor = Annotated[str, Depends(admin_actor)]
AdminUser = Annotated[User, Depends(require(Permission.ADMIN))]
