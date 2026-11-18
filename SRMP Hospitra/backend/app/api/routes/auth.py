from __future__ import annotations

from fastapi import APIRouter, Request, Response, status

from app.api.dependencies import CurrentSession, CurrentUser, DbSession
from app.core.config import settings
from app.schemas.user import AuthStatus, BootstrapRequest, LoginRequest, Me, PasswordChange
from app.services import user_service

router = APIRouter(prefix="/auth", tags=["authentication"])


def _set_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        settings.session_cookie_name, token,
        max_age=settings.session_hours * 3600, httponly=True, samesite="strict",
        secure=settings.cookie_secure, path="/",
    )


@router.get("/status", response_model=AuthStatus,
            summary="Public: whether first-run setup is required and whether this browser is signed in")
def auth_status(request: Request, db: DbSession):
    resolved = user_service.resolve_session(db, request.cookies.get(settings.session_cookie_name))
    return AuthStatus(
        bootstrap_required=user_service.user_count(db) == 0,
        password_min_length=settings.password_min_length,
        authenticated=resolved is not None,
        user=user_service.to_me(resolved[0]) if resolved else None,
    )


@router.post("/bootstrap", response_model=Me, status_code=status.HTTP_201_CREATED,
             summary="First-run only: create the first Admin and sign in")
def bootstrap(payload: BootstrapRequest, response: Response, db: DbSession):
    user_service.bootstrap_admin(db, payload)
    user, token = user_service.authenticate(db, payload.username, payload.password)
    _set_cookie(response, token)
    return user_service.to_me(user)


@router.post("/login", response_model=Me, summary="Sign in (sets an HttpOnly session cookie)")
def login(payload: LoginRequest, response: Response, db: DbSession):
    user, token = user_service.authenticate(db, payload.username, payload.password)
    _set_cookie(response, token)
    return user_service.to_me(user)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT, summary="Sign out (revokes this session)")
def logout(session: CurrentSession, db: DbSession):
    user, sess = session
    user_service.logout(db, user, sess)
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    response.delete_cookie(settings.session_cookie_name, path="/")
    return response


@router.get("/me", response_model=Me, summary="The signed-in user and their permissions")
def me(user: CurrentUser):
    return user_service.to_me(user)


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT,
             summary="Change your own password (other sessions are revoked)")
def change_password(payload: PasswordChange, session: CurrentSession, db: DbSession):
    user, sess = session
    user_service.change_own_password(db, user, sess.id, payload.current_password, payload.new_password)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
