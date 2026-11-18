"""Users, authentication and sessions (V2)."""

from __future__ import annotations

import threading
from datetime import datetime, timedelta

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.constants import ROLE_PERMISSIONS, Permission, Role
from app.core.exceptions import AppError, ConflictError, DomainValidationError, NotFoundError
from app.core.security import dummy_verify, hash_password, new_session_token, token_digest, verify_password
from app.core.time import utcnow
from app.models import User, UserSession
from app.schemas.user import BootstrapRequest, Me, UserCreate, UserRead, UserUpdate
from app.services import audit_service
from app.services.common import PageParams, paginate


class AuthenticationError(AppError):
    status_code = 401
    code = "not_authenticated"


class PermissionDeniedError(AppError):
    status_code = 403
    code = "forbidden"


class TooManyAttemptsError(AppError):
    status_code = 429
    code = "too_many_attempts"


# ---- login throttling (in-memory, per username; adequate for a single local process) ---------
_failures: dict[str, list[datetime]] = {}
_lock = threading.Lock()


def _recent_failures(username: str, now: datetime) -> list[datetime]:
    window = timedelta(minutes=settings.login_lockout_minutes)
    attempts = [t for t in _failures.get(username, []) if now - t < window]
    _failures[username] = attempts
    return attempts


def reset_throttle() -> None:
    with _lock:
        _failures.clear()


# ---- helpers ---------------------------------------------------------------------------------

def permissions_for(role: Role) -> list[Permission]:
    return sorted(ROLE_PERMISSIONS[role], key=lambda p: list(Permission).index(p))


def to_me(user: User) -> Me:
    return Me(**UserRead.model_validate(user).model_dump(), permissions=permissions_for(user.role))


def user_count(db: Session) -> int:
    return db.scalar(select(func.count()).select_from(User)) or 0


def _active_admins(db: Session, exclude_id: str | None = None) -> int:
    stmt = select(func.count()).select_from(User).where(User.role == Role.ADMIN, User.active.is_(True))
    if exclude_id:
        stmt = stmt.where(User.id != exclude_id)
    return db.scalar(stmt) or 0


def _get(db: Session, user_id: str) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise NotFoundError(f"User '{user_id}' was not found.")
    return user


def _ensure_unique(db: Session, username: str) -> None:
    if db.scalar(select(User.id).where(User.username == username)):
        raise ConflictError(f"Username '{username}' is already taken.", [{"field": "username", "message": "Usernames must be unique."}])


def revoke_user_sessions(db: Session, user_id: str, *, except_session_id: str | None = None) -> None:
    stmt = update(UserSession).where(UserSession.user_id == user_id, UserSession.revoked_at.is_(None))
    if except_session_id:
        stmt = stmt.where(UserSession.id != except_session_id)
    db.execute(stmt.values(revoked_at=utcnow()))


# ---- bootstrap and user management --------------------------------------------------------------

def bootstrap_admin(db: Session, payload: BootstrapRequest) -> User:
    """Create the first Admin. Allowed only while no user exists."""
    if user_count(db):
        raise ConflictError("Setup has already been completed. Sign in with an existing account.")
    user = User(username=payload.username, display_name=payload.display_name, role=Role.ADMIN,
                password_hash=hash_password(payload.password), active=True)
    db.add(user)
    db.flush()
    audit_service.record(db, actor=user.username, action="user.bootstrap", entity_type="user", entity_id=user.id,
                         details={"username": user.username, "role": user.role})
    db.commit()
    return user


def create_user(db: Session, payload: UserCreate, actor: str) -> UserRead:
    _ensure_unique(db, payload.username)
    user = User(username=payload.username, display_name=payload.display_name, role=payload.role,
                password_hash=hash_password(payload.password), active=True)
    db.add(user)
    db.flush()
    audit_service.record(db, actor=actor, action="user.created", entity_type="user", entity_id=user.id,
                         details={"username": user.username, "role": user.role})
    db.commit()
    return UserRead.model_validate(user)


def list_users(db: Session, page: PageParams) -> tuple[list[UserRead], int]:
    items, total = paginate(db, select(User).order_by(User.username), page)
    return [UserRead.model_validate(u) for u in items], total


def update_user(db: Session, user_id: str, payload: UserUpdate, actor_user: User) -> UserRead:
    user = _get(db, user_id)
    changes = payload.model_dump(exclude_unset=True)
    for field, value in changes.items():
        if value is None:
            raise DomainValidationError("Field cannot be null.", [{"field": field, "message": "A value is required."}])

    removes_admin = (
        user.role == Role.ADMIN and user.active
        and (changes.get("role", Role.ADMIN) != Role.ADMIN or changes.get("active", True) is False)
    )
    if removes_admin and _active_admins(db, exclude_id=user.id) == 0:
        raise ConflictError("At least one active Admin account must remain.")
    if user.id == actor_user.id and changes.get("active") is False:
        raise ConflictError("You cannot deactivate your own account.")

    details: dict = {"username": user.username, "changes": {}}
    for field in ("display_name", "role", "active"):
        if field in changes and getattr(user, field) != changes[field]:
            details["changes"][field] = {"from": getattr(user, field), "to": changes[field]}
            setattr(user, field, changes[field])
    revoke = False
    if "password" in changes:
        user.password_hash = hash_password(changes["password"])
        details["changes"]["password"] = "reset"
        revoke = True
    if "role" in details["changes"] or details["changes"].get("active", {}).get("to") is False:
        revoke = True
    if not details["changes"]:
        return UserRead.model_validate(user)
    if revoke:
        revoke_user_sessions(db, user.id)
        details["sessions_revoked"] = True
    audit_service.record(db, actor=actor_user.username, action="user.updated", entity_type="user", entity_id=user.id,
                         details=details)
    db.commit()
    return UserRead.model_validate(user)


def change_own_password(db: Session, user: User, session_id: str, current: str, new: str) -> None:
    if not verify_password(current, user.password_hash):
        raise DomainValidationError("Current password is incorrect.",
                                    [{"field": "current_password", "message": "Incorrect password."}])
    if current == new:
        raise DomainValidationError("New password must differ from the current one.",
                                    [{"field": "new_password", "message": "Choose a different password."}])
    user.password_hash = hash_password(new)
    revoke_user_sessions(db, user.id, except_session_id=session_id)
    audit_service.record(db, actor=user.username, action="user.password_changed", entity_type="user",
                         entity_id=user.id, details={"username": user.username, "other_sessions_revoked": True})
    db.commit()


# ---- login / sessions ----------------------------------------------------------------------------

def authenticate(db: Session, username: str, password: str) -> tuple[User, str]:
    """Verify credentials and open a session. Returns (user, raw cookie token)."""
    username = username.strip().lower()
    now = utcnow()
    with _lock:
        if len(_recent_failures(username, now)) >= settings.login_max_failures:
            raise TooManyAttemptsError(
                f"Too many failed sign-in attempts. Try again in {settings.login_lockout_minutes} minutes."
            )
    user = db.scalar(select(User).where(User.username == username))
    ok = False
    if user is None:
        dummy_verify(password)  # equalise timing for unknown usernames
    else:
        ok = verify_password(password, user.password_hash) and user.active
    if not ok:
        with _lock:
            _failures.setdefault(username, []).append(now)
        audit_service.record(db, actor=username[:60] or "unknown", action="auth.login_failed", entity_type="user",
                             entity_id=user.id if user else None, details={"username": username})
        db.commit()
        raise AuthenticationError("Invalid username or password.")
    with _lock:
        _failures.pop(username, None)

    token = new_session_token()
    session = UserSession(token_hash=token_digest(token), user_id=user.id, created_at=now,
                          expires_at=now + timedelta(hours=settings.session_hours))
    db.add(session)
    user.last_login_at = now
    audit_service.record(db, actor=user.username, action="auth.login", entity_type="user", entity_id=user.id,
                         details={"username": user.username})
    db.commit()
    return user, token


def resolve_session(db: Session, token: str | None) -> tuple[User, UserSession] | None:
    if not token:
        return None
    session = db.scalar(select(UserSession).where(UserSession.token_hash == token_digest(token)))
    if session is None or session.revoked_at is not None or session.expires_at <= utcnow():
        return None
    user = db.get(User, session.user_id)
    if user is None or not user.active:
        return None
    return user, session


def logout(db: Session, user: User, session: UserSession) -> None:
    session.revoked_at = utcnow()
    audit_service.record(db, actor=user.username, action="auth.logout", entity_type="user", entity_id=user.id,
                         details={"username": user.username})
    db.commit()
