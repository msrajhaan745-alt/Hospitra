from __future__ import annotations

import re
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.config import settings
from app.core.constants import Permission, Role

USERNAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{2,39}$")


def _username(value: str) -> str:
    value = value.strip().lower()
    if not USERNAME_PATTERN.match(value):
        raise ValueError("Username must be 3–40 characters: lowercase letters, digits, '.', '_' or '-'.")
    return value


def _password(value: str) -> str:
    if len(value) < settings.password_min_length:
        raise ValueError(f"Password must be at least {settings.password_min_length} characters.")
    if len(value) > 128:
        raise ValueError("Password must be at most 128 characters.")
    if value.strip() != value or not value.strip():
        raise ValueError("Password must not start or end with whitespace.")
    return value


def _display(value: str) -> str:
    value = " ".join(value.split())
    if not value:
        raise ValueError("Display name must not be blank.")
    return value


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=40)
    password: str = Field(min_length=1, max_length=128)


class BootstrapRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str
    display_name: str = Field(min_length=1, max_length=80)
    password: str

    @field_validator("username")
    @classmethod
    def _u(cls, v: str) -> str:
        return _username(v)

    @field_validator("password")
    @classmethod
    def _p(cls, v: str) -> str:
        return _password(v)

    @field_validator("display_name")
    @classmethod
    def _d(cls, v: str) -> str:
        return _display(v)


class UserCreate(BootstrapRequest):
    role: Role


class UserUpdate(BaseModel):
    """Admin edits. Username cannot be changed (it is the audit identity)."""

    model_config = ConfigDict(extra="forbid")

    display_name: str | None = Field(default=None, min_length=1, max_length=80)
    role: Role | None = None
    active: bool | None = None
    password: str | None = None

    @field_validator("password")
    @classmethod
    def _p(cls, v: str | None) -> str | None:
        return None if v is None else _password(v)

    @field_validator("display_name")
    @classmethod
    def _d(cls, v: str | None) -> str | None:
        return None if v is None else _display(v)


class PasswordChange(BaseModel):
    model_config = ConfigDict(extra="forbid")

    current_password: str = Field(min_length=1, max_length=128)
    new_password: str

    @field_validator("new_password")
    @classmethod
    def _p(cls, v: str) -> str:
        return _password(v)


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    username: str
    display_name: str
    role: Role
    active: bool
    created_at: datetime
    updated_at: datetime
    last_login_at: datetime | None


class Me(UserRead):
    permissions: list[Permission]


class AuthStatus(BaseModel):
    bootstrap_required: bool
    password_min_length: int
    authenticated: bool = False
    user: Me | None = None
