"""Shared service helpers: pagination and change tracking."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from app.core.config import settings


@dataclass(frozen=True)
class PageParams:
    limit: int = settings.default_page_limit
    offset: int = 0


def paginate(db: Session, stmt: Select, page: PageParams) -> tuple[list[Any], int]:
    total = db.scalar(select(func.count()).select_from(stmt.order_by(None).subquery())) or 0
    items = list(db.scalars(stmt.limit(page.limit).offset(page.offset)).unique())
    return items, total


def json_safe(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def apply_changes(obj: Any, changes: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Set attributes and return a ``{field: {"from": old, "to": new}}`` diff of real changes."""
    diff: dict[str, dict[str, Any]] = {}
    for field, new_value in changes.items():
        old_value = getattr(obj, field)
        if old_value != new_value:
            diff[field] = {"from": json_safe(old_value), "to": json_safe(new_value)}
            setattr(obj, field, new_value)
    return diff
