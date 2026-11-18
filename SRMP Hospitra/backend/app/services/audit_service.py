"""Audit logging. Records are appended inside the caller's transaction so that an audit
entry exists if, and only if, the audited change was committed."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.time import utcnow
from app.models import AuditLog
from app.services.common import PageParams, json_safe, paginate


def _sanitise(details: dict[str, Any] | None) -> dict[str, Any]:
    if not details:
        return {}
    clean: dict[str, Any] = {}
    for key, value in details.items():
        if isinstance(value, dict):
            clean[key] = _sanitise(value)
        elif isinstance(value, list | tuple):
            clean[key] = [_sanitise(v) if isinstance(v, dict) else json_safe(v) for v in value]
        else:
            clean[key] = json_safe(value)
    return clean


def record(
    db: Session,
    *,
    actor: str,
    action: str,
    entity_type: str,
    entity_id: str | None,
    details: dict[str, Any] | None = None,
    timestamp: datetime | None = None,
) -> AuditLog:
    entry = AuditLog(
        actor=actor,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        details=_sanitise(details),
        timestamp=timestamp or utcnow(),
    )
    db.add(entry)
    return entry


def list_audit(
    db: Session,
    page: PageParams,
    *,
    entity_type: str | None = None,
    entity_id: str | None = None,
    action: str | None = None,
    actor: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    exclude_action_prefix: str | None = None,
) -> tuple[list[AuditLog], int]:
    stmt = select(AuditLog)
    if exclude_action_prefix:
        stmt = stmt.where(AuditLog.action.not_like(f"{exclude_action_prefix}%"))
    if entity_type:
        stmt = stmt.where(AuditLog.entity_type == entity_type)
    if entity_id:
        stmt = stmt.where(AuditLog.entity_id == entity_id)
    if action:
        stmt = stmt.where(AuditLog.action.like(f"{action}%"))
    if actor:
        stmt = stmt.where(AuditLog.actor == actor)
    if since:
        stmt = stmt.where(AuditLog.timestamp >= since)
    if until:
        stmt = stmt.where(AuditLog.timestamp <= until)
    stmt = stmt.order_by(AuditLog.timestamp.desc(), AuditLog.id.desc())
    return paginate(db, stmt, page)


def distinct_values(db: Session) -> dict[str, list[str]]:
    return {
        "entity_types": sorted(db.scalars(select(AuditLog.entity_type).distinct())),
        "actions": sorted(db.scalars(select(AuditLog.action).distinct())),
    }
