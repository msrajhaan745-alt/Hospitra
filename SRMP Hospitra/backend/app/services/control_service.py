"""Security control library (V2). Controls are illustrative; deletion is not supported (deactivate instead)."""

from __future__ import annotations

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, selectinload

from app.core.constants import CONTROL_AXIS, ImplementationStatus
from app.core.exceptions import ConflictError, DomainValidationError, NotFoundError
from app.models import RiskControl, SecurityControl, Vulnerability
from app.schemas.control import ControlCreate, ControlRead, ControlUpdate, VulnerabilityRef
from app.services import audit_service, risk_service
from app.services.common import PageParams, apply_changes, paginate


def _link_counts(db: Session) -> tuple[dict[str, int], dict[str, int]]:
    total = dict(db.execute(select(RiskControl.control_id, func.count()).group_by(RiskControl.control_id)).all())
    implemented = dict(db.execute(
        select(RiskControl.control_id, func.count())
        .where(RiskControl.implementation_status == ImplementationStatus.IMPLEMENTED)
        .group_by(RiskControl.control_id)
    ).all())
    return total, implemented


def control_to_read(control: SecurityControl, linked: int = 0, implemented: int = 0) -> ControlRead:
    return ControlRead(
        id=control.id, code=control.code, name=control.name, description=control.description,
        control_type=control.control_type, axis=CONTROL_AXIS[control.control_type], category=control.category,
        active=control.active, created_at=control.created_at, updated_at=control.updated_at,
        vulnerabilities=[VulnerabilityRef(id=v.id, code=v.code, name=v.name) for v in control.vulnerabilities],
        linked_risk_count=linked, implemented_link_count=implemented,
    )


def _get(db: Session, control_id: str) -> SecurityControl:
    control = db.get(SecurityControl, control_id, options=[selectinload(SecurityControl.vulnerabilities)])
    if control is None:
        raise NotFoundError(f"Control '{control_id}' was not found.")
    return control


def get_control(db: Session, control_id: str) -> ControlRead:
    control = _get(db, control_id)
    total, implemented = _link_counts(db)
    return control_to_read(control, total.get(control.id, 0), implemented.get(control.id, 0))


def list_controls(db: Session, page: PageParams, *, search=None, control_type=None, category=None, active=None):
    stmt = select(SecurityControl).options(selectinload(SecurityControl.vulnerabilities))
    if search:
        term = f"%{search.strip()}%"
        stmt = stmt.where(or_(SecurityControl.code.ilike(term), SecurityControl.name.ilike(term),
                              SecurityControl.description.ilike(term)))
    if control_type:
        stmt = stmt.where(SecurityControl.control_type == control_type)
    if category:
        stmt = stmt.where(SecurityControl.category == category)
    if active is not None:
        stmt = stmt.where(SecurityControl.active.is_(active))
    stmt = stmt.order_by(func.length(SecurityControl.code), SecurityControl.code)
    items, total_count = paginate(db, stmt, page)
    total, implemented = _link_counts(db)
    return [control_to_read(c, total.get(c.id, 0), implemented.get(c.id, 0)) for c in items], total_count


def _resolve_vulnerabilities(db: Session, ids: list[str]) -> list[Vulnerability]:
    ids = list(dict.fromkeys(ids))
    vulns = list(db.scalars(select(Vulnerability).where(Vulnerability.id.in_(ids)))) if ids else []
    if len(vulns) != len(ids):
        raise DomainValidationError("Unknown vulnerability reference.",
                                    [{"field": "vulnerability_ids", "message": "One or more vulnerabilities do not exist."}])
    return vulns


def create_control(db: Session, payload: ControlCreate, actor: str) -> ControlRead:
    if db.scalar(select(SecurityControl.id).where(SecurityControl.code == payload.code)):
        raise ConflictError(f"Control code '{payload.code}' already exists.",
                            [{"field": "code", "message": "Codes must be unique."}])
    data = payload.model_dump(exclude={"vulnerability_ids"})
    control = SecurityControl(**data)
    control.vulnerabilities = _resolve_vulnerabilities(db, payload.vulnerability_ids)
    db.add(control)
    db.flush()
    audit_service.record(db, actor=actor, action="control.created", entity_type="control", entity_id=control.id,
                         details={"code": control.code, "name": control.name, "control_type": control.control_type,
                                  "vulnerabilities": [v.code for v in control.vulnerabilities]})
    db.commit()
    return get_control(db, control.id)


def update_control(db: Session, control_id: str, payload: ControlUpdate, actor: str) -> ControlRead:
    control = _get(db, control_id)
    changes = payload.model_dump(exclude_unset=True)
    for field, value in changes.items():
        if value is None:
            raise DomainValidationError("Field cannot be null.", [{"field": field, "message": "A value is required."}])
    vuln_ids = changes.pop("vulnerability_ids", None)
    diff = apply_changes(control, changes)
    if vuln_ids is not None:
        before = [v.code for v in control.vulnerabilities]
        control.vulnerabilities = _resolve_vulnerabilities(db, vuln_ids)
        after = [v.code for v in control.vulnerabilities]
        if sorted(before) != sorted(after):
            diff["vulnerabilities"] = {"from": before, "to": after}
    if not diff:
        return get_control(db, control.id)
    db.flush()
    recalculated = []
    if {"control_type", "active"} & diff.keys():
        recalculated = risk_service.recompute_for_control(db, control.id)
    audit_service.record(db, actor=actor, action="control.updated", entity_type="control", entity_id=control.id,
                         details={"code": control.code, "changes": diff,
                                  "residual_recalculated": recalculated})
    db.commit()
    return get_control(db, control.id)


def categories(db: Session) -> list[str]:
    return sorted(db.scalars(select(SecurityControl.category).distinct()))
