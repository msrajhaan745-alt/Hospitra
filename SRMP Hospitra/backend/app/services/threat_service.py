"""Threat and vulnerability catalogue (create / update / list; no delete)."""

from __future__ import annotations

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, selectinload

from app.core.exceptions import ConflictError, DomainValidationError, NotFoundError
from app.models import Risk, Threat, ThreatVulnerabilityPair, Vulnerability
from app.schemas.threat import PairingRef, ThreatCreate, ThreatRead, ThreatUpdate
from app.schemas.vulnerability import VulnerabilityCreate, VulnerabilityRead, VulnerabilityUpdate
from app.services import audit_service
from app.services.common import PageParams, apply_changes, paginate


def _risk_counts(db: Session, column) -> dict[str, int]:
    return dict(db.execute(select(column, func.count()).group_by(column)).all())


def threat_to_read(threat: Threat, risk_count: int = 0) -> ThreatRead:
    data = ThreatRead.model_validate(threat).model_dump(exclude={"risk_count", "related_vulnerabilities"})
    return ThreatRead(
        **data,
        risk_count=risk_count,
        related_vulnerabilities=[
            PairingRef(id=p.vulnerability.id, code=p.vulnerability.code, name=p.vulnerability.name, rationale=p.rationale)
            for p in sorted(threat.pairs, key=lambda p: p.vulnerability.code)
        ],
    )


def vulnerability_to_read(vuln: Vulnerability, risk_count: int = 0) -> VulnerabilityRead:
    data = VulnerabilityRead.model_validate(vuln).model_dump(exclude={"risk_count", "related_threats"})
    return VulnerabilityRead(
        **data,
        risk_count=risk_count,
        related_threats=[
            PairingRef(id=p.threat.id, code=p.threat.code, name=p.threat.name, rationale=p.rationale)
            for p in sorted(vuln.pairs, key=lambda p: p.threat.code)
        ],
    )


def _catalogue_query(model, search, active, source_type):
    stmt = select(model)
    if search:
        term = f"%{search.strip()}%"
        stmt = stmt.where(or_(model.code.ilike(term), model.name.ilike(term), model.description.ilike(term)))
    if active is not None:
        stmt = stmt.where(model.active == active)
    if source_type:
        stmt = stmt.where(model.source_type == source_type)
    # Natural code order (T1, T2 … T10).
    return stmt.order_by(func.length(model.code), model.code)


# ---- threats -------------------------------------------------------------------------------

def list_threats(db: Session, page: PageParams, *, search=None, active=None, source_type=None):
    stmt = _catalogue_query(Threat, search, active, source_type).options(
        selectinload(Threat.pairs).selectinload(ThreatVulnerabilityPair.vulnerability)
    )
    items, total = paginate(db, stmt, page)
    counts = _risk_counts(db, Risk.threat_id)
    return [threat_to_read(t, counts.get(t.id, 0)) for t in items], total


def get_threat(db: Session, threat_id: str) -> Threat:
    threat = db.get(Threat, threat_id)
    if threat is None:
        raise NotFoundError(f"Threat '{threat_id}' was not found.")
    return threat


def get_threat_read(db: Session, threat_id: str) -> ThreatRead:
    threat = get_threat(db, threat_id)
    count = db.scalar(select(func.count()).select_from(Risk).where(Risk.threat_id == threat_id)) or 0
    return threat_to_read(threat, count)


def create_threat(db: Session, payload: ThreatCreate, actor: str) -> ThreatRead:
    if db.scalar(select(Threat.id).where(Threat.code == payload.code)):
        raise ConflictError(f"Threat code '{payload.code}' already exists.", [{"field": "code", "message": "Codes must be unique."}])
    threat = Threat(**payload.model_dump())
    db.add(threat)
    db.flush()
    audit_service.record(db, actor=actor, action="threat.created", entity_type="threat", entity_id=threat.id,
                         details={"code": threat.code, "name": threat.name, "source_type": threat.source_type})
    db.commit()
    return get_threat_read(db, threat.id)


def update_threat(db: Session, threat_id: str, payload: ThreatUpdate, actor: str) -> ThreatRead:
    threat = get_threat(db, threat_id)
    changes = payload.model_dump(exclude_unset=True)
    _reject_nulls(changes)
    diff = apply_changes(threat, changes)
    if diff:
        audit_service.record(db, actor=actor, action="threat.updated", entity_type="threat", entity_id=threat.id,
                             details={"code": threat.code, "changes": diff})
        db.commit()
    return get_threat_read(db, threat.id)


# ---- vulnerabilities ------------------------------------------------------------------------

def list_vulnerabilities(db: Session, page: PageParams, *, search=None, active=None, source_type=None):
    stmt = _catalogue_query(Vulnerability, search, active, source_type).options(
        selectinload(Vulnerability.pairs).selectinload(ThreatVulnerabilityPair.threat)
    )
    items, total = paginate(db, stmt, page)
    counts = _risk_counts(db, Risk.vulnerability_id)
    return [vulnerability_to_read(v, counts.get(v.id, 0)) for v in items], total


def get_vulnerability(db: Session, vuln_id: str) -> Vulnerability:
    vuln = db.get(Vulnerability, vuln_id)
    if vuln is None:
        raise NotFoundError(f"Vulnerability '{vuln_id}' was not found.")
    return vuln


def get_vulnerability_read(db: Session, vuln_id: str) -> VulnerabilityRead:
    vuln = get_vulnerability(db, vuln_id)
    count = db.scalar(select(func.count()).select_from(Risk).where(Risk.vulnerability_id == vuln_id)) or 0
    return vulnerability_to_read(vuln, count)


def create_vulnerability(db: Session, payload: VulnerabilityCreate, actor: str) -> VulnerabilityRead:
    if db.scalar(select(Vulnerability.id).where(Vulnerability.code == payload.code)):
        raise ConflictError(f"Vulnerability code '{payload.code}' already exists.", [{"field": "code", "message": "Codes must be unique."}])
    vuln = Vulnerability(**payload.model_dump())
    db.add(vuln)
    db.flush()
    audit_service.record(db, actor=actor, action="vulnerability.created", entity_type="vulnerability", entity_id=vuln.id,
                         details={"code": vuln.code, "name": vuln.name, "source_type": vuln.source_type})
    db.commit()
    return get_vulnerability_read(db, vuln.id)


def update_vulnerability(db: Session, vuln_id: str, payload: VulnerabilityUpdate, actor: str) -> VulnerabilityRead:
    vuln = get_vulnerability(db, vuln_id)
    changes = payload.model_dump(exclude_unset=True)
    _reject_nulls(changes)
    diff = apply_changes(vuln, changes)
    if diff:
        audit_service.record(db, actor=actor, action="vulnerability.updated", entity_type="vulnerability", entity_id=vuln.id,
                             details={"code": vuln.code, "changes": diff})
        db.commit()
    return get_vulnerability_read(db, vuln.id)


def _reject_nulls(changes: dict) -> None:
    for field, value in changes.items():
        if value is None:
            raise DomainValidationError("Field cannot be null.", [{"field": field, "message": "A value is required."}])
