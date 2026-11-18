"""Risk register. Derived fields are computed exclusively via app.core.risk_model."""

from __future__ import annotations

from collections.abc import Iterable

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, joinedload, selectinload

from app.core.constants import CONTROL_AXIS, EFFECTIVENESS_LEVELS, ImplementationStatus
from app.core.exceptions import ConflictError, DomainValidationError, NotFoundError
from app.core.risk_model import SEVERITY_BANDS, ControlEffect, assess_residual, assess_risk
from app.models import Asset, Risk, RiskControl, SecurityControl, Threat, ThreatVulnerabilityPair, Vulnerability
from app.schemas.control import ResidualCalculation, RiskControlCreate, RiskControlRead, RiskControlUpdate
from app.schemas.risk import CatalogueRef, RiskAssetRef, RiskCalculation, RiskCreate, RiskRead, RiskUpdate
from app.services import audit_service
from app.services.common import PageParams, apply_changes, json_safe, paginate

SORTABLE = {
    "reference": Risk.reference,
    "risk_score": Risk.risk_score,
    # Severity is a monotonic function of score, so sorting by score sorts by severity.
    "severity": Risk.risk_score,
    "residual_score": Risk.residual_score,
    "residual_severity": Risk.residual_score,
    "likelihood": Risk.likelihood,
    "overall_impact": Risk.overall_impact,
    "status": Risk.status,
    "treatment": Risk.treatment,
    "owner": Risk.owner,
    "updated_at": Risk.updated_at,
    "asset": Asset.asset_tag,
}

_LOAD = (
    joinedload(Risk.asset).joinedload(Asset.branch),
    joinedload(Risk.asset).joinedload(Asset.zone),
    joinedload(Risk.threat),
    joinedload(Risk.vulnerability),
    selectinload(Risk.control_links).joinedload(RiskControl.control),
)


def counts_toward_residual(link: RiskControl) -> bool:
    return link.implementation_status == ImplementationStatus.IMPLEMENTED and link.control.active


def control_effects(risk: Risk) -> list[ControlEffect]:
    """Effects of the risk's counted controls (implemented links to active controls)."""
    return [
        ControlEffect(code=link.control.code, axis=CONTROL_AXIS[link.control.control_type].value,
                      reduction=EFFECTIVENESS_LEVELS[link.effectiveness])
        for link in risk.control_links if counts_toward_residual(link)
    ]


def _residual(risk: Risk):
    return assess_residual(risk.likelihood, risk.overall_impact, control_effects(risk))


def control_link_to_read(link: RiskControl, applied_codes: set[str]) -> RiskControlRead:
    c = link.control
    counted = counts_toward_residual(link)
    return RiskControlRead(
        control_id=c.id, code=c.code, name=c.name, control_type=c.control_type,
        axis=CONTROL_AXIS[c.control_type], category=c.category, control_active=c.active,
        implementation_status=link.implementation_status, effectiveness=link.effectiveness, notes=link.notes,
        reduction=EFFECTIVENESS_LEVELS[link.effectiveness], counted=counted,
        applied=counted and c.code in applied_codes, created_at=link.created_at, updated_at=link.updated_at,
    )


def _band_label(score: int) -> str:
    for low, high, severity in SEVERITY_BANDS:
        if low <= score <= high:
            return f"{low}–{high} → {severity.value}"
    return ""


def _pairing_rationale(db: Session, threat_id: str, vuln_id: str) -> str | None:
    return db.scalar(
        select(ThreatVulnerabilityPair.rationale).where(
            ThreatVulnerabilityPair.threat_id == threat_id,
            ThreatVulnerabilityPair.vulnerability_id == vuln_id,
        )
    )


def risk_to_read(risk: Risk, rationale: str | None = None) -> RiskRead:
    a = risk.asset
    residual = _residual(risk)
    applied = {code for code in (residual.likelihood_control, residual.impact_control) if code}
    return RiskRead(
        id=risk.id,
        reference=risk.reference,
        asset=RiskAssetRef(
            id=a.id, asset_tag=a.asset_tag, name=a.name, branch_code=a.branch.code, zone_name=a.zone.name,
            criticality=a.criticality.value, data_classification=a.data_classification.value,
        ),
        threat=CatalogueRef(id=risk.threat.id, code=risk.threat.code, name=risk.threat.name),
        vulnerability=CatalogueRef(id=risk.vulnerability.id, code=risk.vulnerability.code, name=risk.vulnerability.name),
        likelihood=risk.likelihood,
        confidentiality_impact=risk.confidentiality_impact,
        integrity_impact=risk.integrity_impact,
        availability_impact=risk.availability_impact,
        overall_impact=risk.overall_impact,
        risk_score=risk.risk_score,
        severity=risk.severity,
        residual_likelihood=risk.residual_likelihood,
        residual_impact=risk.residual_impact,
        residual_score=risk.residual_score,
        residual_severity=risk.residual_severity,
        residual_calculation=ResidualCalculation(
            likelihood_expression=residual.likelihood_expression,
            impact_expression=residual.impact_expression,
            score_expression=residual.score_expression,
            severity_band=_band_label(residual.residual_score),
        ),
        controls=[control_link_to_read(link, applied) for link in
                  sorted(risk.control_links, key=lambda x: x.control.code)],
        treatment=risk.treatment,
        owner=risk.owner,
        status=risk.status,
        created_at=risk.created_at,
        updated_at=risk.updated_at,
        calculation=RiskCalculation(
            impact_expression=(
                f"Impact = max(C {risk.confidentiality_impact}, I {risk.integrity_impact}, "
                f"A {risk.availability_impact}) = {risk.overall_impact}"
            ),
            score_expression=f"Score = {risk.likelihood} × {risk.overall_impact} = {risk.risk_score}",
            severity_band=_band_label(risk.risk_score),
            explanation=assess_risk(
                risk.likelihood, risk.confidentiality_impact, risk.integrity_impact, risk.availability_impact
            ).explanation,
        ),
        pairing_rationale=rationale,
    )


def apply_assessment(risk: Risk) -> None:
    """Recompute and store inherent AND residual derived fields from the current inputs and controls."""
    result = assess_risk(risk.likelihood, risk.confidentiality_impact, risk.integrity_impact, risk.availability_impact)
    risk.overall_impact = result.overall_impact
    risk.risk_score = result.risk_score
    risk.severity = result.severity
    residual = _residual(risk)
    risk.residual_likelihood = residual.residual_likelihood
    risk.residual_impact = residual.residual_impact
    risk.residual_score = residual.residual_score
    risk.residual_severity = residual.residual_severity


def _snapshot(risk: Risk) -> dict:
    return {"risk_score": risk.risk_score, "severity": json_safe(risk.severity),
            "residual_score": risk.residual_score, "residual_severity": json_safe(risk.residual_severity)}


def _recalc_details(before: dict, risk: Risk) -> dict:
    after = _snapshot(risk)
    return {k: {"from": before[k], "to": after[k]} for k in before if before[k] != after[k]}


def next_reference(db: Session) -> str:
    refs = db.scalars(select(Risk.reference)).all()
    highest = max((int(r.split("-")[1]) for r in refs if r.startswith("RSK-")), default=0)
    return f"RSK-{highest + 1:04d}"


def build_risk(db: Session, **fields) -> Risk:
    """Create (flush, no commit, no audit) a risk with derived fields. Used by the service and seed."""
    risk = Risk(reference=next_reference(db), **fields)
    apply_assessment(risk)
    db.add(risk)
    db.flush()
    return risk


def _get(db: Session, risk_id: str) -> Risk:
    risk = db.get(Risk, risk_id, options=list(_LOAD))
    if risk is None:
        raise NotFoundError(f"Risk '{risk_id}' was not found.")
    return risk


def get_risk(db: Session, risk_id: str) -> RiskRead:
    risk = _get(db, risk_id)
    return risk_to_read(risk, _pairing_rationale(db, risk.threat_id, risk.vulnerability_id))


def list_risks(
    db: Session,
    page: PageParams,
    *,
    search: str | None = None,
    branch_id: str | None = None,
    asset_id: str | None = None,
    threat_id: str | None = None,
    vulnerability_id: str | None = None,
    severity: str | None = None,
    residual_severity: str | None = None,
    control_id: str | None = None,
    status: str | None = None,
    treatment: str | None = None,
    sort: str = "risk_score",
    order: str = "desc",
) -> tuple[list[RiskRead], int]:
    stmt = (
        select(Risk)
        .join(Asset, Risk.asset_id == Asset.id)
        .join(Threat, Risk.threat_id == Threat.id)
        .join(Vulnerability, Risk.vulnerability_id == Vulnerability.id)
        .options(*_LOAD)
    )
    if search:
        term = f"%{search.strip()}%"
        stmt = stmt.where(or_(
            Risk.reference.ilike(term), Asset.asset_tag.ilike(term), Asset.name.ilike(term),
            Threat.name.ilike(term), Threat.code.ilike(term), Vulnerability.name.ilike(term),
            Vulnerability.code.ilike(term), Risk.owner.ilike(term),
        ))
    if branch_id:
        stmt = stmt.where(Asset.branch_id == branch_id)
    if asset_id:
        stmt = stmt.where(Risk.asset_id == asset_id)
    if threat_id:
        stmt = stmt.where(Risk.threat_id == threat_id)
    if vulnerability_id:
        stmt = stmt.where(Risk.vulnerability_id == vulnerability_id)
    if severity:
        stmt = stmt.where(Risk.severity == severity)
    if residual_severity:
        stmt = stmt.where(Risk.residual_severity == residual_severity)
    if control_id:
        stmt = stmt.where(Risk.control_links.any(RiskControl.control_id == control_id))
    if status:
        stmt = stmt.where(Risk.status == status)
    if treatment:
        stmt = stmt.where(Risk.treatment == treatment)
    column = SORTABLE.get(sort, Risk.risk_score)
    stmt = stmt.order_by(column.desc() if order == "desc" else column.asc(), Risk.reference.asc())
    items, total = paginate(db, stmt, page)
    pairs = {
        (p.threat_id, p.vulnerability_id): p.rationale for p in db.scalars(select(ThreatVulnerabilityPair))
    }
    return [risk_to_read(r, pairs.get((r.threat_id, r.vulnerability_id))) for r in items], total


def create_risk(db: Session, payload: RiskCreate, actor: str) -> RiskRead:
    asset = db.get(Asset, payload.asset_id)
    threat = db.get(Threat, payload.threat_id)
    vuln = db.get(Vulnerability, payload.vulnerability_id)
    errors = []
    if asset is None:
        errors.append({"field": "asset_id", "message": "Unknown asset."})
    if threat is None:
        errors.append({"field": "threat_id", "message": "Unknown threat."})
    elif not threat.active:
        errors.append({"field": "threat_id", "message": "Threat is inactive."})
    if vuln is None:
        errors.append({"field": "vulnerability_id", "message": "Unknown vulnerability."})
    elif not vuln.active:
        errors.append({"field": "vulnerability_id", "message": "Vulnerability is inactive."})
    if errors:
        raise DomainValidationError("Risk references are invalid.", errors)

    duplicate = db.scalar(select(Risk.reference).where(
        Risk.asset_id == asset.id, Risk.threat_id == threat.id, Risk.vulnerability_id == vuln.id
    ))
    if duplicate:
        raise ConflictError(f"A risk for this asset, threat and vulnerability already exists ({duplicate}).")

    risk = build_risk(db, **payload.model_dump())
    audit_service.record(
        db, actor=actor, action="risk.created", entity_type="risk", entity_id=risk.id,
        details={
            "reference": risk.reference, "asset_tag": asset.asset_tag, "threat": threat.code,
            "vulnerability": vuln.code, "likelihood": risk.likelihood,
            "cia": [risk.confidentiality_impact, risk.integrity_impact, risk.availability_impact],
            "risk_score": risk.risk_score, "severity": risk.severity,
        },
    )
    db.commit()
    return get_risk(db, risk.id)


def update_risk(db: Session, risk_id: str, payload: RiskUpdate, actor: str) -> RiskRead:
    risk = _get(db, risk_id)
    changes = payload.model_dump(exclude_unset=True)
    for field, value in changes.items():
        if value is None:
            raise DomainValidationError("Field cannot be null.", [{"field": field, "message": "A value is required."}])
    before = _snapshot(risk)
    diff = apply_changes(risk, changes)
    if diff:
        apply_assessment(risk)
        details = {"reference": risk.reference, "changes": diff}
        recalculated = _recalc_details(before, risk)
        if recalculated:
            details["recalculated"] = recalculated
        audit_service.record(db, actor=actor, action="risk.updated", entity_type="risk", entity_id=risk.id, details=details)
        db.commit()
    db.expire(risk)
    return get_risk(db, risk.id)


# ---- V2: controls applied to a risk ------------------------------------------------------------

def _get_link(risk: Risk, control_id: str) -> RiskControl:
    link = next((link for link in risk.control_links if link.control_id == control_id), None)
    if link is None:
        raise NotFoundError("This control is not linked to the risk.")
    return link


def link_control(db: Session, risk_id: str, payload: RiskControlCreate, actor: str) -> RiskRead:
    risk = _get(db, risk_id)
    control = db.get(SecurityControl, payload.control_id)
    if control is None:
        raise DomainValidationError("Unknown control.", [{"field": "control_id", "message": "Unknown control."}])
    if not control.active:
        raise DomainValidationError("Control is inactive.", [{"field": "control_id", "message": "Inactive controls cannot be linked."}])
    if any(link.control_id == control.id for link in risk.control_links):
        raise ConflictError(f"{control.code} is already linked to {risk.reference}.")
    before = _snapshot(risk)
    risk.control_links.append(RiskControl(control=control, implementation_status=payload.implementation_status,
                                          effectiveness=payload.effectiveness, notes=payload.notes.strip()))
    db.flush()
    apply_assessment(risk)
    audit_service.record(db, actor=actor, action="risk.control_linked", entity_type="risk", entity_id=risk.id, details={
        "reference": risk.reference, "control": control.code, "implementation_status": payload.implementation_status,
        "effectiveness": payload.effectiveness, "recalculated": _recalc_details(before, risk),
    })
    db.commit()
    db.expire(risk)
    return get_risk(db, risk.id)


def update_control_link(db: Session, risk_id: str, control_id: str, payload: RiskControlUpdate, actor: str) -> RiskRead:
    risk = _get(db, risk_id)
    link = _get_link(risk, control_id)
    changes = payload.model_dump(exclude_unset=True)
    for field, value in changes.items():
        if value is None:
            raise DomainValidationError("Field cannot be null.", [{"field": field, "message": "A value is required."}])
    if "notes" in changes:
        changes["notes"] = changes["notes"].strip()
    before = _snapshot(risk)
    diff = apply_changes(link, changes)
    if diff:
        apply_assessment(risk)
        audit_service.record(db, actor=actor, action="risk.control_updated", entity_type="risk", entity_id=risk.id,
                             details={"reference": risk.reference, "control": link.control.code, "changes": diff,
                                      "recalculated": _recalc_details(before, risk)})
        db.commit()
    db.expire(risk)
    return get_risk(db, risk.id)


def unlink_control(db: Session, risk_id: str, control_id: str, actor: str) -> RiskRead:
    risk = _get(db, risk_id)
    link = _get_link(risk, control_id)
    before = _snapshot(risk)
    code = link.control.code
    risk.control_links.remove(link)
    db.flush()
    apply_assessment(risk)
    audit_service.record(db, actor=actor, action="risk.control_unlinked", entity_type="risk", entity_id=risk.id,
                         details={"reference": risk.reference, "control": code,
                                  "recalculated": _recalc_details(before, risk)})
    db.commit()
    db.expire(risk)
    return get_risk(db, risk.id)


def recompute_for_control(db: Session, control_id: str) -> list[dict]:
    """Recalculate residual risk for every risk linked to a control (after its type/active flag changed)."""
    changed = []
    risks = db.scalars(select(Risk).where(Risk.control_links.any(RiskControl.control_id == control_id))
                       .options(*_LOAD)).unique().all()
    for risk in risks:
        before = _snapshot(risk)
        apply_assessment(risk)
        diff = _recalc_details(before, risk)
        if diff:
            changed.append({"reference": risk.reference, **diff})
    return changed


def get_risk_context(
    db: Session,
    asset_ids: Iterable[str],
    threat_codes: Iterable[str],
    vulnerability_codes: Iterable[str],
) -> list[RiskRead]:
    """Illustrative risks on the given assets that relate to the given threats/vulnerabilities."""
    asset_ids = [a for a in asset_ids if a]
    threat_codes, vulnerability_codes = list(threat_codes), list(vulnerability_codes)
    if not asset_ids:
        return []
    stmt = (
        select(Risk)
        .join(Threat, Risk.threat_id == Threat.id)
        .join(Vulnerability, Risk.vulnerability_id == Vulnerability.id)
        .where(Risk.asset_id.in_(asset_ids))
        .where(or_(Threat.code.in_(threat_codes), Vulnerability.code.in_(vulnerability_codes)))
        .options(*_LOAD)
        .order_by(Risk.risk_score.desc(), Risk.reference)
    )
    pairs = {(p.threat_id, p.vulnerability_id): p.rationale for p in db.scalars(select(ThreatVulnerabilityPair))}
    return [risk_to_read(r, pairs.get((r.threat_id, r.vulnerability_id))) for r in db.scalars(stmt).unique()]


def zone_asset_ids(db: Session, zone_id: str | None) -> list[str]:
    if not zone_id:
        return []
    return list(db.scalars(select(Asset.id).where(Asset.zone_id == zone_id).order_by(Asset.asset_tag)))


def risk_counts_by_severity(db: Session, branch_id: str | None = None) -> dict[str, int]:
    stmt = select(Risk.severity, func.count()).join(Asset, Risk.asset_id == Asset.id)
    if branch_id:
        stmt = stmt.where(Asset.branch_id == branch_id)
    return {s.value: n for s, n in db.execute(stmt.group_by(Risk.severity)).all()}
