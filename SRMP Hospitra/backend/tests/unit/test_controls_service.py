"""Residual-risk recalculation through the services (links, status, deactivation, type change)."""

import pytest
from sqlalchemy import select

from app.core.exceptions import ConflictError, DomainValidationError
from app.core.risk_model import ControlEffect, assess_residual
from app.models import AuditLog, Risk, SecurityControl
from app.schemas.control import ControlUpdate, RiskControlCreate, RiskControlUpdate
from app.schemas.risk import RiskUpdate
from app.services import control_service, risk_service
from tests.conftest import asset_by_tag


def _risk(db, tag, threat, vuln):
    asset = asset_by_tag(db, tag)
    return next(r for r in db.scalars(select(Risk).where(Risk.asset_id == asset.id))
                if r.threat.code == threat and r.vulnerability.code == vuln)


def _control(db, code):
    return db.scalar(select(SecurityControl).where(SecurityControl.code == code))


def test_seeded_residual_values_match_the_model(seeded_db):
    for risk in seeded_db.scalars(select(Risk)):
        expected = assess_residual(risk.likelihood, risk.overall_impact, risk_service.control_effects(risk))
        assert (risk.residual_likelihood, risk.residual_impact, risk.residual_score, risk.residual_severity) == (
            expected.residual_likelihood, expected.residual_impact, expected.residual_score, expected.residual_severity)


def test_seeded_examples(seeded_db):
    r1 = risk_service.get_risk(seeded_db, _risk(seeded_db, "HSP-A-CLN-001", "T1", "V6").id)
    assert (r1.risk_score, r1.residual_score, r1.residual_severity.value) == (20, 9, "Moderate")
    rc = risk_service.get_risk(seeded_db, _risk(seeded_db, "HSP-C-CLN-001", "T1", "V6").id)
    assert rc.residual_score == rc.risk_score == 20  # Branch C controls are only Planned
    assert all(not c.counted for c in rc.controls)


def test_planned_link_has_no_effect_until_implemented(seeded_db):
    risk = _risk(seeded_db, "HSP-A-NET-001", "T4", "V4")  # L2 × I3 = 6, no seeded controls
    c04 = _control(seeded_db, "C04")
    r = risk_service.link_control(seeded_db, risk.id, RiskControlCreate(control_id=c04.id, implementation_status="Planned",
                                                                        effectiveness="Substantial"), "op")
    assert r.residual_score == r.risk_score == 6
    r = risk_service.update_control_link(seeded_db, risk.id, c04.id, RiskControlUpdate(implementation_status="Implemented"), "op")
    assert (r.residual_likelihood, r.residual_score, r.residual_severity.value) == (1, 3, "Low")
    assert r.controls[0].applied
    r = risk_service.unlink_control(seeded_db, risk.id, c04.id, "op")
    assert r.residual_score == 6 and r.controls == []
    actions = [a.action for a in seeded_db.scalars(select(AuditLog).where(AuditLog.entity_id == risk.id))]
    assert {"risk.control_linked", "risk.control_updated", "risk.control_unlinked"} <= set(actions)


def test_link_validation(seeded_db):
    risk = _risk(seeded_db, "HSP-A-CLN-001", "T1", "V6")
    with pytest.raises(ConflictError):
        risk_service.link_control(seeded_db, risk.id, RiskControlCreate(
            control_id=_control(seeded_db, "C06").id, implementation_status="Implemented", effectiveness="Partial"), "op")
    with pytest.raises(DomainValidationError):
        risk_service.link_control(seeded_db, risk.id, RiskControlCreate(
            control_id="missing", implementation_status="Implemented", effectiveness="Partial"), "op")


def test_deactivating_a_control_recalculates_linked_risks(seeded_db):
    c08 = _control(seeded_db, "C08")
    target = _risk(seeded_db, "HSP-A-CLN-001", "T1", "V6")
    assert target.residual_score == 9
    control_service.update_control(seeded_db, c08.id, ControlUpdate(active=False), "op")
    seeded_db.refresh(target)
    assert target.residual_score == 3 * 5  # only C06 (L −1) still counts
    log = seeded_db.scalars(select(AuditLog).where(AuditLog.action == "control.updated")).all()[-1]
    assert any(item["reference"] == target.reference for item in log.details["residual_recalculated"])
    control_service.update_control(seeded_db, c08.id, ControlUpdate(active=True), "op")
    seeded_db.refresh(target)
    assert target.residual_score == 9


def test_changing_control_type_moves_axis(seeded_db):
    risk = _risk(seeded_db, "HSP-A-GST-001", "T3", "V3")  # L3 × I2; C03 preventive substantial → 1 × 2 = 2
    assert risk.residual_score == 2
    control_service.update_control(seeded_db, _control(seeded_db, "C03").id, ControlUpdate(control_type="Corrective"), "op")
    seeded_db.refresh(risk)
    assert (risk.residual_likelihood, risk.residual_impact, risk.residual_score) == (3, 1, 3)


def test_inactive_control_cannot_be_linked(seeded_db):
    c04 = _control(seeded_db, "C04")
    control_service.update_control(seeded_db, c04.id, ControlUpdate(active=False), "op")
    risk = _risk(seeded_db, "HSP-A-NET-001", "T4", "V4")
    with pytest.raises(DomainValidationError):
        risk_service.link_control(seeded_db, risk.id, RiskControlCreate(
            control_id=c04.id, implementation_status="Implemented", effectiveness="Partial"), "op")


def test_updating_inherent_inputs_also_recalculates_residual(seeded_db):
    risk = _risk(seeded_db, "HSP-A-CLN-001", "T1", "V6")
    r = risk_service.update_risk(seeded_db, risk.id, RiskUpdate(likelihood=2), "op")
    expected = assess_residual(2, 5, [ControlEffect("C06", "likelihood", 1), ControlEffect("C08", "impact", 2)])
    assert (r.risk_score, r.residual_score) == (10, expected.residual_score)
    log = seeded_db.scalars(select(AuditLog).where(AuditLog.entity_id == risk.id, AuditLog.action == "risk.updated")).all()[-1]
    assert log.details["recalculated"]["residual_score"] == {"from": 9, "to": expected.residual_score}
