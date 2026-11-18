"""Incident creation policy, lifecycle transitions and duplicate-processing protection."""

import pytest
from sqlalchemy import func, select

from app.core.constants import INCIDENT_TRANSITIONS, IncidentStatus, Severity
from app.core.exceptions import ConflictError, InvalidTransitionError
from app.models import AuditLog, Detection, Incident
from app.schemas.incident import IncidentUpdate, NoteCreate
from app.services import incident_service, simulation_service


@pytest.mark.parametrize("severity,matched,expected", [
    (Severity.LOW, True, False),
    (Severity.MODERATE, True, False),
    (Severity.HIGH, True, True),
    (Severity.CRITICAL, True, True),
    (Severity.CRITICAL, False, False),
])
def test_creation_policy(severity, matched, expected):
    assert incident_service.should_create_incident(Detection(severity=severity, matched=matched)) is expected


def test_moderate_scenario_creates_no_incident(seeded_db):
    before = seeded_db.scalar(select(func.count()).select_from(Incident))
    result = simulation_service.run_scenario(seeded_db, "S3", "A", actor="test")
    assert len(result.matched) == 1 and result.matched[0].severity is Severity.MODERATE
    assert result.incidents == []
    assert seeded_db.scalar(select(func.count()).select_from(Incident)) == before


@pytest.mark.parametrize("scenario_id", ["S1", "S4", "S5", "S6", "S7"])
def test_high_and_critical_scenarios_create_one_incident(seeded_db, scenario_id):
    result = simulation_service.run_scenario(seeded_db, scenario_id, "B", actor="test")
    assert len(result.incidents) == 1
    incident = result.incidents[0]
    assert incident.status is IncidentStatus.OPEN
    assert incident.severity is result.matched[0].severity
    assert incident.detection_id == result.matched[0].id
    assert result.events[-1].id in {e.id for e in incident.events}


def test_reprocessing_an_event_is_idempotent(seeded_db):
    result = simulation_service.run_scenario(seeded_db, "S1", "A", actor="test")
    event = result.events[0]
    counts = lambda m: seeded_db.scalar(select(func.count()).select_from(m))  # noqa: E731
    before = (counts(Detection), counts(Incident), counts(AuditLog))
    for _ in range(3):
        outcome = simulation_service.process_event(seeded_db, event)
        assert outcome.incidents_created == []
    seeded_db.commit()
    assert (counts(Detection), counts(Incident), counts(AuditLog)) == before


def test_incident_numbers_are_unique_and_sequential(seeded_db):
    a = simulation_service.run_scenario(seeded_db, "S1", "A", actor="test").incidents[0]
    b = simulation_service.run_scenario(seeded_db, "S6", "A", actor="test").incidents[0]
    assert int(b.incident_number.split("-")[1]) == int(a.incident_number.split("-")[1]) + 1


def _new_incident(db):
    incident = simulation_service.run_scenario(db, "S1", "A", actor="test").incidents[0]
    return incident.id


def test_full_lifecycle(seeded_db):
    incident_id = _new_incident(seeded_db)
    for status in ["Investigating", "Contained", "Resolved", "Closed"]:
        incident_service.update_incident(seeded_db, incident_id, IncidentUpdate(status=status), "local_operator")
        seeded_db.commit()
    incident = seeded_db.get(Incident, incident_id)
    assert incident.status is IncidentStatus.CLOSED
    assert incident.resolved_at is not None and incident.closed_at is not None
    changes = seeded_db.scalars(select(AuditLog).where(AuditLog.entity_id == incident_id,
                                                       AuditLog.action == "incident.status_changed")).all()
    assert len(changes) == 4


@pytest.mark.parametrize("current,requested", [
    ("Open", "Contained"), ("Open", "Resolved"), ("Open", "Closed"), ("Open", "Open"),
    ("Investigating", "Open"), ("Investigating", "Resolved"),
    ("Contained", "Investigating"), ("Contained", "Closed"),
    ("Resolved", "Contained"),
])
def test_invalid_transitions_rejected(seeded_db, current, requested):
    incident_id = _new_incident(seeded_db)
    path = ["Investigating", "Contained", "Resolved"]
    for status in path[: path.index(current) + 1] if current != "Open" else []:
        incident_service.update_incident(seeded_db, incident_id, IncidentUpdate(status=status), "op")
    with pytest.raises(InvalidTransitionError) as exc:
        incident_service.update_incident(seeded_db, incident_id, IncidentUpdate(status=requested), "op")
    assert exc.value.details["allowed_next_status"] == INCIDENT_TRANSITIONS[IncidentStatus(current)].value


def test_closed_incident_is_immutable(seeded_db):
    incident_id = _new_incident(seeded_db)
    for status in ["Investigating", "Contained", "Resolved", "Closed"]:
        incident_service.update_incident(seeded_db, incident_id, IncidentUpdate(status=status), "op")
    with pytest.raises(ConflictError):
        incident_service.update_incident(seeded_db, incident_id,
                                         IncidentUpdate(note=NoteCreate(note_type="Investigation", body="late")), "op")


def test_notes_and_assignment_recorded(seeded_db):
    incident_id = _new_incident(seeded_db)
    incident_service.update_incident(seeded_db, incident_id, IncidentUpdate(
        assigned_to="SOC Tier 1", note=NoteCreate(note_type="Investigation", body="Reviewed guest firewall logs.")), "op")
    incident_service.update_incident(seeded_db, incident_id, IncidentUpdate(
        note=NoteCreate(note_type="Resolution", body="Kiosk rebuilt.")), "op")
    seeded_db.commit()
    incident = seeded_db.get(Incident, incident_id)
    assert incident.assigned_to == "SOC Tier 1"
    assert [n.note_type.value for n in incident.notes] == ["Investigation", "Resolution"]
    assert incident.resolution_notes == "Kiosk rebuilt."
    actions = set(seeded_db.scalars(select(AuditLog.action).where(AuditLog.entity_id == incident_id)))
    assert {"incident.created", "incident.assigned", "incident.note_added"} <= actions
