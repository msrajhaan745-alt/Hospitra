"""End-to-end: Simulation → Event Persistence → Detection → Risk Context → Incident → Audit → WebSocket."""

import pytest
from sqlalchemy import func, select

from app.models import AuditLog, Detection, Incident, SecurityEvent
from app.services import simulation_service


@pytest.fixture
def api(seeded_db, client):
    return client


def _receive_until(ws, message_type, limit=10):
    for _ in range(limit):
        msg = ws.receive_json()
        if msg["type"] == message_type:
            return msg
    raise AssertionError(f"No {message_type} message received")


def test_full_pipeline_high_severity(api, seeded_db):
    with api.websocket_connect("/ws/events") as ws:
        assert ws.receive_json()["type"] == "connected"
        r = api.post("/api/v1/simulation/trigger", json={"scenario_id": "S1", "branch_code": "A"})
        assert r.status_code == 201
        body = r.json()
        msg = _receive_until(ws, "simulation.completed")

    # WebSocket notification published after commit, carrying the persisted identifiers.
    assert msg["data"]["event_ids"] == body["event_ids"]
    assert msg["data"]["incidents"][0]["id"] == body["incident_ids"][0]
    assert msg["timestamp"].endswith("Z")

    seeded_db.expire_all()
    event = seeded_db.get(SecurityEvent, body["event_ids"][0])
    assert event is not None and event.is_simulated and event.scenario_id == "S1"                 # persisted

    detection = seeded_db.get(Detection, body["matched_detection_ids"][0])
    assert detection.event_id == event.id and detection.rule_id == "R1" and detection.matched     # detection
    assert {"source_zone", "destination_zone", "policy"} <= set(detection.evidence)               # evidence

    incident = seeded_db.get(Incident, body["incident_ids"][0])
    assert incident.detection_id == detection.id                                                  # incident
    assert event.id in {e.id for e in incident.events}

    detail = api.get(f"/api/v1/incidents/{incident.id}").json()
    assert detail["risk_context"], "risk context should be attached for the affected asset"      # risk context

    actions = {a.action for a in seeded_db.scalars(select(AuditLog).where(
        AuditLog.entity_id.in_([event.id, detection.id, incident.id, body["run"]["id"]])))}
    assert {"event.created", "detection.matched", "incident.created", "simulation.triggered"} <= actions  # audit


def test_full_pipeline_moderate_severity_creates_no_incident(api, seeded_db):
    incidents_before = seeded_db.scalar(select(func.count()).select_from(Incident))
    with api.websocket_connect("/ws/events") as ws:
        ws.receive_json()
        body = api.post("/api/v1/simulation/trigger", json={"scenario_id": "S2", "branch_code": "C"}).json()
        msg = _receive_until(ws, "simulation.completed")
    assert len(body["event_ids"]) == 5
    assert len(body["matched_detection_ids"]) == 1 and body["incident_ids"] == []
    assert msg["data"]["incidents"] == []
    seeded_db.expire_all()
    assert seeded_db.scalar(select(func.count()).select_from(Incident)) == incidents_before
    # Lower-severity detection stays visible in monitoring.
    detections = api.get("/api/v1/detections", params={"matched": True, "rule_id": "R2"}).json()["items"]
    assert any(d["id"] == body["matched_detection_ids"][0] and d["incident_id"] is None for d in detections)


def test_all_eight_scenarios_via_api(api):
    expected_incident = {"S1": 1, "S2": 0, "S3": 0, "S4": 1, "S5": 1, "S6": 1, "S7": 1, "S8": 0}
    for scenario_id, n in expected_incident.items():
        body = api.post("/api/v1/simulation/trigger", json={"scenario_id": scenario_id, "branch_code": "B"}).json()
        assert len(body["matched_detection_ids"]) == 1, scenario_id
        assert len(body["incident_ids"]) == n, scenario_id


def test_incident_update_broadcasts(api):
    iid = api.post("/api/v1/simulation/trigger", json={"scenario_id": "S4", "branch_code": "A"}).json()["incident_ids"][0]
    with api.websocket_connect("/ws/events") as ws:
        ws.receive_json()
        api.patch(f"/api/v1/incidents/{iid}", json={"status": "Investigating"})
        msg = _receive_until(ws, "incident.updated")
    assert msg["data"] == {"incident_id": iid, "incident_number": msg["data"]["incident_number"], "status": "Investigating"}


def test_failed_run_leaves_no_partial_records(seeded_db, monkeypatch):
    counts = lambda: tuple(seeded_db.scalar(select(func.count()).select_from(m))  # noqa: E731
                           for m in (SecurityEvent, Detection, Incident, AuditLog))
    before = counts()

    def boom(*args, **kwargs):
        raise RuntimeError("simulated failure during incident creation")

    monkeypatch.setattr(simulation_service.incident_service, "create_from_detection", boom)
    with pytest.raises(RuntimeError):
        simulation_service.run_scenario(seeded_db, "S1", "A", actor="test")
    assert counts() == before


def test_reprocessing_via_pipeline_is_idempotent(api, seeded_db):
    body = api.post("/api/v1/simulation/trigger", json={"scenario_id": "S7", "branch_code": "C"}).json()
    seeded_db.expire_all()
    before = seeded_db.scalar(select(func.count()).select_from(Incident))
    for event_id in body["event_ids"]:
        simulation_service.process_event(seeded_db, seeded_db.get(SecurityEvent, event_id))
    seeded_db.commit()
    assert seeded_db.scalar(select(func.count()).select_from(Incident)) == before


def test_ping_pong(api):
    with api.websocket_connect("/ws/events") as ws:
        ws.receive_json()
        ws.send_text("ping")
        assert ws.receive_json()["type"] == "pong"
