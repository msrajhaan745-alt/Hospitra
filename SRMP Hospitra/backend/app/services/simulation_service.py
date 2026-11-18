"""Simulation service and the event-processing pipeline (spec §10.4).

    1. Operator selects a predefined scenario.
    2. Simulation service generates synthetic event drafts.
    3–4. Event service validates and persists each event.
    5–6. Detection service evaluates applicable rules and persists results + evidence.
    7. Risk service retrieves related illustrative risk context.
    8. Incident service creates an incident only for High/Critical detections.
    9. Audit service records the state changes.
   (10–11. The API layer publishes a WebSocket notification AFTER the commit succeeds;
           the frontend then refreshes from the REST API.)

Steps 2–9 run in ONE database transaction: any failure rolls everything back, so no
partial run can be left behind. The simulator never sends packets, opens sockets or
executes commands — it only writes rows to the application database.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import NotFoundError
from app.core.time import utcnow
from app.models import Branch, Detection, Incident, SecurityEvent, SimulationRun
from app.schemas.simulation import ScenarioRead, SimulationRunRead
from app.seed.scenarios import SCENARIOS, SCENARIOS_BY_ID, build_context
from app.services import audit_service, detection_service, event_service, incident_service, risk_service
from app.services.common import PageParams, paginate
from app.services.event_service import EventDraft


@dataclass
class ProcessOutcome:
    event: SecurityEvent
    detections: list[Detection] = field(default_factory=list)
    matched: list[Detection] = field(default_factory=list)
    incidents_created: list[Incident] = field(default_factory=list)
    risk_ids: list[str] = field(default_factory=list)


@dataclass
class TriggerResult:
    run: SimulationRun
    events: list[SecurityEvent]
    matched: list[Detection]
    incidents: list[Incident]

    @property
    def summary(self) -> str:
        if self.incidents:
            numbers = ", ".join(i.incident_number for i in self.incidents)
            tail = f"{len(self.incidents)} incident(s) opened ({numbers})."
        elif self.matched:
            tail = "Detection severity below High — recorded as alert(s), no incident created."
        else:
            tail = "No rule matched."
        return (f"{self.run.scenario_id} generated {len(self.events)} event(s); "
                f"{len(self.matched)} rule match(es). {tail}")


def list_scenarios() -> list[ScenarioRead]:
    out = []
    for s in SCENARIOS:
        rule = detection_service.RULES_BY_ID[s.expected_rule_id]
        out.append(ScenarioRead(
            scenario_id=s.scenario_id, name=s.name, description=s.description,
            expected_rule_id=rule.rule_id, expected_rule_name=rule.name, expected_severity=rule.severity,
            creates_incident=rule.to_read().creates_incident,
            event_count=s.event_count,
            source_description=s.source_description, destination_description=s.destination_description,
        ))
    return out


def process_event(
    db: Session, event: SecurityEvent, *, at: datetime | None = None, audit_detections: bool = True
) -> ProcessOutcome:
    """Steps 5–9 for one persisted event. Safe to call repeatedly for the same event."""
    at = at or utcnow()
    outcome = ProcessOutcome(event=event)
    for detection, created in detection_service.process_event(db, event, at=at):
        outcome.detections.append(detection)
        if created and audit_detections:
            audit_service.record(
                db, actor=settings.system_actor,
                action="detection.matched" if detection.matched else "detection.no_match",
                entity_type="detection", entity_id=detection.id, timestamp=at,
                details={"rule_id": detection.rule_id, "severity": detection.severity,
                         "event_id": event.id, "matched": detection.matched},
            )
        if not detection.matched:
            continue
        outcome.matched.append(detection)
        rule = detection_service.RULES_BY_ID[detection.rule_id]
        asset_ids = detection_service.risk_context_asset_ids(db, event, detection)
        context = risk_service.get_risk_context(db, asset_ids, rule.related_threat_codes, rule.related_vulnerability_codes)
        outcome.risk_ids.extend(r.id for r in context)
        incident, created_incident = incident_service.create_from_detection(
            db, detection, event,
            affected_asset_ids=asset_ids,
            contributing_event_ids=list((detection.evidence or {}).get("contributing_event_ids", [])),
            actor=settings.system_actor, at=at,
        )
        if created_incident and incident is not None:
            outcome.incidents_created.append(incident)
    return outcome


def _branch_by_code(db: Session, code: str) -> Branch:
    branch = db.scalar(select(Branch).where(Branch.code == code))
    if branch is None:
        raise NotFoundError(f"Branch '{code}' was not found. Has the data been seeded?")
    return branch


def run_scenario(
    db: Session,
    scenario_id: str,
    branch_code: str,
    *,
    actor: str,
    now: datetime | None = None,
    commit: bool = True,
) -> TriggerResult:
    scenario = SCENARIOS_BY_ID.get(scenario_id)
    if scenario is None:
        raise NotFoundError(f"Scenario '{scenario_id}' does not exist. Valid scenarios: S1–S8.")
    branch = _branch_by_code(db, branch_code)
    now = now or utcnow()
    try:
        run = SimulationRun(scenario_id=scenario.scenario_id, scenario_name=scenario.name, branch_id=branch.id,
                            triggered_by=actor, status="running", started_at=now)
        db.add(run)
        db.flush()

        events: list[SecurityEvent] = []
        matched: list[Detection] = []
        incidents: list[Incident] = []
        for draft in scenario.build(build_context(db, branch, now)):
            draft.simulation_run_id = run.id
            event = event_service.create_event(db, draft, created_at=now)
            audit_service.record(
                db, actor=settings.system_actor, action="event.created", entity_type="security_event",
                entity_id=event.id, timestamp=now,
                details={"event_type": event.event_type, "scenario_id": event.scenario_id,
                         "simulation_run_id": run.id, "is_simulated": True, "branch": branch.code},
            )
            outcome = process_event(db, event, at=now)
            events.append(event)
            matched.extend(outcome.matched)
            incidents.extend(outcome.incidents_created)

        run.status = "completed"
        run.event_count = len(events)
        run.matched_detection_count = len(matched)
        run.incident_count = len(incidents)
        run.completed_at = now
        audit_service.record(
            db, actor=actor, action="simulation.triggered", entity_type="simulation_run", entity_id=run.id,
            timestamp=now,
            details={"scenario_id": scenario.scenario_id, "scenario_name": scenario.name, "branch": branch.code,
                     "event_count": len(events), "matched_detections": len(matched),
                     "incidents_created": [i.incident_number for i in incidents]},
        )
        db.flush()
        if commit:
            db.commit()
    except Exception:
        db.rollback()
        raise
    return TriggerResult(run=run, events=events, matched=matched, incidents=incidents)


def persist_baseline(db: Session, drafts: list[EventDraft]) -> int:
    """Persist benign baseline events and evaluate them (seed only; no commit)."""
    for draft in drafts:
        event = event_service.create_event(db, draft, created_at=draft.occurred_at)
        process_event(db, event, at=draft.occurred_at, audit_detections=False)
    return len(drafts)


def run_to_read(run: SimulationRun, branch_codes: dict[str, str]) -> SimulationRunRead:
    return SimulationRunRead(
        id=run.id, scenario_id=run.scenario_id, scenario_name=run.scenario_name, branch_id=run.branch_id,
        branch_code=branch_codes.get(run.branch_id, "?"), triggered_by=run.triggered_by, status=run.status,
        event_count=run.event_count, matched_detection_count=run.matched_detection_count,
        incident_count=run.incident_count, started_at=run.started_at, completed_at=run.completed_at,
    )


def list_history(db: Session, page: PageParams) -> tuple[list[SimulationRunRead], int]:
    stmt = select(SimulationRun).order_by(SimulationRun.started_at.desc(), SimulationRun.id)
    items, total = paginate(db, stmt, page)
    codes = dict(db.execute(select(Branch.id, Branch.code)).all())
    return [run_to_read(r, codes) for r in items], total
