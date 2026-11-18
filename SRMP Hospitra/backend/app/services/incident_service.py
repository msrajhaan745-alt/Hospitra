"""Incident management.

Creation policy (spec §10.5): an incident is created automatically ONLY for matched
detections of High or Critical severity. Low and Moderate detections stay visible as
alerts. ``incidents.detection_id`` is UNIQUE, so re-processing an event/detection can never
create a second incident.

Lifecycle: Open → Investigating → Contained → Resolved → Closed, one step at a time.
"Contained" is a recorded state only: Hospitra never isolates hosts, disables accounts or
changes any network configuration.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, joinedload, selectinload

from app.core.constants import (
    INCIDENT_SEVERITIES,
    INCIDENT_TRANSITIONS,
    IncidentStatus,
    NoteType,
)
from app.core.exceptions import ConflictError, InvalidTransitionError, NotFoundError
from app.core.time import utcnow
from app.models import Asset, Detection, Incident, IncidentNote, SecurityEvent
from app.schemas.incident import IncidentDetail, IncidentNoteRead, IncidentRead, IncidentUpdate
from app.services import audit_service
from app.services.asset_service import asset_to_read
from app.services.common import PageParams, paginate

ORIGIN_NOTE = "Opened automatically from a rule-based detection."


def should_create_incident(detection: Detection) -> bool:
    return bool(detection.matched) and detection.severity in INCIDENT_SEVERITIES


def next_incident_number(db: Session) -> str:
    numbers = db.scalars(select(Incident.incident_number)).all()
    highest = max((int(n.split("-")[1]) for n in numbers if n.startswith("INC-")), default=0)
    return f"INC-{highest + 1:04d}"


def create_from_detection(
    db: Session,
    detection: Detection,
    event: SecurityEvent,
    *,
    affected_asset_ids: list[str],
    contributing_event_ids: list[str],
    actor: str,
    at: datetime | None = None,
) -> tuple[Incident | None, bool]:
    """Return (incident, created). Applies the High/Critical policy and is idempotent."""
    if not should_create_incident(detection):
        return None, False
    existing = db.scalar(select(Incident).where(Incident.detection_id == detection.id))
    if existing is not None:
        return existing, False

    at = at or utcnow()
    target = detection.asset or event.destination_asset or event.source_asset
    where = target.asset_tag if target else (event.source_zone.name if event.source_zone else "unknown location")
    incident = Incident(
        incident_number=next_incident_number(db),
        title=f"{detection.rule_name} — {where} (Branch {event.branch.code})",
        description=f"{detection.explanation}\n\n{ORIGIN_NOTE}",
        severity=detection.severity,
        status=IncidentStatus.OPEN,
        detection_id=detection.id,
        created_at=at,
        updated_at=at,
    )
    event_ids = list(dict.fromkeys([*contributing_event_ids, event.id]))
    incident.events = list(db.scalars(select(SecurityEvent).where(SecurityEvent.id.in_(event_ids))))
    if affected_asset_ids:
        incident.assets = list(db.scalars(select(Asset).where(Asset.id.in_(affected_asset_ids))))
    db.add(incident)
    db.flush()
    audit_service.record(
        db, actor=actor, action="incident.created", entity_type="incident", entity_id=incident.id, timestamp=at,
        details={
            "incident_number": incident.incident_number, "severity": incident.severity,
            "detection_id": detection.id, "rule_id": detection.rule_id, "event_id": event.id,
            "policy": "auto-created: detection severity is High or Critical",
        },
    )
    return incident, True


# ---- read models ---------------------------------------------------------------------------

_LOAD = (
    joinedload(Incident.detection).joinedload(Detection.event).joinedload(SecurityEvent.branch),
    selectinload(Incident.assets),
    selectinload(Incident.events),
    selectinload(Incident.notes),
)


def incident_to_read(incident: Incident) -> IncidentRead:
    detection = incident.detection
    return IncidentRead(
        id=incident.id,
        incident_number=incident.incident_number,
        title=incident.title,
        description=incident.description,
        severity=incident.severity,
        status=incident.status,
        assigned_to=incident.assigned_to,
        resolution_notes=incident.resolution_notes,
        detection_id=incident.detection_id,
        rule_id=detection.rule_id,
        rule_name=detection.rule_name,
        branch_code=detection.event.branch.code if detection.event else None,
        asset_tags=[a.asset_tag for a in incident.assets],
        event_count=len(incident.events),
        allowed_next_status=INCIDENT_TRANSITIONS[incident.status],
        created_at=incident.created_at,
        updated_at=incident.updated_at,
        resolved_at=incident.resolved_at,
        closed_at=incident.closed_at,
    )


def get_incident_model(db: Session, incident_id: str) -> Incident:
    incident = db.get(Incident, incident_id, options=list(_LOAD))
    if incident is None:
        raise NotFoundError(f"Incident '{incident_id}' was not found.")
    return incident


def list_incidents(
    db: Session,
    page: PageParams,
    *,
    search: str | None = None,
    status: str | None = None,
    severity: str | None = None,
    branch_id: str | None = None,
    active_only: bool = False,
) -> tuple[list[IncidentRead], int]:
    stmt = (
        select(Incident)
        .join(Detection, Incident.detection_id == Detection.id)
        .join(SecurityEvent, Detection.event_id == SecurityEvent.id)
        .options(*_LOAD)
    )
    if search:
        term = f"%{search.strip()}%"
        stmt = stmt.where(or_(Incident.incident_number.ilike(term), Incident.title.ilike(term),
                              Incident.assigned_to.ilike(term)))
    if status:
        stmt = stmt.where(Incident.status == status)
    if active_only:
        stmt = stmt.where(Incident.status.in_([IncidentStatus.OPEN, IncidentStatus.INVESTIGATING, IncidentStatus.CONTAINED]))
    if severity:
        stmt = stmt.where(Incident.severity == severity)
    if branch_id:
        stmt = stmt.where(SecurityEvent.branch_id == branch_id)
    stmt = stmt.order_by(Incident.created_at.desc(), Incident.incident_number.desc())
    items, total = paginate(db, stmt, page)
    return [incident_to_read(i) for i in items], total


def build_detail(db: Session, incident: Incident, *, events, detection, risk_context) -> IncidentDetail:
    history, _ = audit_service.list_audit(db, PageParams(limit=200, offset=0), entity_type="incident", entity_id=incident.id)
    data =incident_to_read(incident).model_dump()
    return IncidentDetail(
        **data,
        notes=[IncidentNoteRead.model_validate(n) for n in incident.notes],
        events=events,
        assets=[asset_to_read(a) for a in incident.assets],
        detection=detection,
        risk_context=risk_context,
        history=[
            {"id": h.id, "action": h.action, "actor": h.actor, "details": h.details, "timestamp": h.timestamp}
            for h in reversed(history)
        ],
    )


# ---- updates -------------------------------------------------------------------------------

def update_incident(
    db: Session, incident_id: str, payload: IncidentUpdate, actor: str, *, at: datetime | None = None
) -> Incident:
    incident = get_incident_model(db, incident_id)
    at = at or utcnow()
    fields = payload.model_fields_set

    if incident.status == IncidentStatus.CLOSED:
        raise ConflictError(
            f"Incident {incident.incident_number} is Closed and can no longer be modified.",
            {"current_status": incident.status.value},
        )

    if "status" in fields and payload.status is not None:
        expected = INCIDENT_TRANSITIONS[incident.status]
        if payload.status != expected:
            raise InvalidTransitionError(
                f"Cannot change status from {incident.status.value} to {payload.status.value}.",
                {
                    "current_status": incident.status.value,
                    "requested_status": payload.status.value,
                    "allowed_next_status": expected.value if expected else None,
                    "lifecycle": [s.value for s in IncidentStatus],
                },
            )

    changed = False
    if "assigned_to" in fields and payload.assigned_to != incident.assigned_to:
        audit_service.record(db, actor=actor, action="incident.assigned", entity_type="incident",
                             entity_id=incident.id, timestamp=at,
                             details={"incident_number": incident.incident_number,
                                      "from": incident.assigned_to, "to": payload.assigned_to})
        incident.assigned_to = payload.assigned_to
        changed = True

    if payload.note is not None:
        note = IncidentNote(incident_id=incident.id, note_type=payload.note.note_type, body=payload.note.body,
                            author=actor, created_at=at)
        incident.notes.append(note)
        if payload.note.note_type == NoteType.RESOLUTION:
            incident.resolution_notes = (
                f"{incident.resolution_notes}\n\n{payload.note.body}" if incident.resolution_notes else payload.note.body
            )
        audit_service.record(db, actor=actor, action="incident.note_added", entity_type="incident",
                             entity_id=incident.id, timestamp=at,
                             details={"incident_number": incident.incident_number,
                                      "note_type": payload.note.note_type, "length": len(payload.note.body)})
        changed = True

    if "status" in fields and payload.status is not None:
        previous = incident.status
        incident.status = payload.status
        if payload.status == IncidentStatus.RESOLVED:
            incident.resolved_at = at
        if payload.status == IncidentStatus.CLOSED:
            incident.closed_at = at
        details = {"incident_number": incident.incident_number, "from": previous, "to": payload.status}
        if payload.status == IncidentStatus.CONTAINED:
            details["note"] = "Containment recorded only; no host, account or network change was performed."
        audit_service.record(db, actor=actor, action="incident.status_changed", entity_type="incident",
                             entity_id=incident.id, timestamp=at, details=details)
        changed = True

    if changed:
        incident.updated_at = at
        db.flush()
    return incident


def open_incident_counts(db: Session) -> dict[str, int]:
    stmt = (
        select(Incident.severity, func.count())
        .where(Incident.status.in_([IncidentStatus.OPEN, IncidentStatus.INVESTIGATING, IncidentStatus.CONTAINED]))
        .group_by(Incident.severity)
    )
    return {s.value: n for s, n in db.execute(stmt).all()}
