"""Composite read views that join events, detections, rules, risk context and incidents.

Kept separate so that the individual services stay single-purpose and free of import cycles.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Incident
from app.schemas.detection import DetectionDetail
from app.schemas.incident import IncidentDetail
from app.schemas.security_event import EventDetail
from app.services import detection_service, event_service, incident_service, risk_service


def _rule_context(db: Session, event, detection) -> list:
    rule = detection_service.RULES_BY_ID.get(detection.rule_id)
    if rule is None:
        return []
    asset_ids = detection_service.risk_context_asset_ids(db, event, detection)
    return risk_service.get_risk_context(db, asset_ids, rule.related_threat_codes, rule.related_vulnerability_codes)


def event_detail(db: Session, event_id: str) -> EventDetail:
    event = event_service.get_event(db, event_id)
    base = event_service.event_to_read(event).model_dump()
    detections = sorted(event.detections, key=lambda d: d.rule_id)
    incidents = detection_service.incidents_by_detection(db, [d.id for d in detections])
    detection_reads = []
    for d in detections:
        d_full = detection_service.get_detection(db, d.id)
        detection_reads.append(detection_service.detection_to_read(d_full, incidents.get(d.id)))

    risk_context, seen = [], set()
    for d in detections:
        if d.matched:
            for r in _rule_context(db, event, d):
                if r.id not in seen:
                    seen.add(r.id)
                    risk_context.append(r)

    incident = next(iter(incidents.values()), None)
    if incident is None:
        incident = db.scalar(select(Incident).where(Incident.events.any(id=event.id)))
    rules = [detection_service.RULES_BY_ID[d.rule_id].to_read() for d in detections
             if d.rule_id in detection_service.RULES_BY_ID]
    if not rules:
        rules = [r.to_read() for r in detection_service.applicable_rules(event.event_type)]
    return EventDetail(
        **base,
        detections=detection_reads,
        rules=rules,
        risk_context=risk_context,
        incident=(
            {"id": incident.id, "incident_number": incident.incident_number, "status": incident.status.value,
             "severity": incident.severity.value, "title": incident.title}
            if incident else None
        ),
    )


def detection_detail(db: Session, detection_id: str) -> DetectionDetail:
    d = detection_service.get_detection(db, detection_id)
    incident = detection_service.incidents_by_detection(db, [d.id]).get(d.id)
    base = detection_service.detection_to_read(d, incident).model_dump()
    rule = detection_service.RULES_BY_ID.get(d.rule_id)
    event = event_service.get_event(db, d.event_id)
    return DetectionDetail(
        **base,
        rule=rule.to_read() if rule else None,
        risk_context=_rule_context(db, event, d) if d.matched else [],
    )


def incident_detail(db: Session, incident_id: str) -> IncidentDetail:
    incident = incident_service.get_incident_model(db, incident_id)
    detection = detection_service.get_detection(db, incident.detection_id)
    trigger_event = event_service.get_event(db, detection.event_id)
    events = [event_service.event_to_read(event_service.get_event(db, e.id)) for e in incident.events]
    return incident_service.build_detail(
        db, incident,
        events=events,
        detection=detection_service.detection_to_read(detection, incident),
        risk_context=_rule_context(db, trigger_event, detection),
    )
