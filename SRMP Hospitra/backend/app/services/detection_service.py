"""Deterministic, rule-based detection engine (spec §10.2).

Each rule evaluates one persisted event (plus, for threshold rules, earlier persisted
events in a fixed time window) and returns a match result, evidence and a human-readable
explanation. There is no machine learning, scoring model or external lookup.

A matched detection is an INVESTIGATION LEAD, not proof of malicious activity.

Threshold rules (R2, R7) fire once per source per evaluation window: if a matched
detection for the same rule and source already exists within ±window of the event, the
event is recorded as non-matching with an explicit "suppressed" explanation. This prevents
a single burst from producing a flood of duplicate detections.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.core.constants import (
    GUEST_RESTRICTED_ZONE_TYPES,
    INCIDENT_SEVERITIES,
    SENSITIVE_ZONE_TYPES,
    SEVERITY_ORDER,
    EventType,
    Severity,
    ZoneType,
)
from app.core.exceptions import NotFoundError
from app.core.time import ensure_utc, utcnow
from app.models import Asset, Detection, Incident, SecurityEvent
from app.schemas.detection import DetectionEventBrief, DetectionRead, RuleRead
from app.services.common import PageParams, paginate
from app.services.risk_service import zone_asset_ids


@dataclass(frozen=True)
class RuleResult:
    matched: bool
    explanation: str
    evidence: dict[str, Any]
    asset_id: str | None = None


@dataclass(frozen=True)
class Rule:
    rule_id: str
    name: str
    description: str
    event_types: tuple[EventType, ...]
    conditions: tuple[str, ...]
    severity: Severity
    explanation_template: str
    related_threat_codes: tuple[str, ...]
    related_vulnerability_codes: tuple[str, ...]
    scenario_ids: tuple[str, ...]
    evaluate: Callable[[Session, SecurityEvent, Rule], RuleResult] = field(repr=False, compare=False)
    enabled: bool = True
    params: dict[str, Any] = field(default_factory=dict, compare=False)

    def explain(self, **values: Any) -> str:
        return self.explanation_template.format(**values)

    def to_read(self) -> RuleRead:
        return RuleRead(
            rule_id=self.rule_id, name=self.name, description=self.description,
            event_types=[t.value for t in self.event_types], conditions=list(self.conditions),
            severity=self.severity, explanation_template=self.explanation_template, enabled=self.enabled,
            creates_incident=self.severity in INCIDENT_SEVERITIES,
            related_threat_codes=list(self.related_threat_codes),
            related_vulnerability_codes=list(self.related_vulnerability_codes),
            scenario_ids=list(self.scenario_ids),
        )


# ---- helpers -------------------------------------------------------------------------------

def _label(asset: Asset | None, ip: str | None) -> str:
    if asset is not None:
        return f"{asset.asset_tag} ({asset.name})"
    return ip or "unknown"


def _zone_label(zone) -> str:
    return f"{zone.name} (VLAN {zone.vlan_id})" if zone is not None else "external / none"


def _is_external(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        return not ipaddress.ip_network(ip, strict=False).subnet_of(ipaddress.ip_network("10.0.0.0/8"))
    except (ValueError, TypeError):
        return False


def _md(event: SecurityEvent) -> dict[str, Any]:
    return event.event_metadata or {}


def _same_source_clause(event: SecurityEvent):
    if event.source_asset_id:
        return SecurityEvent.source_asset_id == event.source_asset_id
    return SecurityEvent.source_ip == event.source_ip


def _window_events(db: Session, event: SecurityEvent, event_type: EventType, window: int) -> list[SecurityEvent]:
    start = event.occurred_at - timedelta(seconds=window)
    stmt = (
        select(SecurityEvent)
        .where(
            SecurityEvent.event_type == event_type,
            _same_source_clause(event),
            SecurityEvent.occurred_at >= start,
            SecurityEvent.occurred_at <= event.occurred_at,
        )
        .order_by(SecurityEvent.occurred_at, SecurityEvent.created_at)
    )
    return list(db.scalars(stmt))


def _prior_match_in_window(db: Session, event: SecurityEvent, rule_id: str, window: int) -> Detection | None:
    """An already-recorded match for the same rule and source within ±window of this event.

    The check is symmetric because synthetic scenarios back-date their events, so events
    are not always processed in timestamp order.
    """
    start = event.occurred_at - timedelta(seconds=window)
    end = event.occurred_at + timedelta(seconds=window)
    stmt = (
        select(Detection)
        .join(SecurityEvent, Detection.event_id == SecurityEvent.id)
        .where(
            Detection.rule_id == rule_id,
            Detection.matched.is_(True),
            SecurityEvent.id != event.id,
            _same_source_clause(event),
            SecurityEvent.occurred_at >= start,
            SecurityEvent.occurred_at <= end,
        )
        .limit(1)
    )
    return db.scalar(stmt)


# ---- rule evaluators -------------------------------------------------------------------------

def _eval_guest_access(db: Session, e: SecurityEvent, rule: Rule) -> RuleResult:
    src_zone, dst_zone = e.source_zone, e.destination_zone
    evidence = {
        "source": _label(e.source_asset, e.source_ip),
        "source_zone": _zone_label(src_zone),
        "destination": _label(e.destination_asset, e.destination_ip),
        "destination_zone": _zone_label(dst_zone),
        "protocol": _md(e).get("protocol"),
        "destination_port": _md(e).get("destination_port"),
        "firewall_action": _md(e).get("firewall_action"),
        "policy": "Guest Wi-Fi is internet-only; access to private hospital zones is not permitted.",
    }
    if src_zone is None or src_zone.zone_type != ZoneType.GUEST:
        return RuleResult(False, "No violation: the source is not in the Guest Wi-Fi zone.", evidence)
    if dst_zone is None or dst_zone.zone_type not in GUEST_RESTRICTED_ZONE_TYPES:
        return RuleResult(False, "No violation: the destination is not a restricted private hospital zone "
                                 "(internet or DMZ destinations are permitted for guests).", evidence)
    return RuleResult(True, rule.explain(**evidence), evidence, e.destination_asset_id or e.source_asset_id)


def _eval_auth_failures(db: Session, e: SecurityEvent, rule: Rule) -> RuleResult:
    threshold, window = rule.params["threshold"], rule.params["window_seconds"]
    events = _window_events(db, e, EventType.AUTH_FAILURE, window)
    evidence = {
        "source": _label(e.source_asset, e.source_ip),
        "target": _label(e.destination_asset, e.destination_ip),
        "account": _md(e).get("account"),
        "failure_count": len(events),
        "threshold": threshold,
        "window_seconds": window,
        "contributing_event_ids": [x.id for x in events],
    }
    if len(events) < threshold:
        return RuleResult(False, f"Below threshold: {len(events)} failed authentication(s) from this source in "
                                 f"the last {window} s (threshold {threshold}).", evidence)
    prior = _prior_match_in_window(db, e, rule.rule_id, window)
    if prior is not None:
        evidence["suppressed_by_detection_id"] = prior.id
        return RuleResult(False, f"Suppressed: this rule already matched for the same source within the "
                                 f"{window} s window (detection {prior.id[:8]}).", evidence)
    return RuleResult(True, rule.explain(**evidence), evidence, e.source_asset_id or e.destination_asset_id)


def _eval_vpn_login(db: Session, e: SecurityEvent, rule: Rule) -> RuleResult:
    md = _md(e)
    approved = md.get("approved_regions") or []
    reasons = []
    if md.get("login_region") not in approved:
        reasons.append(f"login region '{md.get('login_region')}' is not an approved region "
                       f"({', '.join(approved) or 'none defined'})")
    if md.get("device_posture") != "managed":
        reasons.append(f"device posture is '{md.get('device_posture')}' (expected 'managed')")
    evidence = {
        "user": md.get("user"),
        "source_ip": e.source_ip,
        "vpn_gateway": _label(e.destination_asset, e.destination_ip),
        "login_region": md.get("login_region"),
        "approved_regions": approved,
        "device_posture": md.get("device_posture"),
        "mfa_used": md.get("mfa_used"),
        "reasons": reasons,
    }
    if not reasons:
        return RuleResult(False, "No anomaly: login from an approved region on a managed device.", evidence)
    mfa = {True: "yes", False: "no"}.get(md.get("mfa_used"), "unknown")
    return RuleResult(True, rule.explain(**{**evidence, "mfa_used": mfa}, reason_text="; ".join(reasons)), evidence,
                      e.destination_asset_id)


def _eval_unknown_device(db: Session, e: SecurityEvent, rule: Rule) -> RuleResult:
    md = _md(e)
    zone = e.source_zone
    evidence = {
        "observed_ip": e.source_ip,
        "mac_address": md.get("mac_address"),
        "hostname": md.get("hostname"),
        "zone": _zone_label(zone),
        "inventory_match": e.source_asset_id is not None,
        "observed_by": md.get("observed_by"),
    }
    if e.source_asset_id is not None:
        return RuleResult(False, "No violation: the observed device matches a registered inventory asset.", evidence)
    if zone is None or zone.zone_type not in SENSITIVE_ZONE_TYPES:
        return RuleResult(False, "No violation: the device was not observed in a sensitive zone.", evidence)
    return RuleResult(True, rule.explain(**evidence), evidence, None)


def _eval_outbound(db: Session, e: SecurityEvent, rule: Rule) -> RuleResult:
    md = _md(e)
    threshold = rule.params["bytes_threshold"]
    bytes_out = int(md.get("bytes_out") or 0)
    evidence = {
        "source": _label(e.source_asset, e.source_ip),
        "destination_ip": e.destination_ip,
        "destination_external": _is_external(e.destination_ip),
        "bytes_out": bytes_out,
        "megabytes_out": round(bytes_out / 1_048_576, 1),
        "threshold_megabytes": round(threshold / 1_048_576),
        "baseline_megabytes_24h": round(int(md.get("baseline_bytes_out_24h") or 0) / 1_048_576, 1),
        "protocol": md.get("protocol"),
    }
    if not evidence["destination_external"]:
        return RuleResult(False, "No anomaly: the destination is inside the hospital address space.", evidence)
    if bytes_out < threshold:
        return RuleResult(False, f"No anomaly: {evidence['megabytes_out']} MB is below the "
                                 f"{evidence['threshold_megabytes']} MB threshold.", evidence)
    return RuleResult(True, rule.explain(**evidence), evidence, e.source_asset_id)


def _eval_request_volume(db: Session, e: SecurityEvent, rule: Rule) -> RuleResult:
    md = _md(e)
    rpm = int(md.get("requests_per_minute") or 0)
    baseline = max(int(md.get("baseline_requests_per_minute") or 1), 1)
    multiplier = rule.params["baseline_multiplier"]
    zone = e.destination_zone
    evidence = {
        "target": _label(e.destination_asset, e.destination_ip),
        "target_zone": _zone_label(zone),
        "requests_per_minute": rpm,
        "baseline_requests_per_minute": baseline,
        "ratio_to_baseline": round(rpm / baseline, 1),
        "threshold_multiplier": multiplier,
        "distinct_source_ips": md.get("distinct_source_ips"),
        "http_5xx_rate": md.get("http_5xx_rate"),
        "impact_focus": "Availability",
    }
    if zone is None or zone.zone_type != ZoneType.DMZ:
        return RuleResult(False, "Not applicable: the target is not a public-facing (DMZ) service.", evidence)
    if rpm < baseline * multiplier:
        return RuleResult(False, f"No anomaly: {rpm} req/min is below {multiplier}× the baseline of {baseline}.", evidence)
    return RuleResult(True, rule.explain(**evidence), evidence, e.destination_asset_id)


SUSPICIOUS_FILE_OPERATIONS = frozenset({"shadow_copy_delete", "mass_rename", "high_entropy_write", "ransom_note_create"})


def _eval_ransomware(db: Session, e: SecurityEvent, rule: Rule) -> RuleResult:
    threshold, window = rule.params["threshold"], rule.params["window_seconds"]
    window_events = _window_events(db, e, EventType.FILE_ACTIVITY, window)
    suspicious = [x for x in window_events if (x.event_metadata or {}).get("operation") in SUSPICIOUS_FILE_OPERATIONS]
    evidence = {
        "endpoint": _label(e.source_asset, e.source_ip),
        "process": _md(e).get("process"),
        "suspicious_operation_count": len(suspicious),
        "operations": [x.event_metadata.get("operation") for x in suspicious],
        "files_affected_total": sum(int(x.event_metadata.get("files_affected") or 0) for x in suspicious),
        "threshold": threshold,
        "window_seconds": window,
        "contributing_event_ids": [x.id for x in suspicious],
    }
    if len(suspicious) < threshold:
        return RuleResult(False, f"Below threshold: {len(suspicious)} suspicious file operation(s) in the last "
                                 f"{window} s (threshold {threshold}).", evidence)
    prior = _prior_match_in_window(db, e, rule.rule_id, window)
    if prior is not None:
        evidence["suppressed_by_detection_id"] = prior.id
        return RuleResult(False, f"Suppressed: this rule already matched for the same endpoint within the "
                                 f"{window} s window (detection {prior.id[:8]}).", evidence)
    evidence["operation_summary"] = ", ".join(sorted(set(evidence["operations"])))
    return RuleResult(True, rule.explain(**evidence), evidence, e.source_asset_id)


def _eval_vendor_window(db: Session, e: SecurityEvent, rule: Rule) -> RuleResult:
    md = _md(e)
    evidence = {
        "vendor": md.get("vendor"),
        "account": md.get("account"),
        "target": _label(e.destination_asset, e.destination_ip),
        "access_time": e.occurred_at.isoformat(),
        "approved_window_start": md.get("approved_window_start"),
        "approved_window_end": md.get("approved_window_end"),
        "change_ticket": md.get("change_ticket"),
    }
    try:
        start = ensure_utc(datetime.fromisoformat(md["approved_window_start"]))
        end = ensure_utc(datetime.fromisoformat(md["approved_window_end"]))
    except (KeyError, TypeError, ValueError):
        evidence["window_defined"] = False
        return RuleResult(True, rule.explain(**evidence) + " No valid approved window was recorded.", evidence,
                          e.destination_asset_id)
    if start <= e.occurred_at <= end:
        return RuleResult(False, "No violation: vendor access occurred inside the approved window.", evidence)
    return RuleResult(True, rule.explain(**evidence), evidence, e.destination_asset_id)


# ---- rule catalogue (severities per the approved scenario configuration) ------------------

RULES: tuple[Rule, ...] = (
    Rule(
        rule_id="R1", name="Guest-to-restricted-zone access violation",
        description="A device in the Guest Wi-Fi zone attempted to reach a private hospital zone.",
        event_types=(EventType.NETWORK_ACCESS,),
        conditions=("source zone type = guest",
                    "destination zone type ∈ {management, staff, clinical, application, medical, security}"),
        severity=Severity.HIGH,
        explanation_template=("Guest Wi-Fi device {source} in {source_zone} attempted {protocol}/{destination_port} "
                              "access to {destination} in restricted zone {destination_zone} (firewall action: "
                              "{firewall_action}). {policy}"),
        related_threat_codes=("T3", "T1"), related_vulnerability_codes=("V1", "V3"),
        scenario_ids=("S1",), evaluate=_eval_guest_access,
    ),
    Rule(
        rule_id="R2", name="Repeated authentication failures",
        description="Repeated failed authentications from one source within a short evaluation window.",
        event_types=(EventType.AUTH_FAILURE,),
        conditions=("≥ 5 auth_failure events from the same source within 300 s",
                    "no earlier R2 match for the same source inside that window"),
        severity=Severity.MODERATE,
        explanation_template=("{failure_count} failed authentication attempts from {source} against {target} "
                              "(account '{account}') within {window_seconds} s, meeting the threshold of "
                              "{threshold}. This may indicate password guessing or a misconfigured service."),
        related_threat_codes=("T2", "T6"), related_vulnerability_codes=("V2", "V7"),
        scenario_ids=("S2",), evaluate=_eval_auth_failures, params={"threshold": 5, "window_seconds": 300},
    ),
    Rule(
        rule_id="R3", name="Unusual VPN access",
        description="A successful VPN login outside its approved access context.",
        event_types=(EventType.VPN_LOGIN,),
        conditions=("login_region ∉ approved_regions", "OR device_posture ≠ managed"),
        severity=Severity.MODERATE,
        explanation_template=("VPN login by '{user}' from {source_ip} via {vpn_gateway} is outside the approved "
                              "access context: {reason_text}. MFA used: {mfa_used}."),
        related_threat_codes=("T2",), related_vulnerability_codes=("V2",),
        scenario_ids=("S3",), evaluate=_eval_vpn_login,
    ),
    Rule(
        rule_id="R4", name="Unknown device in restricted zone",
        description="A device with no matching inventory record appeared in a sensitive zone.",
        event_types=(EventType.DEVICE_OBSERVED,),
        conditions=("no registered asset matches the observed device",
                    "zone type ∈ {management, clinical, application, medical, security}"),
        severity=Severity.HIGH,
        explanation_template=("Unregistered device {mac_address} ({hostname}) at {observed_ip} was observed in "
                              "sensitive zone {zone} by {observed_by}. It has no matching inventory record."),
        related_threat_codes=("T8", "T3"), related_vulnerability_codes=("V1",),
        scenario_ids=("S4",), evaluate=_eval_unknown_device,
    ),
    Rule(
        rule_id="R5", name="Unusual outbound transfer",
        description="An unusually large data transfer from an internal asset to an external destination.",
        event_types=(EventType.OUTBOUND_TRANSFER,),
        conditions=("destination is outside 10.0.0.0/8", "bytes_out ≥ 500 MB"),
        severity=Severity.HIGH,
        explanation_template=("{source} sent {megabytes_out} MB to external address {destination_ip} over "
                              "{protocol}, exceeding the {threshold_megabytes} MB threshold (24 h baseline: "
                              "{baseline_megabytes_24h} MB)."),
        related_threat_codes=("T6", "T7"), related_vulnerability_codes=("V7", "V5"),
        scenario_ids=("S5",), evaluate=_eval_outbound, params={"bytes_threshold": 500 * 1_048_576},
    ),
    Rule(
        rule_id="R6", name="DDoS-like request volume",
        description="Request volume to a public-facing service far above its baseline (availability).",
        event_types=(EventType.REQUEST_VOLUME,),
        conditions=("target zone type = dmz", "requests_per_minute ≥ 10 × baseline"),
        severity=Severity.HIGH,
        explanation_template=("{target} in {target_zone} received {requests_per_minute} requests/min from "
                              "{distinct_source_ips} source IPs — {ratio_to_baseline}× its baseline of "
                              "{baseline_requests_per_minute}. Impact focus: {impact_focus}."),
        related_threat_codes=("T5",), related_vulnerability_codes=("V5",),
        scenario_ids=("S6",), evaluate=_eval_request_volume, params={"baseline_multiplier": 10},
    ),
    Rule(
        rule_id="R7", name="Ransomware-like behaviour",
        description="A burst of suspicious file operations from a single endpoint.",
        event_types=(EventType.FILE_ACTIVITY,),
        conditions=("≥ 5 suspicious file operations (shadow-copy deletion, mass rename, high-entropy writes, "
                    "ransom-note creation) from one endpoint within 120 s",
                    "no earlier R7 match for the same endpoint inside that window"),
        severity=Severity.CRITICAL,
        explanation_template=("{endpoint} performed {suspicious_operation_count} suspicious file operations "
                              "({operation_summary}) affecting {files_affected_total} files within "
                              "{window_seconds} s via process '{process}'."),
        related_threat_codes=("T1",), related_vulnerability_codes=("V6", "V8", "V1"),
        scenario_ids=("S7",), evaluate=_eval_ransomware, params={"threshold": 5, "window_seconds": 120},
    ),
    Rule(
        rule_id="R8", name="Vendor access policy violation",
        description="Vendor remote access outside its approved maintenance window.",
        event_types=(EventType.VENDOR_ACCESS,),
        conditions=("access time ∉ [approved_window_start, approved_window_end]",),
        severity=Severity.MODERATE,
        explanation_template=("Vendor '{vendor}' account '{account}' accessed {target} at {access_time}, outside "
                              "the approved window {approved_window_start} – {approved_window_end} "
                              "(ticket {change_ticket})."),
        related_threat_codes=("T7",), related_vulnerability_codes=("V7", "V2"),
        scenario_ids=("S8",), evaluate=_eval_vendor_window,
    ),
)

RULES_BY_ID: dict[str, Rule] = {r.rule_id: r for r in RULES}


def applicable_rules(event_type: EventType) -> list[Rule]:
    return [r for r in RULES if r.enabled and event_type in r.event_types]


def evaluate_event(db: Session, event: SecurityEvent) -> list[tuple[Rule, RuleResult]]:
    return [(rule, rule.evaluate(db, event, rule)) for rule in applicable_rules(event.event_type)]


def process_event(db: Session, event: SecurityEvent, *, at: datetime | None = None) -> list[tuple[Detection, bool]]:
    """Evaluate applicable rules and persist one Detection per (event, rule).

    Returns ``(detection, newly_created)`` pairs. Idempotent: if the event has already been
    evaluated by a rule, the existing detection is returned and nothing new is written.
    """
    existing = {d.rule_id: d for d in db.scalars(select(Detection).where(Detection.event_id == event.id))}
    results: list[tuple[Detection, bool]] = []
    for rule in applicable_rules(event.event_type):
        if rule.rule_id in existing:
            results.append((existing[rule.rule_id], False))
            continue
        result = rule.evaluate(db, event, rule)
        detection = Detection(
            event_id=event.id,
            rule_id=rule.rule_id,
            rule_name=rule.name,
            matched=result.matched,
            severity=rule.severity,
            explanation=result.explanation,
            evidence=result.evidence,
            asset_id=result.asset_id,
            created_at=at or utcnow(),
        )
        db.add(detection)
        db.flush()
        results.append((detection, True))
    # Event severity reflects the highest of its reported severity and any matched rule severity.
    for d, _ in results:
        if d.matched and SEVERITY_ORDER[d.severity] > SEVERITY_ORDER[event.severity]:
            event.severity = d.severity
    db.flush()
    return results


# ---- read models ---------------------------------------------------------------------------

def detection_to_read(d: Detection, incident: Incident | None = None) -> DetectionRead:
    e = d.event
    return DetectionRead(
        id=d.id, event_id=d.event_id, rule_id=d.rule_id, rule_name=d.rule_name, matched=d.matched,
        severity=d.severity, explanation=d.explanation, evidence=d.evidence or {}, asset_id=d.asset_id,
        asset_tag=d.asset.asset_tag if d.asset else None, created_at=d.created_at,
        event=DetectionEventBrief(id=e.id, event_type=e.event_type.value, occurred_at=e.occurred_at,
                                  branch_code=e.branch.code, scenario_id=e.scenario_id, message=e.message),
        incident_id=incident.id if incident else None,
        incident_number=incident.incident_number if incident else None,
    )


DETECTION_LOAD = (
    joinedload(Detection.event).joinedload(SecurityEvent.branch),
    joinedload(Detection.asset),
)


def get_detection(db: Session, detection_id: str) -> Detection:
    d = db.get(Detection, detection_id, options=list(DETECTION_LOAD))
    if d is None:
        raise NotFoundError(f"Detection '{detection_id}' was not found.")
    return d


def incidents_by_detection(db: Session, detection_ids: list[str]) -> dict[str, Incident]:
    if not detection_ids:
        return {}
    return {i.detection_id: i for i in db.scalars(select(Incident).where(Incident.detection_id.in_(detection_ids)))}


def list_detections(
    db: Session,
    page: PageParams,
    *,
    matched: bool | None = None,
    rule_id: str | None = None,
    severity: str | None = None,
    branch_id: str | None = None,
    event_id: str | None = None,
    since: datetime | None = None,
) -> tuple[list[DetectionRead], int]:
    stmt = select(Detection).join(SecurityEvent, Detection.event_id == SecurityEvent.id).options(*DETECTION_LOAD)
    if matched is not None:
        stmt = stmt.where(Detection.matched.is_(matched))
    if rule_id:
        stmt = stmt.where(Detection.rule_id == rule_id)
    if severity:
        stmt = stmt.where(Detection.severity == severity)
    if branch_id:
        stmt = stmt.where(SecurityEvent.branch_id == branch_id)
    if event_id:
        stmt = stmt.where(Detection.event_id == event_id)
    if since:
        stmt = stmt.where(SecurityEvent.occurred_at >= since)
    stmt = stmt.order_by(SecurityEvent.occurred_at.desc(), Detection.rule_id)
    items, total = paginate(db, stmt, page)
    incidents = incidents_by_detection(db, [d.id for d in items])
    return [detection_to_read(d, incidents.get(d.id)) for d in items], total


def risk_context_asset_ids(db: Session, event: SecurityEvent, detection: Detection | None = None) -> list[str]:
    """Assets whose illustrative risks are relevant to an event: the detection's asset, the
    event's source/destination assets, or — for unregistered devices — the zone's assets."""
    ids =[x for x in (detection.asset_id if detection else None, event.source_asset_id, event.destination_asset_id) if x]
    if not ids:
        ids = zone_asset_ids(db, event.source_zone_id or event.destination_zone_id)
    return list(dict.fromkeys(ids))
