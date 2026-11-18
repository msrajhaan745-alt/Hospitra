"""Command Centre aggregates. Every number is computed from persisted records."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.constants import (
    ACTIVE_INCIDENT_STATUSES,
    SEVERITY_ORDER,
    AssetStatus,
    IncidentStatus,
    Severity,
)
from app.core.time import utcnow
from app.models import Asset, Branch, Detection, Incident, NetworkZone, Risk, SecurityEvent
from app.services import audit_service, detection_service
from app.services.common import PageParams

SEVERITIES = [s.value for s in Severity]


def _incident_rows(db: Session, branch_id: str | None):
    stmt = (
        select(Incident.severity, Incident.status, SecurityEvent.branch_id)
        .join(Detection, Incident.detection_id == Detection.id)
        .join(SecurityEvent, Detection.event_id == SecurityEvent.id)
    )
    if branch_id:
        stmt = stmt.where(SecurityEvent.branch_id == branch_id)
    return db.execute(stmt).all()


def branch_posture(open_by_severity: Counter, warning_assets: int, offline_assets: int, alerts_24h: int) -> tuple[str, str]:
    """Derived, transparent branch status label (documented in docs/ARCHITECTURE.md)."""
    if open_by_severity.get(Severity.CRITICAL, 0):
        return "Critical", "Open Critical incident"
    reasons = []
    if open_by_severity.get(Severity.HIGH, 0):
        reasons.append(f"{open_by_severity[Severity.HIGH]} open High incident(s)")
    if offline_assets:
        reasons.append(f"{offline_assets} asset(s) offline")
    if warning_assets:
        reasons.append(f"{warning_assets} asset(s) with warnings")
    if alerts_24h:
        reasons.append(f"{alerts_24h} detection(s) in 24 h")
    if reasons:
        return "Elevated", "; ".join(reasons)
    return "Normal", "No open incidents, asset warnings or recent detections"


def summary(db: Session, branch_id: str | None = None) -> dict:
    now = utcnow()
    day_ago = now - timedelta(hours=24)

    asset_stmt = select(Asset.branch_id, Asset.status, func.count()).group_by(Asset.branch_id, Asset.status)
    asset_rows = db.execute(asset_stmt).all()
    assets_by_branch: dict[str, Counter] = defaultdict(Counter)
    for b_id, status, n in asset_rows:
        assets_by_branch[b_id][status] += n
    scoped_assets = Counter()
    for b_id, counter in assets_by_branch.items():
        if branch_id is None or b_id == branch_id:
            scoped_assets.update(counter)

    incident_rows = _incident_rows(db, None)
    open_by_branch: dict[str, Counter] = defaultdict(Counter)
    for sev, status, b_id in incident_rows:
        if status in ACTIVE_INCIDENT_STATUSES:
            open_by_branch[b_id][sev] += 1
    scoped_incidents = [r for r in incident_rows if branch_id is None or r[2] == branch_id]
    open_scoped = Counter(sev.value for sev, status, _ in scoped_incidents if status in ACTIVE_INCIDENT_STATUSES)
    status_scoped = Counter(status.value for _, status, _ in scoped_incidents)
    severity_scoped = Counter(sev.value for sev, _, _ in scoped_incidents)

    def _event_count(*conds) -> int:
        stmt = select(func.count()).select_from(SecurityEvent).where(*conds)
        if branch_id:
            stmt = stmt.where(SecurityEvent.branch_id == branch_id)
        return db.scalar(stmt) or 0

    def _matched_count(*conds) -> int:
        stmt = (select(func.count()).select_from(Detection).join(SecurityEvent, Detection.event_id == SecurityEvent.id)
                .where(Detection.matched.is_(True), *conds))
        if branch_id:
            stmt = stmt.where(SecurityEvent.branch_id == branch_id)
        return db.scalar(stmt) or 0

    alerts_24h_by_branch = dict(db.execute(
        select(SecurityEvent.branch_id, func.count()).select_from(Detection)
        .join(SecurityEvent, Detection.event_id == SecurityEvent.id)
        .where(Detection.matched.is_(True), SecurityEvent.occurred_at >= day_ago)
        .group_by(SecurityEvent.branch_id)
    ).all())

    matched_total = _matched_count()
    incident_detection_count = len(scoped_incidents)

    branches = []
    for b in db.scalars(select(Branch).order_by(Branch.code)):
        counts = assets_by_branch.get(b.id, Counter())
        open_sev = open_by_branch.get(b.id, Counter())
        posture, reason = branch_posture(
            open_sev, counts.get(AssetStatus.WARNING, 0), counts.get(AssetStatus.OFFLINE, 0),
            alerts_24h_by_branch.get(b.id, 0),
        )
        highest = max(open_sev, key=lambda s: SEVERITY_ORDER[s]).value if open_sev else None
        branches.append({
            "id": b.id, "code": b.code, "name": b.name, "role": b.role, "site_id": b.site_id,
            "assets_total": sum(counts.values()),
            "assets_by_status": {s.value: counts.get(s, 0) for s in AssetStatus},
            "open_incidents": sum(open_sev.values()),
            "highest_open_severity": highest,
            "detections_24h": alerts_24h_by_branch.get(b.id, 0),
            "posture": posture,
            "posture_reason": reason,
        })

    zone_stmt = (select(NetworkZone.name, NetworkZone.vlan_id, func.count(Asset.id))
                 .join(Asset, Asset.zone_id == NetworkZone.id)
                 .group_by(NetworkZone.name, NetworkZone.vlan_id).order_by(NetworkZone.vlan_id))
    if branch_id:
        zone_stmt = zone_stmt.where(Asset.branch_id == branch_id)

    recent_detections, _ = detection_service.list_detections(
        db, PageParams(limit=8, offset=0), matched=True, branch_id=branch_id
    )
    # Sign-in/out events are in the audit log but are not security activity for the Command Centre feed.
    activity, _ = audit_service.list_audit(db, PageParams(limit=12, offset=0), exclude_action_prefix="auth.")

    risk_stmt = select(Risk.severity, func.count()).join(Asset, Risk.asset_id == Asset.id).group_by(Risk.severity)
    residual_stmt = (select(Risk.residual_severity, func.count()).join(Asset, Risk.asset_id == Asset.id)
                     .group_by(Risk.residual_severity))
    if branch_id:
        risk_stmt = risk_stmt.where(Asset.branch_id == branch_id)
        residual_stmt = residual_stmt.where(Asset.branch_id == branch_id)
    risk_counts = {s.value: n for s, n in db.execute(risk_stmt).all()}
    residual_counts = {s.value: n for s, n in db.execute(residual_stmt).all()}

    return {
        "generated_at": now,
        "branch_id": branch_id,
        "assets": {
            "total": sum(scoped_assets.values()),
            "active": scoped_assets.get(AssetStatus.ACTIVE, 0),
            "warning": scoped_assets.get(AssetStatus.WARNING, 0),
            "offline": scoped_assets.get(AssetStatus.OFFLINE, 0),
            "maintenance": scoped_assets.get(AssetStatus.MAINTENANCE, 0),
        },
        "incidents": {
            "total": len(scoped_incidents),
            "open_total": sum(open_scoped.values()),
            "open_by_severity": {s: open_scoped.get(s, 0) for s in SEVERITIES},
            "by_severity": {s: severity_scoped.get(s, 0) for s in SEVERITIES},
            "by_status": {s.value: status_scoped.get(s.value, 0) for s in IncidentStatus},
        },
        "events": {"total": _event_count(), "last_24h": _event_count(SecurityEvent.occurred_at >= day_ago)},
        "detections": {
            "matched_total": matched_total,
            "matched_last_24h": _matched_count(SecurityEvent.occurred_at >= day_ago),
            "alerts_without_incident": max(matched_total - incident_detection_count, 0),
        },
        "risks": {
            "total": sum(risk_counts.values()),
            "by_severity": {s: risk_counts.get(s, 0) for s in SEVERITIES},
            "residual_by_severity": {s: residual_counts.get(s, 0) for s in SEVERITIES},
        },
        "recent_detections": [d.model_dump() for d in recent_detections],
        "branches": branches,
        "asset_distribution": {
            "by_branch": [{"code": b["code"], "name": b["name"], "count": b["assets_total"]} for b in branches
                          if branch_id is None or b["id"] == branch_id],
            "by_zone": [{"zone": name, "vlan_id": vlan, "count": n} for name, vlan, n in db.execute(zone_stmt).all()],
        },
        "recent_activity": [
            {"id": a.id, "actor": a.actor, "action": a.action, "entity_type": a.entity_type,
             "entity_id": a.entity_id, "details": a.details, "timestamp": a.timestamp}
            for a in activity
        ],
    }


def event_trends(db: Session, days: int = 7, branch_id: str | None = None) -> dict:
    now = utcnow()
    start_day = (now - timedelta(days=days - 1)).date()
    stmt = select(SecurityEvent.occurred_at, SecurityEvent.severity).where(
        SecurityEvent.occurred_at >= now.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=days - 1)
    )
    if branch_id:
        stmt = stmt.where(SecurityEvent.branch_id == branch_id)
    buckets: dict = {start_day + timedelta(days=i): Counter() for i in range(days)}
    for occurred_at, severity in db.execute(stmt).all():
        day = occurred_at.date()
        if day in buckets:
            buckets[day][severity.value] += 1

    det_stmt = (select(SecurityEvent.occurred_at).select_from(Detection)
                .join(SecurityEvent, Detection.event_id == SecurityEvent.id)
                .where(Detection.matched.is_(True)))
    if branch_id:
        det_stmt = det_stmt.where(SecurityEvent.branch_id == branch_id)
    detections = Counter(ts.date() for ts in db.scalars(det_stmt))

    series = []
    for day, counter in buckets.items():
        series.append({"date": day.isoformat(), **{s: counter.get(s, 0) for s in SEVERITIES},
                       "total": sum(counter.values()), "detections": detections.get(day, 0)})
    return {"days": days, "branch_id": branch_id, "bucket": "day (UTC)", "series": series}


def risk_distribution(db: Session, branch_id: str | None = None) -> dict:
    stmt = (select(Risk.severity, Risk.likelihood, Risk.overall_impact, Branch.code, Risk.residual_severity)
            .join(Asset, Risk.asset_id == Asset.id).join(Branch, Asset.branch_id == Branch.id))
    if branch_id:
        stmt = stmt.where(Asset.branch_id == branch_id)
    rows = db.execute(stmt).all()
    by_sev = Counter(r[0].value for r in rows)
    by_residual = Counter(r[4].value for r in rows)
    by_branch: dict[str, Counter] = defaultdict(Counter)
    matrix = [[0] * 5 for _ in range(5)]  # [likelihood-1][impact-1]
    for severity, likelihood, impact, code, _residual in rows:
        by_branch[code][severity.value] += 1
        matrix[likelihood - 1][impact - 1] += 1
    return {
        "branch_id": branch_id,
        "total": len(rows),
        "by_severity": {s: by_sev.get(s, 0) for s in SEVERITIES},
        "residual_by_severity": {s: by_residual.get(s, 0) for s in SEVERITIES},
        "by_branch": [{"branch_code": code, **{s: c.get(s, 0) for s in SEVERITIES}} for code, c in sorted(by_branch.items())],
        "matrix": {"rows": "likelihood 1–5", "columns": "impact 1–5", "counts": matrix},
    }
