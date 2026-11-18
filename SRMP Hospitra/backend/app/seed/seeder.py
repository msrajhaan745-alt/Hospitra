"""Idempotent seeding of the dataset.

Every entity is looked up by its natural key (branch code, branch+VLAN, asset tag,
threat/vulnerability code, threat+vulnerability pair, asset+threat+vulnerability) and is
created only if missing. Existing rows — including operator edits — are left untouched,
so re-running the seed never creates duplicates.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.constants import BASELINE_SCENARIO_ID, ZONE_TEMPLATE, AssetStatus, ImplementationStatus
from app.core.time import utcnow
from app.db.base import Base
from app.models import (
    Asset,
    Branch,
    NetworkZone,
    Risk,
    RiskControl,
    SecurityControl,
    SecurityEvent,
    Threat,
    ThreatVulnerabilityPair,
    Vulnerability,
)
from app.schemas.incident import IncidentUpdate, NoteCreate
from app.seed import seed_data
from app.seed.scenarios import baseline_drafts, build_context
from app.services import audit_service, incident_service, risk_service, simulation_service


@dataclass
class SeedReport:
    created: dict[str, int] = field(default_factory=dict)

    def add(self, key: str, n: int = 1) -> None:
        self.created[key] = self.created.get(key, 0) + n

    @property
    def total_created(self) -> int:
        return sum(self.created.values())


def asset_tag(branch_code: str, zone_code: str, n: int) -> str:
    return f"HSP-{branch_code}-{zone_code}-{n:03d}"


def seed_network(db: Session, report: SeedReport, now: datetime) -> None:
    for b in seed_data.BRANCHES:
        branch = db.scalar(select(Branch).where(Branch.code == b["code"]))
        if branch is None:
            branch = Branch(**b, active=True, created_at=now)
            db.add(branch)
            db.flush()
            report.add("branches")

        for z in ZONE_TEMPLATE:
            zone = db.scalar(
                select(NetworkZone).where(NetworkZone.branch_id == branch.id, NetworkZone.vlan_id == z["vlan_id"])
            )
            if zone is None:
                zone = NetworkZone(
                    branch_id=branch.id,
                    name=z["name"],
                    code=z["code"],
                    zone_type=z["zone_type"],
                    vlan_id=z["vlan_id"],
                    subnet_cidr=f"10.{branch.site_id}.{z['vlan_id']}.0/24",
                    description=z["description"],
                )
                db.add(zone)
                db.flush()
                report.add("zones")

            for index, a in enumerate(seed_data.ASSET_TEMPLATE[z["code"]]):
                tag = asset_tag(branch.code, z["code"], a["n"])
                if db.scalar(select(Asset.id).where(Asset.asset_tag == tag)) is not None:
                    continue
                name = a["name"]
                if z["code"] == "MED":
                    name = seed_data.MEDICAL_DEVICE_NAMES[branch.code][a["n"] - 1]
                status = seed_data.STATUS_OVERRIDES.get(tag, AssetStatus.ACTIVE)
                last_seen = {
                    AssetStatus.OFFLINE: now - timedelta(days=3, hours=2),
                    AssetStatus.MAINTENANCE: now - timedelta(hours=6),
                }.get(status, now - timedelta(minutes=2 + (z["vlan_id"] // 10 + index * 3) % 14))
                c, i, av = a["cia"]
                db.add(
                    Asset(
                        asset_tag=tag,
                        name=f"{name} ({branch.code})",
                        asset_type=a["type"],
                        ip_address=f"10.{branch.site_id}.{z['vlan_id']}.{a['host']}",
                        operating_system=a["os"],
                        criticality=a["crit"],
                        data_classification=a["cls"],
                        confidentiality=c,
                        integrity=i,
                        availability=av,
                        status=status,
                        owner=a["owner"],
                        branch_id=branch.id,
                        zone_id=zone.id,
                        last_seen_at=last_seen,
                        created_at=now,
                        updated_at=now,
                    )
                )
                report.add("assets")
    db.flush()


def seed_catalogue(db: Session, report: SeedReport, now: datetime) -> None:
    for t in seed_data.THREATS:
        if db.scalar(select(Threat.id).where(Threat.code == t["code"])) is None:
            db.add(Threat(**t, active=True, created_at=now))
            report.add("threats")
    for v in seed_data.VULNERABILITIES:
        if db.scalar(select(Vulnerability.id).where(Vulnerability.code == v["code"])) is None:
            db.add(Vulnerability(**v, active=True, created_at=now))
            report.add("vulnerabilities")
    db.flush()

    threats = {t.code: t for t in db.scalars(select(Threat))}
    vulns = {v.code: v for v in db.scalars(select(Vulnerability))}
    for t_code, v_code, rationale in seed_data.THREAT_VULNERABILITY_PAIRS:
        threat, vuln = threats[t_code], vulns[v_code]
        exists = db.scalar(
            select(ThreatVulnerabilityPair.id).where(
                ThreatVulnerabilityPair.threat_id == threat.id,
                ThreatVulnerabilityPair.vulnerability_id == vuln.id,
            )
        )
        if exists is None:
            db.add(ThreatVulnerabilityPair(threat_id=threat.id, vulnerability_id=vuln.id, rationale=rationale))
            report.add("threat_vulnerability_pairs")
    db.flush()


def seed_risks(db: Session, report: SeedReport, now: datetime) -> None:
    threats = {t.code: t for t in db.scalars(select(Threat))}
    vulns = {v.code: v for v in db.scalars(select(Vulnerability))}
    for b_index, b in enumerate(seed_data.BRANCHES):
        adjust = seed_data.BRANCH_LIKELIHOOD_ADJUSTMENT[b["code"]]
        for t_index, tpl in enumerate(seed_data.RISK_TEMPLATES):
            asset = db.scalar(select(Asset).where(Asset.asset_tag == f"HSP-{b['code']}-{tpl['asset']}"))
            threat, vuln = threats[tpl["threat"]], vulns[tpl["vuln"]]
            exists = db.scalar(select(Risk.id).where(
                Risk.asset_id == asset.id, Risk.threat_id == threat.id, Risk.vulnerability_id == vuln.id
            ))
            if exists is not None:
                continue
            c, i, a = tpl["cia"]
            risk_service.build_risk(
                db,
                asset_id=asset.id, threat_id=threat.id, vulnerability_id=vuln.id,
                likelihood=max(1, min(5, tpl["l"] + adjust)),
                confidentiality_impact=c, integrity_impact=i, availability_impact=a,
                treatment=tpl["treatment"], owner=tpl["owner"], status=tpl["status"],
                created_at=now - timedelta(days=30),
                updated_at=now - timedelta(days=(t_index + b_index * 3) % 21),
            )
            report.add("risks")


def seed_controls(db: Session, report: SeedReport, now: datetime) -> None:
    vulns = {v.code: v for v in db.scalars(select(Vulnerability))}
    for c in seed_data.CONTROLS:
        if db.scalar(select(SecurityControl.id).where(SecurityControl.code == c["code"])) is not None:
            continue
        control = SecurityControl(code=c["code"], name=c["name"], description=c["description"],
                                  control_type=c["control_type"], category=c["category"], active=True,
                                  created_at=now, updated_at=now)
        control.vulnerabilities = [vulns[code] for code in c["vulns"]]
        db.add(control)
        report.add("controls")
    db.flush()


def seed_control_links(db: Session, report: SeedReport, now: datetime) -> None:
    controls = {c.code: c for c in db.scalars(select(SecurityControl))}
    threats = {t.code: t for t in db.scalars(select(Threat))}
    vulns = {v.code: v for v in db.scalars(select(Vulnerability))}
    for b in seed_data.BRANCHES:
        planned_only = b["code"] in seed_data.BRANCHES_WITH_PLANNED_CONTROLS
        for (asset_key, t_code, v_code), links in seed_data.RISK_CONTROL_LINKS.items():
            risk = db.scalar(
                select(Risk).join(Asset, Risk.asset_id == Asset.id)
                .where(Asset.asset_tag == f"HSP-{b['code']}-{asset_key}",
                       Risk.threat_id == threats[t_code].id, Risk.vulnerability_id == vulns[v_code].id)
            )
            if risk is None:
                continue
            existing = {link.control_id for link in risk.control_links}
            added = False
            for control_code, status, effectiveness in links:
                control = controls[control_code]
                if control.id in existing:
                    continue
                risk.control_links.append(RiskControl(
                    control=control, effectiveness=effectiveness,
                    implementation_status=ImplementationStatus.PLANNED if planned_only else status,
                    created_at=now, updated_at=now,
                ))
                added = True
                report.add("risk_control_links")
            if added:
                db.flush()
                risk_service.apply_assessment(risk)
    db.flush()


# Historical scenario runs with the lifecycle steps applied to any resulting incident.
# (scenario, branch, how long ago, assignee, [(status, note_type, note, minutes after creation)])
HISTORICAL_RUNS: list[tuple] = [
    ("S6", "A", timedelta(days=5, hours=3), "SOC Tier 1", [
        ("Investigating", "Investigation", "Request spike confirmed against the portal baseline; traffic spread across many sources.", 15),
        ("Contained", "Containment", "Upstream filtering requested from the ISP.", 90),
        ("Resolved", "Resolution", "Request rate returned to baseline; portal availability restored.", 360),
        ("Closed", None, None, 1440),
    ]),
    ("S2", "B", timedelta(days=4, hours=6), None, []),
    ("S5", "C", timedelta(days=3, hours=2), "SOC Tier 2", [
        ("Investigating", "Investigation", "Transfer volume confirmed in the flow record; owner contacted.", 30),
        ("Contained", "Containment", "Database service account credentials scheduled for rotation.", 120),
        ("Resolved", "Resolution", "Transfer attributed to an unapproved reporting export; export job removed.", 600),
    ]),
    ("S8", "A", timedelta(days=2, hours=4), None, []),
    ("S4", "B", timedelta(days=1, hours=1), "Biomed On-Call", [
        ("Investigating", "Investigation", "Checking whether the device is a newly delivered modality not yet registered in inventory.", 25),
    ]),
    ("S3", "C", timedelta(hours=20), None, []),
    ("S1", "C", timedelta(hours=9), None, []),
]


def seed_history(db: Session, report: SeedReport, now: datetime) -> None:
    """Benign baseline events (last 7 days) plus a few historical scenario runs."""
    already =db.scalar(select(SecurityEvent.id).where(SecurityEvent.scenario_id == BASELINE_SCENARIO_ID).limit(1))
    if already is not None:
        return

    for index, branch in enumerate(db.scalars(select(Branch).order_by(Branch.code))):
        drafts = baseline_drafts(build_context(db, branch, now), index)
        report.add("baseline_events", simulation_service.persist_baseline(db, drafts))

    for scenario_id, branch_code, ago, assignee, steps in HISTORICAL_RUNS:
        when = now - ago
        result = simulation_service.run_scenario(db, scenario_id, branch_code, actor="seed", now=when, commit=False)
        report.add("historical_runs")
        report.add("historical_events", len(result.events))
        for incident in result.incidents:
            report.add("incidents")
            if assignee:
                incident_service.update_incident(db, incident.id, IncidentUpdate(assigned_to=assignee), "seed",
                                                 at=when + timedelta(minutes=5))
            for status, note_type, note, minutes in steps:
                at = when + timedelta(minutes=minutes)
                if note:
                    incident_service.update_incident(
                        db, incident.id, IncidentUpdate(note=NoteCreate(note_type=note_type, body=note)), "seed", at=at
                    )
                incident_service.update_incident(db, incident.id, IncidentUpdate(status=status), "seed", at=at)
    db.flush()


def _record_seed(db: Session, report: SeedReport, action: str = "seed.applied", extra: dict | None = None) -> None:
    if report.total_created or extra:
        audit_service.record(
            db, actor=settings.system_actor, action=action, entity_type="system", entity_id=None,
            details={"created": report.created, **(extra or {})},
        )


def seed_reference_data(db: Session, now: datetime | None = None) -> SeedReport:
    """Seed the network, assets and catalogue only (no risks or events). Commits."""
    now = now or utcnow()
    report = SeedReport()
    seed_network(db, report, now)
    seed_catalogue(db, report, now)
    _record_seed(db, report)
    db.commit()
    return report


def seed_all(db: Session, now: datetime | None = None, *, commit: bool = True) -> SeedReport:
    """Seed the complete dataset. Idempotent."""
    now = now or utcnow()
    report = SeedReport()
    try:
        seed_network(db, report, now)
        seed_catalogue(db, report, now)
        seed_controls(db, report, now)
        seed_risks(db, report, now)
        seed_control_links(db, report, now)
        seed_history(db, report, now)
        _record_seed(db, report)
        if commit:
            db.commit()
    except Exception:
        db.rollback()
        raise
    return report


# User accounts and their sessions survive a data reset (otherwise the operator would be locked out).
PRESERVED_ON_RESET = frozenset({"users", "user_sessions"})


def reset_data(db: Session, actor: str, now: datetime | None = None) -> SeedReport:
    """Delete all data (not user accounts) and reseed, in a single transaction."""
    try:
        deleted = {}
        for table in reversed(Base.metadata.sorted_tables):
            if table.name in PRESERVED_ON_RESET:
                continue
            deleted[table.name] = db.execute(delete(table)).rowcount
        db.flush()
        report = seed_all(db, now, commit=False)
        audit_service.record(
            db, actor=actor, action="data.reset", entity_type="system", entity_id=None,
            details={"deleted": deleted, "created": report.created},
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    return report
