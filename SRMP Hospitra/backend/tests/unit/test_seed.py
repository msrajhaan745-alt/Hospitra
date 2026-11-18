import ipaddress
import re

from sqlalchemy import func, select

from app.core.constants import BASELINE_SCENARIO_ID
from app.core.risk_model import assess_risk
from app.models import (
    Asset,
    AuditLog,
    Branch,
    Detection,
    Incident,
    NetworkZone,
    Risk,
    SecurityEvent,
    Threat,
    ThreatVulnerabilityPair,
    Vulnerability,
)
from app.seed.seeder import reset_data, seed_all


def count(db, model):
    return db.scalar(select(func.count()).select_from(model))


def test_seed_creates_exact_network(seeded_db):
    db = seeded_db
    assert count(db, Branch) == 3
    assert count(db, NetworkZone) == 24
    assert count(db, Asset) == 48
    for branch in db.scalars(select(Branch)):
        zones = db.scalars(select(NetworkZone).where(NetworkZone.branch_id == branch.id)).all()
        assert sorted(z.vlan_id for z in zones) == [10, 20, 30, 40, 50, 60, 70, 80]
        for zone in zones:
            assert zone.subnet_cidr == f"10.{branch.site_id}.{zone.vlan_id}.0/24"
            assets = db.scalars(select(Asset).where(Asset.zone_id == zone.id)).all()
            assert len(assets) == 2
            for asset in assets:
                assert asset.branch_id == branch.id
                assert ipaddress.ip_address(asset.ip_address) in ipaddress.ip_network(zone.subnet_cidr)
                assert re.fullmatch(rf"HSP-{branch.code}-{zone.code}-00[12]", asset.asset_tag)


def test_branch_site_ids(seeded_db):
    sites = {b.code: b.site_id for b in seeded_db.scalars(select(Branch))}
    assert sites == {"A": 20, "B": 21, "C": 22}


def test_catalogue_seeded(seeded_db):
    codes = sorted(seeded_db.scalars(select(Threat.code)))
    assert {"T1", "T2", "T3", "T4", "T5", "T6", "T7"} <= set(codes)
    assert sorted(seeded_db.scalars(select(Vulnerability.code))) == [f"V{i}" for i in range(1, 9)]
    # Not every threat is paired with every vulnerability.
    assert count(seeded_db, ThreatVulnerabilityPair) < count(seeded_db, Threat) * count(seeded_db, Vulnerability)


def test_seeded_risks_use_the_central_formula(seeded_db):
    risks = seeded_db.scalars(select(Risk)).all()
    assert len(risks) == 42
    for r in risks:
        expected = assess_risk(r.likelihood, r.confidentiality_impact, r.integrity_impact, r.availability_impact)
        assert (r.overall_impact, r.risk_score, r.severity) == (expected.overall_impact, expected.risk_score, expected.severity)


def test_all_seeded_events_are_synthetic(seeded_db):
    events = seeded_db.scalars(select(SecurityEvent)).all()
    assert len(events) > 0
    assert all(e.is_simulated and e.scenario_id and e.message and e.occurred_at for e in events)
    assert any(e.scenario_id == BASELINE_SCENARIO_ID for e in events)


def test_seed_is_idempotent(seeded_db):
    models = (Branch, NetworkZone, Asset, Threat, Vulnerability, ThreatVulnerabilityPair, Risk, SecurityEvent,
              Detection, Incident)
    before = {m.__name__: count(seeded_db, m) for m in models}
    report = seed_all(seeded_db)
    after = {m.__name__: count(seeded_db, m) for m in models}
    assert report.created == {}
    assert before == after


def test_seed_preserves_operator_edits(seeded_db):
    asset = seeded_db.scalar(select(Asset).where(Asset.asset_tag == "HSP-A-CLN-001"))
    asset.owner = "Edited Owner"
    seeded_db.commit()
    seed_all(seeded_db)
    seeded_db.refresh(asset)
    assert asset.owner == "Edited Owner"


def test_seeded_incidents_only_from_high_or_critical(seeded_db):
    for incident in seeded_db.scalars(select(Incident)):
        assert incident.severity.value in {"High", "Critical"}
        assert incident.detection.matched


def test_reset_restores_baseline_and_is_audited(seeded_db):
    baseline_events = count(seeded_db, SecurityEvent)
    asset = seeded_db.scalar(select(Asset).where(Asset.asset_tag == "HSP-A-CLN-001"))
    asset.owner = "Edited Owner"
    seeded_db.commit()

    reset_data(seeded_db, actor="local_operator")
    assert count(seeded_db, Asset) == 48
    assert count(seeded_db, SecurityEvent) == baseline_events
    assert seeded_db.scalar(select(Asset.owner).where(Asset.asset_tag == "HSP-A-CLN-001")) != "Edited Owner"
    reset_logs = seeded_db.scalars(select(AuditLog).where(AuditLog.action == "data.reset")).all()
    assert len(reset_logs) == 1 and reset_logs[0].actor == "local_operator"
