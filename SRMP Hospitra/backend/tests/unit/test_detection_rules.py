"""Detection rule matching, non-matching conditions, suppression and event normalisation."""

from datetime import timedelta

import pytest
from sqlalchemy import select

from app.core.constants import EventType, Severity
from app.core.exceptions import DomainValidationError
from app.core.time import utcnow
from app.models import Detection
from app.seed.scenarios import SCENARIOS, SCENARIOS_BY_ID, baseline_drafts, build_context
from app.services import detection_service, event_service, simulation_service
from app.services.event_service import EventDraft
from tests.conftest import asset_by_tag, branch_by_code, zone_by_code

EXPECTED = {
    "S1": ("R1", Severity.HIGH), "S2": ("R2", Severity.MODERATE), "S3": ("R3", Severity.MODERATE),
    "S4": ("R4", Severity.HIGH), "S5": ("R5", Severity.HIGH), "S6": ("R6", Severity.HIGH),
    "S7": ("R7", Severity.CRITICAL), "S8": ("R8", Severity.MODERATE),
}


def test_rule_catalogue_is_complete_and_unique():
    ids = [r.rule_id for r in detection_service.RULES]
    assert ids == ["R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8"]
    for rule in detection_service.RULES:
        assert rule.name and rule.description and rule.event_types and rule.conditions
        assert rule.explanation_template and rule.enabled


def test_scenarios_map_to_configured_rules():
    for scenario in SCENARIOS:
        rule_id, severity = EXPECTED[scenario.scenario_id]
        assert scenario.expected_rule_id == rule_id
        assert detection_service.RULES_BY_ID[rule_id].severity is severity


@pytest.mark.parametrize("scenario_id", list(EXPECTED))
def test_each_scenario_triggers_expected_rule(seeded_db, scenario_id):
    rule_id, severity = EXPECTED[scenario_id]
    result = simulation_service.run_scenario(seeded_db, scenario_id, "A", actor="test")
    assert len(result.events) == SCENARIOS_BY_ID[scenario_id].event_count
    assert len(result.matched) == 1
    detection = result.matched[0]
    assert detection.rule_id == rule_id
    assert detection.severity is severity
    assert detection.evidence and detection.explanation
    assert all(e.is_simulated and e.scenario_id == scenario_id for e in result.events)


def test_baseline_events_never_match(reference_db):
    ctx = build_context(reference_db, branch_by_code(reference_db, "A"), utcnow())
    drafts = baseline_drafts(ctx, 0, days=3, per_day=11)
    # Every benign template (and therefore every event type) is exercised.
    assert {d.event_type for d in drafts} == set(EventType)
    simulation_service.persist_baseline(reference_db, drafts)
    assert reference_db.scalar(select(Detection).where(Detection.matched.is_(True))) is None


def _draft(db, **kw):
    branch = branch_by_code(db, "A")
    base = dict(branch_id=branch.id, scenario_id="TEST", occurred_at=utcnow(), message="test event")
    base.update(kw)
    return EventDraft(**base)


def _evaluate(db, draft):
    event = event_service.create_event(db, draft)
    return dict((d.rule_id, d) for d, _ in detection_service.process_event(db, event)), event


def test_r1_not_matched_for_guest_to_internet(reference_db):
    kiosk = asset_by_tag(reference_db, "HSP-A-GST-002")
    results, _ = _evaluate(reference_db, _draft(reference_db, event_type="network_access",
                                                source_asset_id=kiosk.id, destination_ip="198.51.100.50"))
    assert results["R1"].matched is False
    assert "not a restricted" in results["R1"].explanation


def test_r1_not_matched_for_clinical_to_application(reference_db):
    ws, app_server = asset_by_tag(reference_db, "HSP-A-CLN-001"), asset_by_tag(reference_db, "HSP-A-APP-001")
    results, _ = _evaluate(reference_db, _draft(reference_db, event_type="network_access",
                                                source_asset_id=ws.id, destination_asset_id=app_server.id))
    assert results["R1"].matched is False


def test_r1_matched_with_evidence(reference_db):
    kiosk, med = asset_by_tag(reference_db, "HSP-A-GST-001"), asset_by_tag(reference_db, "HSP-A-MED-001")
    results, event = _evaluate(reference_db, _draft(reference_db, event_type="network_access",
                                                    source_asset_id=kiosk.id, destination_asset_id=med.id,
                                                    metadata={"protocol": "TCP", "destination_port": 22}))
    d = results["R1"]
    assert d.matched and d.severity is Severity.HIGH
    assert d.evidence["source_zone"].startswith("Guest Wi-Fi")
    assert d.evidence["destination_zone"].startswith("Medical Devices")
    assert event.severity is Severity.HIGH  # raised to the matched rule severity


def test_r2_below_threshold(reference_db):
    src, dst = asset_by_tag(reference_db, "HSP-A-ADM-001"), asset_by_tag(reference_db, "HSP-A-NET-002")
    now = utcnow()
    for i in range(4):
        results, _ = _evaluate(reference_db, _draft(reference_db, event_type="auth_failure", source_asset_id=src.id,
                                                    destination_asset_id=dst.id, occurred_at=now + timedelta(seconds=i)))
    assert results["R2"].matched is False
    assert results["R2"].evidence["failure_count"] == 4


def test_r2_window_excludes_old_failures(reference_db):
    src, dst = asset_by_tag(reference_db, "HSP-A-ADM-001"), asset_by_tag(reference_db, "HSP-A-NET-002")
    now = utcnow()
    for i in range(4):  # four failures 20 minutes ago — outside the 300 s window
        _evaluate(reference_db, _draft(reference_db, event_type="auth_failure", source_asset_id=src.id,
                                       destination_asset_id=dst.id, occurred_at=now - timedelta(minutes=20, seconds=i)))
    results, _ = _evaluate(reference_db, _draft(reference_db, event_type="auth_failure", source_asset_id=src.id,
                                                destination_asset_id=dst.id, occurred_at=now))
    assert results["R2"].matched is False
    assert results["R2"].evidence["failure_count"] == 1


def test_threshold_rule_suppressed_within_window(seeded_db):
    first = simulation_service.run_scenario(seeded_db, "S2", "A", actor="test")
    assert len(first.matched) == 1
    second = simulation_service.run_scenario(seeded_db, "S2", "A", actor="test", now=utcnow() + timedelta(seconds=30))
    assert second.matched == []
    last = seeded_db.scalar(select(Detection).where(Detection.event_id == second.events[-1].id))
    assert "Suppressed" in last.explanation


def test_r3_non_matching_login(reference_db):
    gw = asset_by_tag(reference_db, "HSP-A-DMZ-002")
    results, _ = _evaluate(reference_db, _draft(reference_db, event_type="vpn_login", source_ip="198.51.100.10",
                                                destination_asset_id=gw.id,
                                                metadata={"login_region": "Home", "approved_regions": ["Home"],
                                                          "device_posture": "managed"}))
    assert results["R3"].matched is False


def test_r4_registered_device_does_not_match(reference_db):
    ws = asset_by_tag(reference_db, "HSP-A-CLN-002")
    results, _ = _evaluate(reference_db, _draft(reference_db, event_type="device_observed", source_asset_id=ws.id))
    assert results["R4"].matched is False


def test_r4_unknown_device_in_guest_zone_does_not_match(reference_db):
    guest = zone_by_code(reference_db, "A", "GST")
    results, _ = _evaluate(reference_db, _draft(reference_db, event_type="device_observed", source_zone_id=guest.id,
                                                source_ip="10.20.60.77"))
    assert results["R4"].matched is False


def test_r5_internal_or_small_transfers_do_not_match(reference_db):
    db_server = asset_by_tag(reference_db, "HSP-A-APP-002")
    backup = asset_by_tag(reference_db, "HSP-A-SEC-002")
    r_internal, _ = _evaluate(reference_db, _draft(reference_db, event_type="outbound_transfer", source_asset_id=db_server.id,
                                                   destination_asset_id=backup.id, metadata={"bytes_out": 5_000_000_000}))
    r_small, _ = _evaluate(reference_db, _draft(reference_db, event_type="outbound_transfer", source_asset_id=db_server.id,
                                                destination_ip="203.0.113.9", metadata={"bytes_out": 10_000_000}))
    assert r_internal["R5"].matched is False and r_small["R5"].matched is False


def test_r6_requires_dmz_and_multiplier(reference_db):
    portal = asset_by_tag(reference_db, "HSP-A-DMZ-001")
    app_server = asset_by_tag(reference_db, "HSP-A-APP-001")
    r_normal, _ = _evaluate(reference_db, _draft(reference_db, event_type="request_volume", destination_asset_id=portal.id,
                                                 metadata={"requests_per_minute": 5000, "baseline_requests_per_minute": 1200}))
    r_internal, _ = _evaluate(reference_db, _draft(reference_db, event_type="request_volume", destination_asset_id=app_server.id,
                                                   metadata={"requests_per_minute": 90000, "baseline_requests_per_minute": 1200}))
    assert r_normal["R6"].matched is False and r_internal["R6"].matched is False


def test_r7_benign_file_activity_does_not_match(reference_db):
    ws, share = asset_by_tag(reference_db, "HSP-A-CLN-002"), asset_by_tag(reference_db, "HSP-A-ADM-002")
    now = utcnow()
    for i in range(8):
        results, _ = _evaluate(reference_db, _draft(reference_db, event_type="file_activity", source_asset_id=ws.id,
                                                    destination_asset_id=share.id, occurred_at=now + timedelta(seconds=i),
                                                    metadata={"operation": "file_save", "files_affected": 1}))
    assert results["R7"].matched is False


def test_r8_inside_window_does_not_match(reference_db):
    med = asset_by_tag(reference_db, "HSP-A-MED-002")
    now = utcnow()
    results, _ = _evaluate(reference_db, _draft(reference_db, event_type="vendor_access", destination_asset_id=med.id,
                                                occurred_at=now,
                                                metadata={"approved_window_start": (now - timedelta(hours=1)).isoformat(),
                                                          "approved_window_end": (now + timedelta(hours=1)).isoformat()}))
    assert results["R8"].matched is False


def test_telemetry_events_are_not_evaluated(reference_db):
    src, dst = asset_by_tag(reference_db, "HSP-A-NET-001"), asset_by_tag(reference_db, "HSP-A-SEC-001")
    results, event = _evaluate(reference_db, _draft(reference_db, event_type="telemetry", source_asset_id=src.id,
                                                    destination_asset_id=dst.id))
    assert results == {}
    assert event_service.detection_status(event) == "not_evaluated"


# ---- event normalisation ----------------------------------------------------------------

def test_normalisation_fills_zone_and_ip_from_assets(reference_db):
    kiosk, app_server = asset_by_tag(reference_db, "HSP-A-GST-002"), asset_by_tag(reference_db, "HSP-A-APP-001")
    clean = event_service.normalise_draft(reference_db, _draft(
        reference_db, event_type="network_access", source_asset_id=kiosk.id, destination_asset_id=app_server.id,
        message="  extra   spaces  ", metadata={"b": 1, "a": 2}))
    assert clean.source_ip == kiosk.ip_address and clean.destination_ip == app_server.ip_address
    assert clean.source_zone_id == kiosk.zone_id and clean.destination_zone_id == app_server.zone_id
    assert clean.message == "extra spaces"
    assert list(clean.metadata) == ["a", "b"]
    assert clean.event_type is EventType.NETWORK_ACCESS and clean.occurred_at.tzinfo is not None


@pytest.mark.parametrize("overrides,field", [
    ({"is_simulated": False}, "is_simulated"),
    ({"scenario_id": " "}, "scenario_id"),
    ({"message": ""}, "message"),
    ({"event_type": "packet_capture"}, "event_type"),
    ({"severity": "Extreme"}, "severity"),
    ({"source_ip": "not-an-ip"}, "source_ip"),
    ({"source_asset_id": "missing"}, "source_asset_id"),
    ({"branch_id": "missing"}, "branch_id"),
])
def test_normalisation_rejects_invalid_events(reference_db, overrides, field):
    kw = {"event_type": "network_access", **overrides}
    with pytest.raises(DomainValidationError) as exc:
        event_service.normalise_draft(reference_db, _draft(reference_db, **kw))
    assert exc.value.details[0]["field"] == field


def test_normalisation_rejects_zone_mismatch(reference_db):
    kiosk = asset_by_tag(reference_db, "HSP-A-GST-002")
    clinical = zone_by_code(reference_db, "A", "CLN")
    with pytest.raises(DomainValidationError):
        event_service.normalise_draft(reference_db, _draft(reference_db, event_type="network_access",
                                                           source_asset_id=kiosk.id, source_zone_id=clinical.id))
