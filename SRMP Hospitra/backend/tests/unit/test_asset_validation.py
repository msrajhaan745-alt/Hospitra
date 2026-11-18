import pytest
from pydantic import ValidationError

from app.core.exceptions import ConflictError, DomainValidationError
from app.schemas.asset import AssetCreate, AssetUpdate
from app.services import asset_service
from tests.conftest import asset_by_tag, branch_by_code, zone_by_code


def _payload(db, **overrides):
    branch = branch_by_code(db, "A")
    zone = zone_by_code(db, "A", "CLN")
    data = {
        "asset_tag": "hsp-a-cln-099",
        "name": "Test Clinical Workstation",
        "asset_type": "Workstation",
        "ip_address": "10.20.30.99",
        "criticality": "High",
        "data_classification": "Restricted",
        "confidentiality": 4,
        "integrity": 4,
        "availability": 3,
        "owner": "Clinical Applications Team",
        "branch_id": branch.id,
        "zone_id": zone.id,
    }
    data.update(overrides)
    return data


def test_asset_tag_is_normalised_to_upper_case(reference_db):
    payload = AssetCreate(**_payload(reference_db))
    assert payload.asset_tag == "HSP-A-CLN-099"


@pytest.mark.parametrize("tag", ["ab", "HSP A 1", "HSP_A_001", "-LEADING"])
def test_invalid_asset_tags_rejected(reference_db, tag):
    with pytest.raises(ValidationError):
        AssetCreate(**_payload(reference_db, asset_tag=tag))


@pytest.mark.parametrize("ip", ["10.20.30", "999.1.1.1", "not-an-ip", "fe80::1"])
def test_invalid_ip_rejected(reference_db, ip):
    with pytest.raises(ValidationError):
        AssetCreate(**_payload(reference_db, ip_address=ip))


@pytest.mark.parametrize("field", ["confidentiality", "integrity", "availability"])
@pytest.mark.parametrize("value", [0, 6, "3"])
def test_cia_rating_bounds(reference_db, field, value):
    with pytest.raises(ValidationError):
        AssetCreate(**_payload(reference_db, **{field: value}))


def test_invalid_enum_rejected(reference_db):
    with pytest.raises(ValidationError):
        AssetCreate(**_payload(reference_db, criticality="Extreme"))
    with pytest.raises(ValidationError):
        AssetCreate(**_payload(reference_db, data_classification="Secret"))


def test_unknown_fields_rejected(reference_db):
    with pytest.raises(ValidationError):
        AssetCreate(**_payload(reference_db, risk_score=25))


def test_zone_must_belong_to_branch(reference_db):
    other_zone = zone_by_code(reference_db, "B", "CLN")
    payload = AssetCreate(**_payload(reference_db, zone_id=other_zone.id, ip_address="10.21.30.99"))
    with pytest.raises(DomainValidationError) as exc:
        asset_service.create_asset(reference_db, payload, "local_operator")
    assert "does not belong" in exc.value.message


def test_ip_must_be_inside_zone_subnet(reference_db):
    payload = AssetCreate(**_payload(reference_db, ip_address="10.20.40.99"))
    with pytest.raises(DomainValidationError):
        asset_service.create_asset(reference_db, payload, "local_operator")


def test_duplicate_tag_rejected(reference_db):
    payload = AssetCreate(**_payload(reference_db, asset_tag="HSP-A-CLN-001"))
    with pytest.raises(ConflictError):
        asset_service.create_asset(reference_db, payload, "local_operator")


def test_update_revalidates_branch_zone_consistency(reference_db):
    asset = asset_by_tag(reference_db, "HSP-A-CLN-001")
    other_zone = zone_by_code(reference_db, "C", "CLN")
    with pytest.raises(DomainValidationError):
        asset_service.update_asset(reference_db, asset.id, AssetUpdate(zone_id=other_zone.id), "local_operator")


def test_update_rejects_null_required_field(reference_db):
    asset = asset_by_tag(reference_db, "HSP-A-CLN-001")
    with pytest.raises(DomainValidationError):
        asset_service.update_asset(reference_db, asset.id, AssetUpdate(owner=None), "local_operator")
