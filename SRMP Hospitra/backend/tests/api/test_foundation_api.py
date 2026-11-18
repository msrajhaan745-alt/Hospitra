"""API tests for health, branches, zones and asset CRUD (milestone M1)."""

import pytest

from tests.conftest import asset_by_tag, branch_by_code, zone_by_code


@pytest.fixture
def seeded_client(reference_db, client):
    return client


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["database"] == "ok"
    assert "environment" not in body


def test_openapi_docs_available(client):
    assert client.get("/docs").status_code == 200
    spec = client.get("/openapi.json").json()
    assert "/api/v1/assets" in spec["paths"]


def test_list_branches(seeded_client):
    r = seeded_client.get("/api/v1/branches")
    assert r.status_code == 200
    branches = r.json()
    assert [b["code"] for b in branches] == ["A", "B", "C"]
    assert [b["site_id"] for b in branches] == [20, 21, 22]
    assert all(b["zone_count"] == 8 and b["asset_count"] == 16 for b in branches)


def test_get_branch_with_zones(seeded_client, reference_db):
    branch = branch_by_code(reference_db, "B")
    r = seeded_client.get(f"/api/v1/branches/{branch.id}")
    assert r.status_code == 200
    body = r.json()
    assert len(body["zones"]) == 8
    assert [z["vlan_id"] for z in body["zones"]] == [10, 20, 30, 40, 50, 60, 70, 80]
    assert body["zones"][0]["subnet_cidr"] == "10.21.10.0/24"


def test_get_branch_not_found(seeded_client):
    r = seeded_client.get("/api/v1/branches/does-not-exist")
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "not_found"


def test_list_and_get_zones(seeded_client, reference_db):
    r = seeded_client.get("/api/v1/zones")
    assert r.status_code == 200
    zones = r.json()
    assert len(zones) == 24
    subnets = {z["subnet_cidr"] for z in zones}
    assert "10.20.60.0/24" in subnets and "10.22.80.0/24" in subnets

    guest = zone_by_code(reference_db, "A", "GST")
    r = seeded_client.get(f"/api/v1/zones/{guest.id}")
    assert r.status_code == 200
    assert r.json()["zone_type"] == "guest"
    assert r.json()["asset_count"] == 2

    branch = branch_by_code(reference_db, "C")
    r = seeded_client.get("/api/v1/zones", params={"branch_id": branch.id})
    assert len(r.json()) == 8


def test_asset_list_filters(seeded_client, reference_db):
    r = seeded_client.get("/api/v1/assets", params={"limit": 200})
    assert r.json()["total"] == 48

    branch = branch_by_code(reference_db, "A")
    r = seeded_client.get("/api/v1/assets", params={"branch_id": branch.id})
    assert r.json()["total"] == 16

    r = seeded_client.get("/api/v1/assets", params={"asset_type": "Medical Device"})
    assert r.json()["total"] == 6

    r = seeded_client.get("/api/v1/assets", params={"criticality": "Critical"})
    assert all(a["criticality"] == "Critical" for a in r.json()["items"])

    r = seeded_client.get("/api/v1/assets", params={"status": "Offline"})
    assert [a["asset_tag"] for a in r.json()["items"]] == ["HSP-B-ADM-002"]

    r = seeded_client.get("/api/v1/assets", params={"search": "hsp-c-net"})
    assert r.json()["total"] == 2

    r = seeded_client.get("/api/v1/assets", params={"zone_type": "guest"})
    assert r.json()["total"] == 6


def test_asset_list_sorting_and_pagination(seeded_client):
    r = seeded_client.get("/api/v1/assets", params={"sort": "asset_tag", "order": "desc", "limit": 5, "offset": 0})
    body = r.json()
    assert body["limit"] == 5 and body["offset"] == 0 and len(body["items"]) == 5
    tags = [a["asset_tag"] for a in body["items"]]
    assert tags == sorted(tags, reverse=True)

    r = seeded_client.get("/api/v1/assets", params={"limit": 500})
    assert r.status_code == 422


def test_create_get_update_asset(seeded_client, reference_db):
    branch = branch_by_code(reference_db, "A")
    zone = zone_by_code(reference_db, "A", "ADM")
    payload = {
        "asset_tag": "HSP-A-ADM-010",
        "name": "Reception Workstation",
        "asset_type": "Workstation",
        "ip_address": "10.20.20.40",
        "operating_system": "Windows 11 Enterprise",
        "criticality": "Medium",
        "data_classification": "Internal",
        "confidentiality": 2,
        "integrity": 3,
        "availability": 2,
        "owner": "Corporate IT Service Desk",
        "branch_id": branch.id,
        "zone_id": zone.id,
    }
    r = seeded_client.post("/api/v1/assets", json=payload)
    assert r.status_code == 201, r.text
    created = r.json()
    assert created["status"] == "Active"
    assert created["zone_name"] == "Staff / Administration"
    assert created["created_at"].endswith("Z")

    r = seeded_client.get(f"/api/v1/assets/{created['id']}")
    assert r.status_code == 200
    assert r.json()["asset_tag"] == "HSP-A-ADM-010"

    r = seeded_client.patch(f"/api/v1/assets/{created['id']}", json={"status": "Warning", "owner": "Front Office IT"})
    assert r.status_code == 200
    assert r.json()["status"] == "Warning"
    assert r.json()["owner"] == "Front Office IT"

    audit = seeded_client.get("/api/v1/audit", params={"entity_id": created["id"]}).json()
    actions = [a["action"] for a in audit["items"]]
    assert actions == ["asset.updated", "asset.created"]
    assert audit["items"][0]["actor"] == "test-admin"  # V2: the signed-in username
    assert audit["items"][0]["details"]["changes"]["status"] == {"from": "Active", "to": "Warning"}


def test_duplicate_asset_tag_rejected(seeded_client, reference_db):
    existing = asset_by_tag(reference_db, "HSP-A-CLN-001")
    payload = {
        "asset_tag": "HSP-A-CLN-001", "name": "Dup", "asset_type": "Workstation",
        "ip_address": "10.20.30.90", "criticality": "High", "data_classification": "Restricted",
        "confidentiality": 3, "integrity": 3, "availability": 3, "owner": "X",
        "branch_id": existing.branch_id, "zone_id": existing.zone_id,
    }
    r = seeded_client.post("/api/v1/assets", json=payload)
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "conflict"

    other = asset_by_tag(reference_db, "HSP-A-CLN-002")
    r = seeded_client.patch(f"/api/v1/assets/{other.id}", json={"asset_tag": "HSP-A-CLN-001"})
    assert r.status_code == 409


def test_invalid_foreign_keys_rejected(seeded_client, reference_db):
    zone = zone_by_code(reference_db, "A", "CLN")
    base = {
        "asset_tag": "HSP-A-CLN-050", "name": "X", "asset_type": "Workstation",
        "ip_address": "10.20.30.50", "criticality": "High", "data_classification": "Restricted",
        "confidentiality": 3, "integrity": 3, "availability": 3, "owner": "X",
    }
    r = seeded_client.post("/api/v1/assets", json={**base, "branch_id": "nope", "zone_id": zone.id})
    assert r.status_code == 422
    assert r.json()["error"]["details"][0]["field"] == "branch_id"

    r = seeded_client.post("/api/v1/assets", json={**base, "branch_id": zone.branch_id, "zone_id": "nope"})
    assert r.status_code == 422

    other_branch = branch_by_code(reference_db, "C")
    r = seeded_client.post("/api/v1/assets", json={**base, "branch_id": other_branch.id, "zone_id": zone.id})
    assert r.status_code == 422


def test_validation_error_shape(seeded_client):
    r = seeded_client.post("/api/v1/assets", json={"asset_tag": "x"})
    assert r.status_code == 422
    err = r.json()["error"]
    assert err["code"] == "validation_error"
    fields = {d["field"] for d in err["details"]}
    assert {"asset_tag", "name", "branch_id"} <= fields


def test_asset_not_found(seeded_client):
    assert seeded_client.get("/api/v1/assets/missing").status_code == 404
    assert seeded_client.patch("/api/v1/assets/missing", json={"name": "x"}).status_code == 404


def test_no_delete_endpoint_for_assets(seeded_client, reference_db):
    asset = asset_by_tag(reference_db, "HSP-A-CLN-001")
    assert seeded_client.delete(f"/api/v1/assets/{asset.id}").status_code == 405
