"""V2 control library and residual risk through the API."""

import csv
import io

import pytest


@pytest.fixture
def api(seeded_db, client):
    return client


def _codes(api):
    return {c["code"]: c for c in api.get("/api/v1/controls", params={"limit": 200}).json()["items"]}


def _vulns(api):
    return {v["code"]: v["id"] for v in api.get("/api/v1/vulnerabilities").json()["items"]}


def test_control_library(api):
    controls = _codes(api)
    assert len(controls) == 12
    assert controls["C02"]["control_type"] == "Preventive" and controls["C02"]["axis"] == "likelihood"
    assert controls["C08"]["axis"] == "impact"
    assert [v["code"] for v in controls["C09"]["vulnerabilities"]] == ["V1", "V5", "V7"]
    assert controls["C06"]["linked_risk_count"] == 3 and controls["C06"]["implemented_link_count"] == 2
    assert api.get("/api/v1/controls", params={"control_type": "Detective"}).json()["total"] == 1
    assert "Identity" in api.get("/api/v1/controls/categories").json()


def test_create_and_update_control(api):
    vulns = _vulns(api)
    body = {"code": "c13", "name": "Application allow-listing", "description": "Only approved binaries run.",
            "control_type": "Preventive", "category": "Endpoint", "vulnerability_ids": [vulns["V6"]]}
    r = api.post("/api/v1/controls", json=body)
    assert r.status_code == 201 and r.json()["code"] == "C13"
    cid = r.json()["id"]
    assert api.post("/api/v1/controls", json=body).status_code == 409
    assert api.post("/api/v1/controls", json={**body, "code": "C14", "vulnerability_ids": ["nope"]}).status_code == 422
    assert api.post("/api/v1/controls", json={**body, "code": "C15", "control_type": "Magic"}).status_code == 422
    r = api.patch(f"/api/v1/controls/{cid}", json={"category": "Endpoint security", "vulnerability_ids": []})
    assert r.json()["category"] == "Endpoint security" and r.json()["vulnerabilities"] == []
    assert api.patch(f"/api/v1/controls/{cid}", json={"code": "C99"}).status_code == 422


def test_risk_residual_via_api(api):
    risk = api.get("/api/v1/risks", params={"search": "HSP-A-NET-001"}).json()["items"][0]
    assert risk["residual_score"] == risk["risk_score"] and risk["controls"] == []
    c04 = _codes(api)["C04"]["id"]

    r = api.post(f"/api/v1/risks/{risk['id']}/controls",
                 json={"control_id": c04, "implementation_status": "Implemented", "effectiveness": "Partial"})
    assert r.status_code == 201
    body = r.json()
    assert body["residual_likelihood"] == risk["likelihood"] - 1
    assert body["residual_score"] == body["residual_likelihood"] * body["residual_impact"]
    assert body["controls"][0]["counted"] is True and body["controls"][0]["applied"] is True
    assert body["residual_calculation"]["score_expression"].startswith("Residual Score =")
    assert api.post(f"/api/v1/risks/{risk['id']}/controls",
                    json={"control_id": c04, "implementation_status": "Planned", "effectiveness": "Partial"}).status_code == 409

    r = api.patch(f"/api/v1/risks/{risk['id']}/controls/{c04}", json={"implementation_status": "Planned"})
    assert r.json()["residual_score"] == risk["risk_score"] and r.json()["controls"][0]["counted"] is False
    assert api.patch(f"/api/v1/risks/{risk['id']}/controls/{c04}", json={"effectiveness": "Total"}).status_code == 422

    r = api.delete(f"/api/v1/risks/{risk['id']}/controls/{c04}")
    assert r.status_code == 200 and r.json()["controls"] == []
    assert api.delete(f"/api/v1/risks/{risk['id']}/controls/{c04}").status_code == 404


def test_residual_fields_are_not_client_writable(api):
    risk = api.get("/api/v1/risks", params={"limit": 1}).json()["items"][0]
    assert api.patch(f"/api/v1/risks/{risk['id']}", json={"residual_score": 1}).status_code == 422


def test_residual_filters_sorting_and_distribution(api):
    low = api.get("/api/v1/risks", params={"residual_severity": "Low", "limit": 200}).json()
    assert low["total"] > 0 and all(r["residual_severity"] == "Low" for r in low["items"])
    ordered = api.get("/api/v1/risks", params={"sort": "residual_score", "order": "desc", "limit": 200}).json()["items"]
    scores = [r["residual_score"] for r in ordered]
    assert scores == sorted(scores, reverse=True)
    c06 = _codes(api)["C06"]["id"]
    linked = api.get("/api/v1/risks", params={"control_id": c06}).json()
    assert linked["total"] == 3
    dist = api.get("/api/v1/dashboard/risk-distribution").json()
    assert sum(dist["residual_by_severity"].values()) == dist["total"] == 42
    # Residual can never exceed inherent, so there cannot be more residual-Critical than inherent-Critical risks.
    assert dist["residual_by_severity"]["Critical"] <= dist["by_severity"]["Critical"]
    summary = api.get("/api/v1/dashboard/summary").json()
    assert summary["risks"]["residual_by_severity"] == dist["residual_by_severity"]


def test_risk_csv_has_residual_columns(api):
    rows = list(csv.DictReader(io.StringIO(api.get("/api/v1/exports/risks.csv").content.decode("utf-8-sig"))))
    assert len(rows) == 42
    first = next(r for r in rows if r["asset_tag"] == "HSP-A-CLN-001" and r["threat_code"] == "T1")
    assert (first["risk_score"], first["residual_score"], first["residual_severity"]) == ("20", "9", "Moderate")
    assert first["implemented_controls"] == "C06:Partial;C08:Substantial"


def test_control_changes_are_audited_with_actor(api):
    cid = _codes(api)["C11"]["id"]
    api.patch(f"/api/v1/controls/{cid}", json={"active": False})
    entry = api.get("/api/v1/audit", params={"entity_id": cid}).json()["items"][0]
    assert entry["action"] == "control.updated" and entry["actor"] == "test-admin"
