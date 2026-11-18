"""API tests for catalogue, risks, events, detections, simulation, incidents, audit,
dashboard and exports."""

import csv
import io

import pytest

from tests.conftest import asset_by_tag, branch_by_code


@pytest.fixture
def api(seeded_db, client):
    return client


def _ids(client, path, key="code"):
    return {i[key]: i["id"] for i in client.get(path, params={"limit": 200}).json()["items"]}


# ---- threats & vulnerabilities ------------------------------------------------------------

def test_threat_catalogue(api):
    body = api.get("/api/v1/threats").json()
    codes = [t["code"] for t in body["items"]]
    assert codes[:7] == ["T1", "T2", "T3", "T4", "T5", "T6", "T7"]
    t2 = next(t for t in body["items"] if t["code"] == "T2")
    assert t2["source_type"] == "Case Study"
    assert {v["code"] for v in t2["related_vulnerabilities"]} == {"V2", "V7"}
    assert all(v["rationale"] for v in t2["related_vulnerabilities"])
    t8 = next(t for t in body["items"] if t["code"] == "T8")
    assert t8["source_type"] == "Proposed"


def test_vulnerability_catalogue(api):
    items = api.get("/api/v1/vulnerabilities").json()["items"]
    assert [v["code"] for v in items] == [f"V{i}" for i in range(1, 9)]
    assert all(v["risk_count"] >= 0 for v in items)


def test_create_and_update_threat(api):
    r = api.post("/api/v1/threats", json={"code": "t9", "name": "Phishing of clinical staff",
                                          "description": "Proposed scenario.", "category": "Social engineering"})
    assert r.status_code == 201
    created = r.json()
    assert created["code"] == "T9" and created["source_type"] == "Proposed"

    assert api.post("/api/v1/threats", json={"code": "T9", "name": "x", "description": "x", "category": "x"}).status_code == 409

    r = api.patch(f"/api/v1/threats/{created['id']}", json={"active": False})
    assert r.status_code == 200 and r.json()["active"] is False
    assert api.patch(f"/api/v1/threats/{created['id']}", json={"code": "T10"}).status_code == 422

    actions = [a["action"] for a in api.get("/api/v1/audit", params={"entity_id": created["id"]}).json()["items"]]
    assert actions == ["threat.updated", "threat.created"]


def test_create_and_update_vulnerability(api):
    r = api.post("/api/v1/vulnerabilities", json={"code": "V9", "name": "Shared clinical accounts",
                                                  "description": "Proposed.", "weakness_type": "Access control"})
    assert r.status_code == 201
    vid = r.json()["id"]
    r = api.patch(f"/api/v1/vulnerabilities/{vid}", json={"description": "Updated description."})
    assert r.json()["description"] == "Updated description."
    assert api.get("/api/v1/vulnerabilities", params={"source_type": "Proposed"}).json()["total"] == 1


# ---- risks -------------------------------------------------------------------------------

def test_risk_list_sorted_and_filtered(api, seeded_db):
    items = api.get("/api/v1/risks", params={"limit": 200}).json()["items"]
    assert len(items) == 42
    scores = [r["risk_score"] for r in items]
    assert scores == sorted(scores, reverse=True)
    crit = api.get("/api/v1/risks", params={"severity": "Critical"}).json()
    assert crit["total"] >= 1 and all(r["severity"] == "Critical" for r in crit["items"])
    branch = branch_by_code(seeded_db, "B")
    assert all(r["asset"]["branch_code"] == "B"
               for r in api.get("/api/v1/risks", params={"branch_id": branch.id}).json()["items"])


def test_create_risk_calculates_score(api, seeded_db):
    threats, vulns = _ids(api, "/api/v1/threats"), _ids(api, "/api/v1/vulnerabilities")
    asset = asset_by_tag(seeded_db, "HSP-A-CLN-002")
    payload = {"asset_id": asset.id, "threat_id": threats["T4"], "vulnerability_id": vulns["V4"],
               "likelihood": 4, "confidentiality_impact": 4, "integrity_impact": 3, "availability_impact": 5,
               "treatment": "Mitigate", "owner": "Clinical Applications Team"}
    r = api.post("/api/v1/risks", json=payload)
    assert r.status_code == 201, r.text
    risk = r.json()
    assert (risk["overall_impact"], risk["risk_score"], risk["severity"]) == (5, 20, "Critical")
    assert risk["calculation"]["score_expression"] == "Score = 4 × 5 = 20"
    assert risk["reference"].startswith("RSK-")
    assert risk["pairing_rationale"]  # T4/V4 is a documented pairing

    assert api.post("/api/v1/risks", json=payload).status_code == 409  # duplicate combination

    r = api.patch(f"/api/v1/risks/{risk['id']}", json={"likelihood": 1})
    assert (r.json()["risk_score"], r.json()["severity"]) == (5, "Moderate")
    audit = api.get("/api/v1/audit", params={"entity_id": risk["id"]}).json()["items"]
    assert audit[0]["details"]["recalculated"]["risk_score"] == {"from": 20, "to": 5}


def test_risk_rejects_derived_fields_and_bad_inputs(api, seeded_db):
    threats, vulns = _ids(api, "/api/v1/threats"), _ids(api, "/api/v1/vulnerabilities")
    asset = asset_by_tag(seeded_db, "HSP-A-ADM-001")
    base = {"asset_id": asset.id, "threat_id": threats["T6"], "vulnerability_id": vulns["V7"], "likelihood": 2,
            "confidentiality_impact": 2, "integrity_impact": 2, "availability_impact": 2,
            "treatment": "Accept", "owner": "Corporate IT"}
    assert api.post("/api/v1/risks", json={**base, "risk_score": 25}).status_code == 422
    assert api.post("/api/v1/risks", json={**base, "severity": "Low"}).status_code == 422
    assert api.post("/api/v1/risks", json={**base, "likelihood": 6}).status_code == 422
    assert api.post("/api/v1/risks", json={**base, "integrity_impact": 0}).status_code == 422
    assert api.post("/api/v1/risks", json={**base, "treatment": "Ignore"}).status_code == 422
    r = api.post("/api/v1/risks", json={**base, "asset_id": "missing"})
    assert r.status_code == 422 and r.json()["error"]["details"][0]["field"] == "asset_id"
    existing = api.get("/api/v1/risks", params={"limit": 1}).json()["items"][0]
    assert api.patch(f"/api/v1/risks/{existing['id']}", json={"risk_score": 1}).status_code == 422


# ---- simulation, events, detections -----------------------------------------------------

def test_scenarios_listed(api):
    scenarios = api.get("/api/v1/simulation/scenarios").json()
    assert [s["scenario_id"] for s in scenarios] == [f"S{i}" for i in range(1, 9)]
    by_id = {s["scenario_id"]: s for s in scenarios}
    assert by_id["S1"]["expected_severity"] == "High" and by_id["S1"]["creates_incident"] is True
    assert by_id["S2"]["creates_incident"] is False
    assert by_id["S7"]["expected_severity"] == "Critical"


def test_trigger_validation(api):
    assert api.post("/api/v1/simulation/trigger", json={"scenario_id": "S9"}).status_code == 422
    assert api.post("/api/v1/simulation/trigger", json={"scenario_id": "S1", "branch_code": "D"}).status_code == 422
    assert api.post("/api/v1/simulation/trigger", json={"scenario_id": "S1", "command": "rm"}).status_code == 422


def test_trigger_and_inspect_event(api):
    r = api.post("/api/v1/simulation/trigger", json={"scenario_id": "S1", "branch_code": "A"})
    assert r.status_code == 201
    body = r.json()
    assert len(body["event_ids"]) == 1 and len(body["matched_detection_ids"]) == 1 and len(body["incident_ids"]) == 1
    assert "1 incident(s) opened" in body["summary"]

    event = api.get(f"/api/v1/events/{body['event_ids'][0]}").json()
    assert event["is_simulated"] is True and event["scenario_id"] == "S1"
    assert event["source_zone"]["zone_type"] == "guest" and event["destination_zone"]["zone_type"] == "application"
    assert event["detection_status"] == "detected" and event["severity"] == "High"
    assert event["detections"][0]["rule_id"] == "R1" and event["detections"][0]["evidence"]["policy"]
    assert event["rules"][0]["rule_id"] == "R1"
    assert event["incident"]["status"] == "Open"
    assert any(r["threat"]["code"] in {"T1", "T3"} for r in event["risk_context"])

    detection = api.get(f"/api/v1/detections/{body['matched_detection_ids'][0]}").json()
    assert detection["matched"] is True and detection["rule"]["name"].startswith("Guest")
    assert detection["incident_number"] == event["incident"]["incident_number"]

    history = api.get("/api/v1/simulation/history").json()
    assert history["items"][0]["scenario_id"] == "S1" and history["items"][0]["triggered_by"] == "test-admin"


def test_event_filters(api, seeded_db):
    total = api.get("/api/v1/events").json()["total"]
    assert total > 0
    for sev in ["Low", "High"]:
        items = api.get("/api/v1/events", params={"severity": sev, "limit": 200}).json()["items"]
        assert all(e["severity"] == sev for e in items)
    items = api.get("/api/v1/events", params={"event_type": "vpn_login", "limit": 200}).json()["items"]
    assert items and all(e["event_type"] == "vpn_login" for e in items)
    branch = branch_by_code(seeded_db, "C")
    items = api.get("/api/v1/events", params={"branch_id": branch.id, "limit": 200}).json()["items"]
    assert items and all(e["branch_code"] == "C" for e in items)
    detected = api.get("/api/v1/events", params={"detection_status": "detected", "limit": 200}).json()["items"]
    assert detected and all(e["detection_status"] == "detected" for e in detected)
    assert api.get("/api/v1/events", params={"search": "unregistered"}).json()["total"] >= 1
    future = api.get("/api/v1/events", params={"since": "2999-01-01T00:00:00Z"}).json()
    assert future["total"] == 0 and future["items"] == []
    assert api.get("/api/v1/events", params={"since": "not-a-date"}).status_code == 422


def test_detections_and_rules(api):
    rules = api.get("/api/v1/detections/rules").json()
    assert [r["rule_id"] for r in rules] == [f"R{i}" for i in range(1, 9)]
    matched = api.get("/api/v1/detections", params={"matched": True, "limit": 200}).json()
    assert matched["total"] >= 7 and all(d["matched"] for d in matched["items"])
    assert api.get("/api/v1/detections/missing").status_code == 404


# ---- incidents ---------------------------------------------------------------------------

def _new_incident(api):
    body = api.post("/api/v1/simulation/trigger", json={"scenario_id": "S6", "branch_code": "B"}).json()
    return body["incident_ids"][0]


def test_incident_lifecycle_via_api(api):
    iid = _new_incident(api)
    detail = api.get(f"/api/v1/incidents/{iid}").json()
    assert detail["status"] == "Open" and detail["allowed_next_status"] == "Investigating"
    assert detail["events"] and detail["detection"]["rule_id"] == "R6" and detail["assets"]
    assert detail["risk_context"] and detail["history"][0]["action"] == "incident.created"

    r = api.patch(f"/api/v1/incidents/{iid}", json={
        "status": "Investigating", "assigned_to": "SOC Tier 1",
        "note": {"note_type": "Investigation", "body": "Confirmed spike against baseline."}})
    assert r.status_code == 200
    assert r.json()["status"] == "Investigating" and r.json()["assigned_to"] == "SOC Tier 1"

    r = api.patch(f"/api/v1/incidents/{iid}", json={"status": "Contained",
                                                   "note": {"note_type": "Containment", "body": "Recorded only."}})
    assert r.json()["status"] == "Contained"
    for status in ["Resolved", "Closed"]:
        assert api.patch(f"/api/v1/incidents/{iid}", json={"status": status}).status_code == 200
    final = api.get(f"/api/v1/incidents/{iid}").json()
    assert final["status"] == "Closed" and final["closed_at"] and final["resolved_at"]
    assert [n["note_type"] for n in final["notes"]] == ["Investigation", "Containment"]


def test_invalid_incident_transition_structured_error(api):
    iid = _new_incident(api)
    r = api.patch(f"/api/v1/incidents/{iid}", json={"status": "Resolved"})
    assert r.status_code == 409
    err = r.json()["error"]
    assert err["code"] == "invalid_status_transition"
    assert err["details"] == {"current_status": "Open", "requested_status": "Resolved",
                              "allowed_next_status": "Investigating",
                              "lifecycle": ["Open", "Investigating", "Contained", "Resolved", "Closed"]}
    assert api.patch(f"/api/v1/incidents/{iid}", json={"status": "Pending"}).status_code == 422
    assert api.patch(f"/api/v1/incidents/{iid}", json={}).status_code == 422
    assert api.patch(f"/api/v1/incidents/{iid}", json={"note": {"note_type": "Investigation", "body": "  "}}).status_code == 422


def test_incident_list_filters(api, seeded_db):
    all_items = api.get("/api/v1/incidents").json()
    assert all_items["total"] >= 4
    active = api.get("/api/v1/incidents", params={"active_only": True}).json()["items"]
    assert all(i["status"] in {"Open", "Investigating", "Contained"} for i in active)
    closed = api.get("/api/v1/incidents", params={"status": "Closed"}).json()["items"]
    assert all(i["status"] == "Closed" for i in closed)
    branch = branch_by_code(seeded_db, "C")
    assert all(i["branch_code"] == "C" for i in api.get("/api/v1/incidents", params={"branch_id": branch.id}).json()["items"])
    assert api.get("/api/v1/incidents/missing").status_code == 404


# ---- audit, dashboard ---------------------------------------------------------------------

def test_audit_listing(api):
    body = api.get("/api/v1/audit", params={"limit": 10}).json()
    assert body["total"] > 0 and len(body["items"]) <= 10
    stamps = [a["timestamp"] for a in body["items"]]
    assert stamps == sorted(stamps, reverse=True)
    assert all(a["timestamp"].endswith("Z") for a in body["items"])
    facets = api.get("/api/v1/audit/facets").json()
    assert "incident" in facets["entity_types"]
    inc = api.get("/api/v1/audit", params={"entity_type": "incident"}).json()["items"]
    assert inc and all(a["entity_type"] == "incident" for a in inc)


def test_dashboard_endpoints_reflect_database(api, seeded_db):
    s = api.get("/api/v1/dashboard/summary").json()
    assert s["assets"]["total"] == 48
    assert s["assets"]["active"] + s["assets"]["warning"] + s["assets"]["offline"] + s["assets"]["maintenance"] == 48
    assert s["assets"]["offline"] == 1 and s["assets"]["warning"] == 3
    assert len(s["branches"]) == 3 and {b["posture"] for b in s["branches"]} <= {"Normal", "Elevated", "Critical"}
    assert sum(s["incidents"]["open_by_severity"].values()) == s["incidents"]["open_total"]
    events_total = api.get("/api/v1/events").json()["total"]
    assert s["events"]["total"] == events_total

    before = s["incidents"]["open_total"]
    api.post("/api/v1/simulation/trigger", json={"scenario_id": "S7", "branch_code": "A"})
    after = api.get("/api/v1/dashboard/summary").json()
    assert after["incidents"]["open_total"] == before + 1
    assert after["incidents"]["open_by_severity"]["Critical"] >= 1
    assert next(b for b in after["branches"] if b["code"] == "A")["posture"] == "Critical"

    trends = api.get("/api/v1/dashboard/event-trends", params={"days": 7}).json()
    assert len(trends["series"]) == 7
    # Buckets are UTC calendar days: compare with every event since the first bucket's midnight.
    since = f"{trends['series'][0]['date']}T00:00:00Z"
    assert sum(d["total"] for d in trends["series"]) == api.get("/api/v1/events", params={"since": since}).json()["total"]

    dist = api.get("/api/v1/dashboard/risk-distribution").json()
    assert dist["total"] == 42 == sum(dist["by_severity"].values())
    assert sum(sum(row) for row in dist["matrix"]["counts"]) == 42

    branch = branch_by_code(seeded_db, "A")
    scoped = api.get("/api/v1/dashboard/summary", params={"branch_id": branch.id}).json()
    assert scoped["assets"]["total"] == 16
    assert api.get("/api/v1/dashboard/event-trends", params={"days": 0}).status_code == 422


# ---- exports -----------------------------------------------------------------------------

@pytest.mark.parametrize("name,expected_rows,first_col", [
    ("assets", 48, "asset_tag"), ("risks", 42, "risk_reference"), ("events", None, "event_id"),
    ("incidents", None, "incident_number"),
])
def test_csv_exports(api, name, expected_rows, first_col):
    r = api.get(f"/api/v1/exports/{name}.csv")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers["content-disposition"] and f"hospitra-{name}-" in r.headers["content-disposition"]
    rows = list(csv.reader(io.StringIO(r.content.decode("utf-8-sig"))))
    assert rows[0][0] == first_col
    assert len(set(len(row) for row in rows)) == 1  # consistent column count
    if expected_rows is not None:
        assert len(rows) - 1 == expected_rows
    else:
        assert len(rows) > 1
    ts_cols = [i for i, h in enumerate(rows[0]) if h.endswith("_utc")]
    for row in rows[1:]:
        for i in ts_cols:
            assert row[i] == "" or row[i].endswith("Z")


def test_pdf_export(api):
    r = api.get("/api/v1/exports/summary.pdf")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert r.content.startswith(b"%PDF-") and len(r.content) > 5000


def test_reset_requires_confirmation(api):
    assert api.post("/api/v1/simulation/reset", json={}).status_code == 422
    assert api.post("/api/v1/simulation/reset", json={"confirm": "yes"}).status_code == 422
    api.post("/api/v1/simulation/trigger", json={"scenario_id": "S1"})
    r = api.post("/api/v1/simulation/reset", json={"confirm": "RESET"})
    assert r.status_code == 200 and r.json()["created"]["assets"] == 48
    assert api.get("/api/v1/audit", params={"action": "data.reset"}).json()["total"] == 1
