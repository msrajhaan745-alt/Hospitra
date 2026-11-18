"""V2 authentication, sessions, roles and user management."""

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update
from starlette.websockets import WebSocketDisconnect

from app.core.constants import Role
from app.core.time import utcnow
from app.models import AuditLog, UserSession
from tests.conftest import ADMIN_USERNAME, TEST_PASSWORD, create_user, login

PROTECTED = ["/api/v1/dashboard/summary", "/api/v1/assets", "/api/v1/risks", "/api/v1/events", "/api/v1/incidents",
             "/api/v1/audit", "/api/v1/controls", "/api/v1/exports/assets.csv", "/api/v1/users"]


# ---- bootstrap -------------------------------------------------------------------------------

def test_first_run_bootstrap_flow(anon_client):
    assert anon_client.get("/api/v1/auth/status").json()["bootstrap_required"] is True
    weak = anon_client.post("/api/v1/auth/bootstrap", json={"username": "admin", "display_name": "A", "password": "short"})
    assert weak.status_code == 422
    r = anon_client.post("/api/v1/auth/bootstrap", json={"username": "Chief.Admin", "display_name": "Chief Admin",
                                                        "password": TEST_PASSWORD})
    assert r.status_code == 201
    me = r.json()
    assert me["username"] == "chief.admin" and me["role"] == "Admin" and "admin" in me["permissions"]
    assert "password_hash" not in me
    assert anon_client.get("/api/v1/auth/me").status_code == 200  # signed in by bootstrap
    assert anon_client.get("/api/v1/auth/status").json()["bootstrap_required"] is False
    again = anon_client.post("/api/v1/auth/bootstrap", json={"username": "other", "display_name": "O", "password": TEST_PASSWORD})
    assert again.status_code == 409


# ---- authentication required -----------------------------------------------------------------

@pytest.mark.parametrize("path", PROTECTED)
def test_api_requires_authentication(anon_client, path):
    r = anon_client.get(path)
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "not_authenticated"


def test_public_endpoints(anon_client):
    assert anon_client.get("/health").status_code == 200
    status = anon_client.get("/api/v1/auth/status").json()
    assert status["authenticated"] is False and status["user"] is None


def test_status_reports_signed_in_user(client):
    status = client.get("/api/v1/auth/status").json()
    assert status["authenticated"] is True and status["user"]["username"] == ADMIN_USERNAME


def test_websocket_rejects_unauthenticated(anon_client):
    with pytest.raises(WebSocketDisconnect) as exc:
        with anon_client.websocket_connect("/ws/events") as ws:
            ws.receive_json()
    assert exc.value.code == 4401


def test_websocket_rejection_happens_after_handshake(anon_client):
    # Closing *before* accept turns into an HTTP 403 handshake failure; browsers then only see
    # code 1006 and retry forever. The handshake must succeed so the 4401 reaches the client.
    ws_cm = anon_client.websocket_connect("/ws/events")
    ws = ws_cm.__enter__()  # raises here if the server refused the handshake
    try:
        with pytest.raises(WebSocketDisconnect) as exc:
            ws.receive_json()
        assert exc.value.code == 4401
    finally:
        try:
            ws_cm.__exit__(None, None, None)
        except Exception:
            pass


def test_websocket_accepts_signed_in_user(client):
    with client.websocket_connect("/ws/events") as ws:
        assert ws.receive_json()["type"] == "connected"


# ---- login / logout / sessions --------------------------------------------------------------

def test_login_sets_hardened_cookie_and_logout_revokes(app, session_factory):
    create_user(session_factory, "analyst-1", Role.ANALYST)
    with TestClient(app) as c:
        r = c.post("/api/v1/auth/login", json={"username": "ANALYST-1", "password": TEST_PASSWORD})
        assert r.status_code == 200 and r.json()["permissions"] == ["read", "operate"]
        cookie = r.headers["set-cookie"].lower()
        assert "httponly" in cookie and "samesite=strict" in cookie and "path=/" in cookie
        assert c.get("/api/v1/auth/me").status_code == 200
        assert c.post("/api/v1/auth/logout").status_code == 204
        assert c.get("/api/v1/auth/me").status_code == 401


def test_login_failures(app, session_factory, anon_client):
    create_user(session_factory, "inactive-user", Role.VIEWER, active=False)
    bad = anon_client.post("/api/v1/auth/login", json={"username": ADMIN_USERNAME, "password": "wrong-password"})
    assert bad.status_code == 401 and bad.json()["error"]["message"] == "Invalid username or password."
    unknown = anon_client.post("/api/v1/auth/login", json={"username": "nobody", "password": TEST_PASSWORD})
    assert unknown.status_code == 401 and unknown.json()["error"]["message"] == bad.json()["error"]["message"]
    assert anon_client.post("/api/v1/auth/login", json={"username": "inactive-user", "password": TEST_PASSWORD}).status_code == 401


def test_lockout_after_repeated_failures(session_factory, anon_client, db):
    create_user(session_factory, "target-user", Role.VIEWER)
    for _ in range(5):
        assert anon_client.post("/api/v1/auth/login", json={"username": "target-user", "password": "nope-nope-nope"}).status_code == 401
    locked = anon_client.post("/api/v1/auth/login", json={"username": "target-user", "password": TEST_PASSWORD})
    assert locked.status_code == 429 and locked.json()["error"]["code"] == "too_many_attempts"
    failures = db.scalars(select(AuditLog).where(AuditLog.action == "auth.login_failed")).all()
    assert len(failures) == 5 and all("password" not in str(f.details).lower() for f in failures)


def test_expired_session_rejected(client, db):
    db.execute(update(UserSession).values(expires_at=utcnow() - timedelta(minutes=1)))
    db.commit()
    assert client.get("/api/v1/auth/me").status_code == 401


def test_change_password_revokes_other_sessions(app, session_factory):
    create_user(session_factory, "pw-user", Role.ANALYST)
    with TestClient(app) as a, TestClient(app) as b:
        login(a, "pw-user")
        login(b, "pw-user")
        wrong = a.post("/api/v1/auth/change-password", json={"current_password": "wrong", "new_password": "a-new-password-1"})
        assert wrong.status_code == 422
        assert a.post("/api/v1/auth/change-password",
                      json={"current_password": TEST_PASSWORD, "new_password": "a-new-password-1"}).status_code == 204
        assert a.get("/api/v1/auth/me").status_code == 200       # this session stays valid
        assert b.get("/api/v1/auth/me").status_code == 401       # other sessions revoked
    with TestClient(app) as c:
        assert c.post("/api/v1/auth/login", json={"username": "pw-user", "password": TEST_PASSWORD}).status_code == 401
        assert c.post("/api/v1/auth/login", json={"username": "pw-user", "password": "a-new-password-1"}).status_code == 200


# ---- role matrix -----------------------------------------------------------------------------

def test_viewer_is_read_only(seeded_db, client_as):
    viewer = client_as(Role.VIEWER)
    for path in ["/api/v1/dashboard/summary", "/api/v1/risks", "/api/v1/controls", "/api/v1/events",
                 "/api/v1/exports/risks.csv", "/api/v1/exports/summary.pdf"]:
        assert viewer.get(path).status_code == 200, path
    incident_id = viewer.get("/api/v1/incidents").json()["items"][0]["id"]
    denied = [
        viewer.post("/api/v1/simulation/trigger", json={"scenario_id": "S1"}),
        viewer.patch(f"/api/v1/incidents/{incident_id}", json={"assigned_to": "x"}),
        viewer.post("/api/v1/risks", json={}),
        viewer.post("/api/v1/controls", json={}),
        viewer.post("/api/v1/assets", json={}),
        viewer.post("/api/v1/threats", json={}),
        viewer.post("/api/v1/simulation/reset", json={"confirm": "RESET"}),
        viewer.get("/api/v1/users"),
    ]
    for r in denied:
        assert r.status_code == 403, r.text
        assert r.json()["error"]["code"] == "forbidden"


def test_analyst_operates_but_cannot_administer(seeded_db, client_as):
    analyst = client_as(Role.ANALYST)
    r = analyst.post("/api/v1/simulation/trigger", json={"scenario_id": "S1", "branch_code": "A"})
    assert r.status_code == 201
    assert analyst.get("/api/v1/simulation/history").json()["items"][0]["triggered_by"] == "test-analyst"
    iid = r.json()["incident_ids"][0]
    assert analyst.patch(f"/api/v1/incidents/{iid}", json={"status": "Investigating"}).status_code == 200
    assert analyst.post("/api/v1/simulation/reset", json={"confirm": "RESET"}).status_code == 403
    assert analyst.get("/api/v1/users").status_code == 403


def test_admin_reset_keeps_user_accounts(seeded_db, client):
    assert client.post("/api/v1/simulation/reset", json={"confirm": "RESET"}).status_code == 200
    assert client.get("/api/v1/auth/me").json()["username"] == ADMIN_USERNAME


# ---- user management -------------------------------------------------------------------------

def test_user_management(app, client):
    r = client.post("/api/v1/users", json={"username": "new.viewer", "display_name": "New Viewer", "role": "Viewer",
                                           "password": TEST_PASSWORD})
    assert r.status_code == 201
    uid = r.json()["id"]
    assert "password_hash" not in r.json()
    assert client.post("/api/v1/users", json={"username": "new.viewer", "display_name": "Dup", "role": "Viewer",
                                              "password": TEST_PASSWORD}).status_code == 409
    assert {u["username"] for u in client.get("/api/v1/users").json()["items"]} == {ADMIN_USERNAME, "new.viewer"}

    with TestClient(app) as user_client:
        login(user_client, "new.viewer")
        assert client.patch(f"/api/v1/users/{uid}", json={"role": "Analyst"}).json()["role"] == "Analyst"
        assert user_client.get("/api/v1/auth/me").status_code == 401   # role change revokes sessions
        login(user_client, "new.viewer")
        assert user_client.get("/api/v1/auth/me").json()["permissions"] == ["read", "operate"]
        assert client.patch(f"/api/v1/users/{uid}", json={"active": False}).status_code == 200
        assert user_client.get("/api/v1/auth/me").status_code == 401
        assert user_client.post("/api/v1/auth/login", json={"username": "new.viewer", "password": TEST_PASSWORD}).status_code == 401
    actions = [a["action"] for a in client.get("/api/v1/audit", params={"entity_id": uid}).json()["items"]]
    assert "user.created" in actions and "user.updated" in actions


def test_last_admin_and_self_protection(client):
    me = client.get("/api/v1/auth/me").json()
    demote = client.patch(f"/api/v1/users/{me['id']}", json={"role": "Viewer"})
    assert demote.status_code == 409 and "Admin" in demote.json()["error"]["message"]
    assert client.patch(f"/api/v1/users/{me['id']}", json={"active": False}).status_code == 409
    assert client.patch(f"/api/v1/users/{me['id']}", json={"password": "short"}).status_code == 422
