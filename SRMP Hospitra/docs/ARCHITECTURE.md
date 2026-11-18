# Architecture

Hospitra is a **modular monolith**: one FastAPI process (Uvicorn) serves the REST API (`/api/v1`),
the WebSocket notification channel (`/ws/events`), the health endpoint (`/health`), the OpenAPI docs
(`/docs`) and the static frontend (`/`). Data lives in one SQLite file managed by Alembic migrations.
There are no microservices, brokers, caches or external services.

```text
Hospital IT / Security Operator
             │
             ▼
   Browser interface  (frontend/: HTML · custom CSS · vanilla ES modules · Chart.js · custom SVG)
             │  REST (fetch, JSON)          ▲ WebSocket notifications (after commit)
             ▼                              │
   FastAPI application  (backend/app/main.py)
     ├─ api/routes/*       thin routers: parse/validate (Pydantic v2), call a service, return a schema
     ├─ services/*         domain logic and transactions
     ├─ core/risk_model    the ONLY implementation of the risk formula and severity bands
     ├─ websocket/manager  connection set + broadcast
     └─ models/* ─ SQLAlchemy 2 ORM ─► SQLite (data/hospitra.db), schema via Alembic
```

## Version 2 security layer

```text
Browser ──(HttpOnly SameSite=Strict cookie "hospitra_session")──► FastAPI
   /api/v1/auth/*  public: status, login, bootstrap (first run only)
   /api/v1/*       Depends(current_user)  → 401 if no valid session
   write routes    Depends(operate_actor) → 403 unless Analyst/Admin; returns username for the audit log
   users, reset    Depends(admin_actor)   → 403 unless Admin
   /ws/events      session checked before accept; otherwise closed with code 4401
```

- `core/security.py`: PBKDF2-SHA256 (600 000 iterations, random salt, stored with its work factor),
  random session tokens; only `sha256(token)` is stored (`user_sessions.token_hash`).
- `services/user_service.py`: bootstrap, login with in-memory throttling (5 failures / 15 min per
  username), timing-equalised unknown-user path, session resolve/revoke, user management guards.
- Sessions are revoked on logout, password change (other sessions), role change, deactivation and
  admin password reset. Absolute lifetime 8 h (`HOSPITRA_SESSION_HOURS`).
- The frontend never sees the token; `can(permission)` hides controls the role cannot use, but the
  server is the enforcement point.

## Version 2 risk layer

`core/risk_model.assess_residual` (single implementation) ← `risk_service.apply_assessment`, called
whenever risk inputs change, a control is linked/updated/unlinked, or a linked control's type/active
flag changes (`risk_service.recompute_for_control`). Residual values are stored for filtering and sorting.

## Backend modules

| Layer | Path | Responsibility |
|---|---|---|
| Configuration | `app/core/config.py` | Env-driven settings incl. session lifetime, cookie security, PBKDF2 work factor |
| Security (V2) | `app/core/security.py` | Password hashing and session tokens (standard library) |
| Constants | `app/core/constants.py` | All enums, zone template, incident transitions, creation policy |
| Risk model | `app/core/risk_model.py` | `assess_risk()` — impact = max(C,I,A), score = L × impact, bands |
| Errors | `app/core/exceptions.py` | `AppError` hierarchy + handlers → `{"error": {code, message, details}}`; no stack traces |
| DB | `app/db/` | Naming-convention metadata, `UTCDateTime` type, enum CHECK constraints, sessions, migrations |
| Models | `app/models/` | One module per entity (see DATABASE_SCHEMA.md) |
| Schemas | `app/schemas/` | Request models use `extra="forbid"` (e.g. derived risk fields are rejected) |
| Services | `app/services/` | `asset`, `network`, `threat`, `risk`, `event`, `detection`, `incident`, `simulation`, `audit`, `dashboard`, `export`, `investigation` (composite read views), V2: `user`, `control` |
| Routes | `app/api/routes/` | `health, dashboard, branches, zones, assets, threats, vulnerabilities, risks, events, detections, simulation, incidents, audit, exports, ws`, V2: `auth, users, controls` |
| WebSocket | `app/websocket/manager.py` | Broadcast `{type, data, timestamp}`; notifications only |
| Seed | `app/seed/` | `seed_data.py` (fixed dataset), `scenarios.py` (S1–S8 + baseline), `seeder.py` (idempotent seed, reset), `cli.py` |

## Event-processing pipeline (spec §10.4)

Implemented in `services/simulation_service.py::run_scenario` and `process_event`:

1. Operator selects a predefined scenario (`POST /api/v1/simulation/trigger`).
2. `scenarios.py` builds synthetic `EventDraft`s from fixed definitions (pure function of branch + time).
3. `event_service.normalise_draft` validates (synthetic only, known type, valid references/IPs, zone ↔ asset consistency) and fills zone/IP from registered assets.
4. `event_service.create_event` persists the event (flush).
5. `detection_service.process_event` evaluates every enabled rule that applies to the event type.
6. One `Detection` per (event, rule) is persisted with evidence and explanation (UNIQUE constraint).
7. `risk_service.get_risk_context` retrieves illustrative risks for the affected assets that relate to the rule's threats/vulnerabilities.
8. `incident_service.create_from_detection` creates an incident **only** for matched High/Critical detections (`incidents.detection_id` UNIQUE ⇒ never duplicated).
9. `audit_service.record` writes `event.created`, `detection.matched|no_match`, `incident.created`, `simulation.triggered`.
10. Steps 2–9 run in **one transaction**; on any error everything is rolled back. Only after `commit()` does the route broadcast `simulation.completed` over the WebSocket.
11. The frontend re-reads the affected views from the REST API (the database is the source of truth).

Sync service code runs in Starlette's thread pool (`run_in_threadpool`) from async routes so the
WebSocket broadcast can be awaited after the commit.

## Frontend

```text
frontend/
  index.html            persistent shell: sidebar, header (branch context, Run scenario, user menu)
  css/                  tokens.css · base.css · layout.css · components.css · views.css
  js/app.js             bootstrap, hash router, nav counters, live-update fan-out
  js/core/              api.js (single fetch client, ApiError) · state.js (branch context + bus)
                        ws.js (reconnecting WebSocket) · ui.js (toast, drawer stack, modal, confirm,
                        badges, states) · table.js (sortable table + pager) · controls.js (filters,
                        fields, 1–5 rating) · charts.js (Chart.js theme) · dom.js · icons.js · format.js
  js/details.js         shared detail drawers: asset, event, risk, incident, threat, vulnerability
  js/forms.js           asset / risk / catalogue create-edit modals
  js/views/             dashboard, network, assets, catalogue, monitoring, risks, incidents, reports
  vendor/chart.umd.js   Chart.js 4.4.1 (MIT) served locally
```

- Every view exposes `mount(root, params)` → `{destroy, onLive, onDataChanged, onBranch}`.
- All API data is inserted as text nodes (no `innerHTML` of data).
- Severity is always shown as colour **plus** text **plus** a 1–4 bar glyph.
- After a WebSocket reconnect, views are refreshed from REST because missed notifications are not replayed.

## Derived values shown in the UI

| Value | Where computed | Definition |
|---|---|---|
| Risk impact / score / severity | `core/risk_model.py` (server) | See RISK_MODEL.md; the frontend never computes it |
| Event severity | `detection_service.process_event` | max(reported step severity, severity of any matched rule) |
| Detection status | `event_service.detection_status` | `detected` (≥1 match) · `no_match` · `not_evaluated` (no applicable rule) |
| Branch status | `dashboard_service.branch_posture` | **Critical** if an open Critical incident; else **Elevated** if any open High incident, offline/warning asset or matched detection in the last 24 h; else **Normal** |
| Open incident | constants | status ∈ {Open, Investigating, Contained} |

## Implementation decisions (within scope)

Approved by the project owner for Version 2:
- Scope: login + roles, and security controls + residual risk.
- Residual model: level reduction (Preventive → likelihood, Detective/Corrective → impact; Partial 1, Substantial 2; strongest per axis; floor 1; only Implemented links on active controls).
- Roles: Viewer (read/export) / Analyst (+ operate) / Admin (+ users, reset).
- First account: first-run setup screen (plus CLI), no default passwords.
- No demo / synthetic-data / illustrative labels or disclaimers in the UI, exports or generated text (owner request after 2.0.0 delivery; supersedes the original spec's persistent indicator).

Routine V2 decisions: standard-library PBKDF2 and server-side sessions (no new dependencies); user
accounts survive demo reset; `/auth/status` is public and reports whether the browser is signed in;
sign-in/out events are audited but excluded from the Command Centre activity feed; Branch C seed
control links are *Planned* to show the contrast with Branches A and B.

Approved by the project owner at kick-off (V1):
- Scenario severities: S1 High, S2 Moderate, S3 Moderate, S4 High, S5 High, S6 High, S7 Critical, S8 Moderate.
- Incident transitions: strictly forward, one step at a time; Closed is terminal and immutable.
- Python 3.12 installed per-user via winget.

Routine decisions taken during implementation:
- **Supporting tables:** `threat_vulnerability_pairs` (documented pairings + rationale), `simulation_runs` (history), `incident_notes`, `incident_events`, `incident_assets`.
- **Supporting columns:** `branches.role/site_id`, `network_zones.code`, `risks.reference` (RSK-0001), `security_events.branch_id/source_zone_id/destination_zone_id/simulation_run_id` (needed for unregistered devices and external sources), `detections.asset_id`, `incidents.detection_id`.
- **Additional read endpoints:** `GET /threats/{id}`, `GET /vulnerabilities/{id}`, `GET /detections/rules`, `GET /audit/facets`; optional `branch_id` on dashboard endpoints.
- **Incidents are created automatically only** (the API contract has no `POST /incidents`).
- **One proposed threat (T8 Unauthorised device connection)** is seeded so S4 has a catalogue anchor and the case-study/proposed distinction is visible.
- **Benign baseline events** use `scenario_id = "BASELINE"`; they are synthetic and evaluated by the rules (none match).
- **Threshold rules (R2, R7)** fire once per source per evaluation window (see SIMULATION_AND_DETECTION.md).
- **PDF:** ReportLab. **Charts:** Chart.js vendored, no CDN.
- **Delete** is not exposed for any entity (referential integrity and audit history).
- **Reset** clears all tables including the audit log, then records a single `data.reset` entry.
