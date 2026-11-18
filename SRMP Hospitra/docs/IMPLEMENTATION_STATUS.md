# Implementation status

Current version: **2.0.0** (2026-11-17). Evidence: [TESTING.md](TESTING.md).

## Version 2

| Item | Status | Evidence |
|---|---|---|
| Sign-in, first-run setup, sessions, sign-out, change password | Complete | `test_auth_api.py`; browser: first-run setup, wrong-password error, sign-out |
| Roles enforced on every API route and the WebSocket | Complete | 401 on 9 endpoints, role matrix tests, WS close 4401; browser Viewer/Analyst checks |
| User management (Admin) with session revocation and Admin guards | Complete | `test_user_management`, `test_last_admin_and_self_protection`; browser user list |
| Control library + control ↔ vulnerability links | Complete | `test_controls_api.py`; browser Security Controls view |
| Residual risk (approved level-reduction model) | Complete | Exhaustive `test_residual_model.py`; service tests; browser: C04 link → 1 × 3 = 3 |
| Residual in dashboard, register, CSV, PDF | Complete | API tests; browser residual toggle; CSV columns test |
| Migration 0002 incl. V1 data backfill | Complete | `test_v1_data_is_backfilled_by_0002`; downgrade round trip |
| Audit of user actions and V2 changes | Complete | API + browser audit checks |
| V1 functionality preserved | Complete | all V1 tests pass signed-in; V1 browser walkthrough 28/28 |

Pending / blocked within V2 scope: none. Not exercised by an automated test: behaviour when the 8-hour
session expires *while a page is open* (covered at API level by `test_expired_session_rejected`; the UI
handler shows "Your session has ended" and returns to sign-in).

## V1 milestones

| Milestone | Status | Evidence |
|---|---|---|
| M0 Project setup | Complete | Structure, pinned `requirements.txt`, venv install, vendored Chart.js, README |
| M1 Backend foundation | Complete | Server starts, `/docs` loads, Alembic migration verified, asset CRUD + duplicate rejection tested |
| M2 Frontend foundation & Command Centre | Complete | All routes load without console errors; dashboard KPI matches API; charts render persisted data |
| M3 Network model & inventory | Complete | 3 branches × 8 zones × 2 assets verified by tests and UI; topology node opens the correct asset |
| M4 Simulation & detection | Complete | S1–S8 trigger expected rules (unit, API and integration tests); explanations visible in UI; WebSocket updates received by test client and browser |
| M5 Risk & incident management | Complete | Formula/bands tested exhaustively; High/Critical create incidents, Low/Moderate do not; lifecycle persists; audit available |
| M6 Exports, integration, validation | Complete | CSV/PDF tested and inspected; integration suite; UI walkthrough 28/28; docs written |

## Acceptance criteria (spec §20)

### Functional
- [x] Application starts locally (`uvicorn app.main:app`, verified repeatedly)
- [x] API documentation is accessible (`/docs`; `test_openapi_docs_available`)
- [x] SQLite database persists (`backend/data/hospitra.db`; Alembic-managed)
- [x] Three branches exist · [x] Eight zones per branch · [x] Forty-eight synthetic assets (`test_seed_creates_exact_network`)
- [x] Asset inventory is functional (search, filters, sort, pagination, create/edit — API + UI tests)
- [x] Network topology is interactive (branch/zone/asset selection, detail panel, keyboard — UI tests)
- [x] Threat catalogue works · [x] Vulnerability catalogue works (API + UI creation tests)
- [x] Risk register works · [x] Risk formula is correct · [x] Severity thresholds are correct
- [x] All eight scenarios can be triggered (`test_all_eight_scenarios_via_api`, parametrised unit tests)
- [x] Synthetic events persist (DB CHECK `is_simulated = 1`; integration test)
- [x] Detection rules work (match + non-match tests for R1–R8)
- [x] Detection explanations are visible (event drawer — UI walkthrough)
- [x] High/Critical detections create incidents · [x] Low/Moderate detections do not
- [x] Incident lifecycle works (one-step transitions, structured rejection, Closed immutable)
- [x] Audit history persists
- [x] WebSocket updates work (integration test client + live browser refresh)
- [x] CSV exports work · [x] PDF export works

### Safety
- [x] No real network scanning · [x] No packet capture · [x] No real infrastructure modification (source scan; no such libraries in `requirements.txt`)
- [x] No patient data · [x] No real credentials (fictional accounts only, no passwords stored)
- [x] No external threat-intelligence dependency (no outbound calls; reserved documentation IP ranges)
- [x] All generated events carry their scenario ID (DB constraint `is_simulated = 1` + scenario marker in UI/CSV). The on-screen synthetic-data labels were removed at the project owner's request in 2.0.0.
- [x] No unsupported compliance claims (the UI/PDF disclaimers were removed at the project owner's request; see KNOWN_LIMITATIONS.md)

### Engineering
- [x] Database migrations are present (`0001_initial_schema`, verified against models)
- [x] Backend modules are separated (core / db / models / schemas / services / api / websocket / seed)
- [x] Frontend modules are organised (core / views / details / forms; 5 CSS files)
- [x] API validation works · [x] Error handling is structured
- [x] Unit tests pass (V1: 119 · V2: 148) · [x] API tests pass (V1: 37 · V2: 68) · [x] Integration tests pass (7)
- [x] Documentation matches implementation (written after the code and checked against it)
- [x] Setup and run instructions work on Windows (the documented commands were the ones used to install, migrate, seed, run and test on this machine; a from-scratch clone on a second machine has not been tried)

## Completed / pending / blocked

- **Completed:** all modules and endpoints in spec §9 and §13, the pipeline in §10.4, and the tests in §16.
- **Pending:** none within V1 scope.
- **Blocked:** none.
- **Not exercised by an automated test:** the UI refresh after a WebSocket *reconnect* (the server was not restarted during a browser session). It is implemented in `frontend/js/app.js`.

## Deliberate additions (within scope, documented)

Supporting tables and columns, four read-only endpoints (`GET /threats/{id}`, `GET /vulnerabilities/{id}`,
`GET /detections/rules`, `GET /audit/facets`), optional `branch_id` on dashboard endpoints, proposed
threat T8, the `BASELINE` scenario identifier for benign seed history, and the optional `ui-tests/`
harness. See ARCHITECTURE.md → *Implementation decisions*.
