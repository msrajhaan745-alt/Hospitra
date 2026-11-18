# Testing

All results below were produced by actually running the commands on the development machine
(Windows 11, Python 3.12.10, Node.js 26.13.1, Chrome headless). V2 results: 2026-11-17.

## How to run

```powershell
cd backend
.\.venv\Scripts\python.exe -m pytest                  # everything
.\.venv\Scripts\python.exe -m pytest tests/unit -q
.\.venv\Scripts\python.exe -m pytest tests/api -q
.\.venv\Scripts\python.exe -m pytest tests/integration -q
```

Each test gets a fresh temporary SQLite file; the application database is never touched. Tests use
a low PBKDF2 work factor (`HOSPITRA_PBKDF2_ITERATIONS=1000`, set in `conftest.py`) for speed. The
`client` fixture is signed in as an Admin; `anon_client` has no session; `client_as(Role.X)` creates a
signed-in client for any role. `pytest.ini` silences one advisory Starlette warning about HTTPX.

## Recorded results (Version 2)

| Suite | Result |
|---|---|
| `tests/unit` | 148 tests |
| `tests/api` | 68 tests |
| `tests/integration` | 7 tests |
| **Full run (`pytest`)** | **223 passed, 0 failed** (145 s, run concurrently with the UI suite) |

V1 baseline for comparison: 163 tests. All 163 V1 tests still pass under V2; two assertions changed
from the fixed actor `local_operator` to the signed-in test username, because V2 records real users.

## Coverage map

### V1 scope (unchanged — see spec §16)
Risk formula and bands (all 25 L×I combinations), asset validation, branch–zone consistency, every
rule R1–R8 matching and non-matching, suppression, event normalisation, incident policy and
transitions, duplicate-processing protection, seed idempotency and reset, migrations, all REST
endpoints, CSV/PDF exports, and the end-to-end pipeline with WebSocket delivery and rollback on failure.

### V2 additions
| Area | Tests |
|---|---|
| Residual model | `unit/test_residual_model.py` — no controls, each axis, Partial/Substantial, **no stacking**, deterministic ties, floor of 1, exhaustive 5×5×3×3 check against the definition, invalid effects/inputs |
| Residual via services | `unit/test_controls_service.py` — seeded values match the model for all 42 risks; Planned → Implemented → unlink; inactive control cannot be linked; deactivating/reactivating a control recalculates linked risks (audited); changing a control's type moves its axis; editing inherent inputs recalculates residual |
| Password/session primitives | `unit/test_security.py` — hash round trip, salts, malformed hashes, token digests |
| Migration `0002` | `unit/test_migrations.py` — schema equals models; a populated **V1 database upgrades with residual = inherent**; downgrade/upgrade round trip |
| Authentication | `api/test_auth_api.py` — first-run bootstrap (once only, weak password rejected), 401 on 9 protected endpoints, public endpoints, WebSocket closed with 4401 without a session, hardened cookie flags, logout revocation, generic login errors, **lockout after 5 failures (429)**, expired sessions, password change revokes other sessions |
| Roles | Viewer: 6 reads/exports allowed, 8 writes denied (403). Analyst: simulate + incident updates allowed, reset and users denied. Admin: reset keeps user accounts |
| User management | Create/duplicate/list, role change revokes sessions, deactivation blocks sign-in, cannot demote the last Admin or deactivate yourself, audit entries |
| Controls API | Library, create/update/validation, link/patch/unlink with recalculation, derived residual fields not writable, residual filters/sorting, dashboard residual distribution, CSV residual columns, audit actor |

## Frontend validation (headless browser)

`ui-tests/` drives Chrome through the DevTools Protocol. V2 runs used an **isolated test server on
port 8001 with a throwaway database** (so the real database still shows first-run setup), an Admin
password generated per run, and `node run-all.mjs`.

| Script | Result |
|---|---|
| `ui_v2.mjs` — first-run setup (fresh DB), sign-in error, API closed without session, Viewer read-only UI (no Users nav, no Run scenario, trigger disabled, no reset, no New asset, read-only risk drawer, redirect from `#/users`), sign-out, Analyst can trigger (attributed to analyst) but has no reset/users, Admin user list and validation, **linking C04 lowers residual to 1 × 3 = 3**, Planned restores it, control library, deactivating C05 restores residual on its risk, dashboard residual toggle, V2 audit actions | **22/22** on a fresh DB; **21/21** on rerun (first-run step correctly skipped) |
| `ui_routes.mjs` — all 10 routes incl. Security Controls and User Management | 10/10, **no console errors or failed requests** |
| `ui_walkthrough.mjs` — spec §19 demo end-to-end (now signed in) | **28/28** |
| `ui_more.mjs` — live WebSocket refresh, branch context, sorting, empty/error states, risk & threat creation, keyboard | **13/13** |

HTTP errors logged during these runs are only the intentional ones: wrong password (401), invalid
forms (409/422) and a missing-record deep link (404).

### Defects found by the V2 browser runs and fixed
- Sign-out changed the route before reloading, so the dashboard briefly called the API with a revoked session (spurious 401s). Sign-out now reloads in place.
- Every first page load logged a 401 from the `/auth/me` probe. `/auth/status` now reports whether the cookie is valid, so signed-out visitors see no error.
- The `hidden` attribute was overridden by component `display` rules (`.btn`, `.pager`), a latent V1 bug: a global `[hidden]{display:none!important}` rule fixes it.
- Two test-script issues (CSS-uppercased headings in `innerText`; two severity badges per register row) were corrected in the scripts.

## Regression policy

Re-run `pytest` after any backend change and `ui-tests/run-all.mjs` (against a throwaway server)
after frontend or API-contract changes.
