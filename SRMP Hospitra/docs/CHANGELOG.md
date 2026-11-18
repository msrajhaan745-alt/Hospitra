# Changelog

## 2.0.0 — 2026-11-17

Scope approved by the project owner: **login + roles** and **security controls + residual risk**.

### Added
- **Authentication:** first-run setup (creates the first Admin; no default passwords), sign-in/out, change password, server-side sessions (HttpOnly, SameSite=Strict cookie, 8 h), PBKDF2-SHA256 password hashing, sign-in throttling, `create-user` CLI.
- **Roles:** Viewer (read/export), Analyst (+ operate), Admin (+ users, demo reset), enforced on every API route and on the WebSocket (close code 4401); role-aware UI.
- **User Management** view and `/api/v1/users` (Admin): create, change role, deactivate, reset password; sessions revoked on changes; last-Admin and self-deactivation guards.
- **Security controls:** 12-control illustrative library, `/api/v1/controls`, Security Controls view and drawer, control ↔ vulnerability "addresses" links.
- **Residual risk:** approved level-reduction model (`assess_residual`), risk ↔ control links with Planned/Implemented and Partial/Substantial, residual fields on risks, residual filter/sort, inherent/residual dashboard toggle, residual columns in CSV and PDF.
- Audit: real usernames as actors; `auth.*`, `user.*`, `control.*`, `risk.control_*` actions with before/after residual values.
- Alembic migration `0002` (backfills residual = inherent for existing V1 risks).
- Tests: 60 new backend tests (223 total); `ui-tests/ui_v2.mjs` (22 browser checks).

### Changed
- At the project owner's request, all "demo", "synthetic data", "illustrative" and "not proof / not a finding" labels and disclaimers were removed from the UI, the PDF/CSV exports, scenario/seed text, incident descriptions and API descriptions (header badge, PDF disclaimer box and footer, `SIM ·` prefix → scenario ID, `-synthetic-` in export filenames, `X-Hospitra-Data` header, `environment` field in `/health`, `is_illustrative` field and the `is_simulated` CSV column). The data-model constraint `is_simulated = 1` and the scenario IDs are unchanged.
- The reset action and WebSocket message are renamed `demo.reset` → `data.reset` ("Reset data" in the UI); older `demo.reset` audit entries still display correctly.
- `POST /simulation/reset` is Admin-only and keeps user accounts.
- `/auth/status` is public and reports whether the browser is signed in (no 401 on first load).
- The "local_operator" actor is now only used for CLI-initiated resets.

### Fixed
- Expired/invalid session on the live-update socket: the server closed the socket before accepting it, which reached the browser as an HTTP 403 (code 1006), so the page retried every 15 s indefinitely instead of returning to sign-in. The socket is now accepted and closed with code 4401, and the client checks `/auth/status` before reconnecting. Regression test: `test_websocket_rejection_happens_after_handshake`.
- Browsers could keep running the cached V1 frontend after the upgrade (files were served without `Cache-Control`). Frontend files are now `Cache-Control: no-cache`, and the first response to a browser without the current `hospitra_build` cookie carries `Clear-Site-Data: "cache"` (HTTP cache only; the session cookie is kept), so one reload picks up the current version.
- Global `[hidden]` rule so hidden buttons/pagers are actually hidden (latent V1 issue).

## 1.0.0 — 2026-11-16

First complete V1 implementation, built from an empty repository.

- **M0** Project structure, pinned dependencies (`backend/requirements.txt`), Chart.js 4.4.1 vendored, `.env.example`.
- **M1** FastAPI app factory, settings, structured error handling, SQLAlchemy 2 models (10 spec entities plus supporting tables), Alembic migration `0001`, Pydantic v2 schemas, `/health`, branches, zones, asset CRUD with validation, unit and API tests.
- **M2** Custom "Clinical Cyber Operations" design system, application shell (demo banner, sidebar, header with branch context, drawer stack, modals, toasts), API client, Command Centre with four Chart.js charts and dashboard endpoints.
- **M3** Idempotent deterministic seed (3 branches, 24 zones, 48 assets, catalogue, 42 risks, 7-day baseline history, historical runs), reset (UI/API/CLI), Asset Inventory, interactive SVG topology.
- **M4** Scenarios S1–S8, simulation service, event normalisation and persistence, rule engine R1–R8 with stored evidence and explanations, Threat Monitoring view, WebSocket manager and client.
- **M5** Threat & vulnerability catalogue with documented pairings, risk register with the agreed formula, incident creation policy and strict one-step lifecycle with notes and assignment, audit logging.
- **M6** CSV and PDF exports, end-to-end integration tests, headless UI checks (`ui-tests/`), documentation set.

### Fixes made during validation
- Threshold-rule suppression is symmetric (±window), so back-dated scenario events that are processed out of order still cannot produce a second match.
- WebSocket timestamps are serialised like REST responses (`…Z`).
- Frontend: CSS custom properties are set with `setProperty`; nested arrays are flattened in the simulation status; zone policy labels are shortened to fit; after a reconnect the UI refreshes from REST.
- PDF: human-readable UTC timestamps; risk table fits the A4 width. R3 explanation wording is clearer.
