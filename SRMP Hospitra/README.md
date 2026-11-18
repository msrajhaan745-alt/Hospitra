# Hospitra — Hospital Network Security & Risk Monitoring Platform (v2)

> **DEMO ENVIRONMENT — SYNTHETIC DATA.** Hospitra is an academic proof of concept. Every hospital
> branch, asset, address, event and incident is fictional. It is **not** a production SOC tool,
> intrusion detection system, scanner or compliance product. Version 2 adds sign-in and roles, but it
> still runs over plain HTTP on localhost and has not been security-assessed for network exposure.

Hospitra demonstrates how a hospital IT/security team could keep visibility of a segmented network,
organise threats and vulnerabilities, assess illustrative risks with a transparent formula, apply
security controls to see **residual** risk, observe **synthetic** security events, detect selected
policy violations with **deterministic rules**, manage incidents through a fixed lifecycle, and keep an
audit trail attributed to signed-in users — all in one locally run application.

```
Synthetic hospital network → Simulation → Security event → Deterministic detection
   → Risk context (inherent & residual) → Incident (High/Critical only) → Audit trail → Live update (WebSocket)
```

## What's new in Version 2

- **Sign-in and roles.** Viewer (read + export), Analyst (+ operate: simulations, incidents, assets, catalogue, risks, controls), Admin (+ users, demo reset). Enforced by the server on every API call and the WebSocket; the UI hides what a role cannot do. First-run setup creates the first Admin — there are no default passwords.
- **Security controls and residual risk.** A 12-control illustrative library; controls are linked to risks as *Planned* or *Implemented* with *Partial* / *Substantial* effectiveness. Residual risk is recalculated by the server (see [Risk model](docs/RISK_MODEL.md)).
- Audit entries now record the real username; sign-ins, failed sign-ins and user changes are audited.

## Features

| Module | What it does |
|---|---|
| **Command Centre** | KPIs, branch status, 4 Chart.js charts (events over time, risk severity with **inherent/residual toggle**, incidents by severity, assets by branch/zone), recent detections and activity — computed from the database, refreshed live over WebSocket. |
| **Network Infrastructure** | Interactive SVG topology per branch: WAN → gateway → core → 8 VLAN zones → 2 assets each, status rings, open-incident badges, zone policy intent, legend, asset details. |
| **Asset Inventory** | Search, 6 filters, server-side sorting, pagination, create/edit with validation. No delete. |
| **Threats & Vulnerabilities** | T1–T7 / V1–V8 case-study catalogue (+ proposed T8), documented plausible pairings with rationale. |
| **Threat Monitoring** | Simulation console (S1–S8) and a filterable event stream with rule explanation, evidence, risk context and incident link. |
| **Risk Register** | Inherent `L × max(C,I,A)` and residual scores side by side; link controls and see the server's calculation. |
| **Security Controls** *(v2)* | Control library (preventive / detective / corrective), addressed vulnerabilities, linked risks; deactivating a control recalculates residual risk. |
| **Incident Management** | Auto-created for High/Critical detections only; strict one-step lifecycle; notes; history. |
| **Reports & Audit** | Verified CSV exports, PDF summary (now with residual risk), filterable audit log, Admin-only demo reset. |
| **User Management** *(v2, Admin)* | Create users, change role, deactivate, reset passwords (sessions are revoked on changes). |

## Technology

Python 3.12 · FastAPI · Uvicorn · Pydantic v2 · SQLAlchemy 2 · SQLite · Alembic · ReportLab ·
Pytest + HTTPX · vanilla JavaScript (ES modules) · custom CSS · Chart.js 4.4.1 (vendored) · WebSocket.
Passwords: PBKDF2-SHA256 (Python standard library). Sessions: server-side, HttpOnly + SameSite=Strict
cookie. **No new third-party dependencies were added in V2.**

## Prerequisites (Windows)

- **Python 3.12+** — e.g. `winget install -e --id Python.Python.3.12 --scope user`
- A modern browser (Edge or Chrome).
- *Optional:* Node.js ≥ 22 and Chrome/Edge for the headless UI checks in `ui-tests/`.

## Installation

Run in **Windows PowerShell** from the project root (`c:\SRMP Hospitra`):

```powershell
cd backend
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Database migration and seeding

```powershell
cd backend
.\.venv\Scripts\python.exe -m alembic upgrade head        # creates or upgrades (V1 → V2 is migration 0002)
.\.venv\Scripts\python.exe -m app.seed.cli seed           # idempotent: safe to run repeatedly
```

Upgrading an existing V1 database keeps all data; residual values start equal to inherent values
until controls are linked. Running `seed` afterwards adds the control library and the sample links.

## Running the application

```powershell
cd backend
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open **http://127.0.0.1:8000/**.

**First sign-in:** if no accounts exist, the app shows **First-run setup** — choose the first Admin's
username and password (≥ 10 characters). Then add colleagues in **User Management**. Alternatively:

```powershell
.\.venv\Scripts\python.exe -m app.seed.cli create-user --username alice --display-name "Alice" --role Analyst
# the password is prompted (never passed on the command line)
```

API docs: **http://127.0.0.1:8000/docs** (API calls there require a signed-in browser session).

## Environment settings

| Variable | Default | Purpose |
|---|---|---|
| `HOSPITRA_DATABASE_URL` | `sqlite:///<project>/backend/data/hospitra.db` | Database location |
| `HOSPITRA_SESSION_HOURS` | `8` | Absolute session lifetime |
| `HOSPITRA_COOKIE_SECURE` | `false` | Set `true` when served over HTTPS |
| `HOSPITRA_PBKDF2_ITERATIONS` | `600000` | Password-hash work factor |

## Running the tests

```powershell
cd backend
.\.venv\Scripts\python.exe -m pytest            # unit, API and integration tests
```

Optional browser checks — point them at a **throwaway** database/server, because they create test
users and reset demo data:

```powershell
cd ui-tests
$env:HOSPITRA_UI_BASE = "http://127.0.0.1:8001"     # a separate test server
$env:HOSPITRA_UI_USER = "ui-admin"; $env:HOSPITRA_UI_PASSWORD = "<admin password>"
node run-all.mjs
```

Recorded results: [docs/TESTING.md](docs/TESTING.md).

## Resetting demo data (Admin)

UI: **Reports & Audit → Reset data…** (type `RESET`) · CLI: `python -m app.seed.cli reset` ·
API: `POST /api/v1/simulation/reset` with `{"confirm": "RESET"}`. All demo records and the audit log are
replaced in one transaction; **user accounts are kept**.

## Exporting reports

UI: **Reports & Audit → Exports** · API: `GET /api/v1/exports/{assets|risks|events|incidents}.csv`,
`GET /api/v1/exports/summary.pdf` (any signed-in role).

## Project structure

```text
backend/app/core/       config, enums/roles, risk model (inherent + residual), security (hashing), errors
backend/app/models/     SQLAlchemy models incl. user, security_control
backend/app/services/   domain services incl. user_service, control_service
backend/app/api/routes/ routers incl. auth, users, controls
backend/app/db/migrations/versions/  0001 initial schema, 0002 V2
frontend/js/            app.js, auth.js, details.js, forms.js, core/, views/ (incl. controls, users)
ui-tests/               optional headless-browser checks
docs/                   architecture, schema, API, simulation, risk model, testing, demo, status
```

## Documentation

**[User guide](docs/USER_GUIDE.md)** · [Architecture](docs/ARCHITECTURE.md) · [Database schema](docs/DATABASE_SCHEMA.md) ·
[API reference](docs/API_REFERENCE.md) · [Simulation & detection](docs/SIMULATION_AND_DETECTION.md) ·
[Risk model](docs/RISK_MODEL.md) · [Testing](docs/TESTING.md) · [Demo guide](docs/DEMO_GUIDE.md) ·
[Implementation status](docs/IMPLEMENTATION_STATUS.md) · [Known limitations](docs/KNOWN_LIMITATIONS.md) ·
[Changelog](docs/CHANGELOG.md)

## Safety boundaries

No network discovery, scanning, packet capture or traffic generation; no external lookups; no shell
commands; no host, account or network changes ("Containment" is a recorded status). All events are
synthetic (DB constraint). Keep the server on 127.0.0.1; before any network exposure add HTTPS (and
`HOSPITRA_COOKIE_SECURE=true`) and an independent security review. No regulatory or compliance claim.
