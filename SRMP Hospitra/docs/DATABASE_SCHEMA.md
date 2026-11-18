# Database schema

SQLite, managed by Alembic (`versions/0001_initial_schema.py`, `versions/0002_v2_users_sessions_controls_residual_risk.py`).
Tests (`tests/unit/test_migrations.py`) verify that the migrations produce exactly the ORM schema,
that a populated V1 database upgrades with residual values backfilled, and that downgrade/upgrade
round-trips. Foreign keys are enforced (`PRAGMA foreign_keys=ON`).

Conventions: primary keys are UUID strings (`VARCHAR(36)`); all timestamps are **UTC** (stored naive,
returned timezone-aware, serialised as ISO 8601 with `Z`); enums are stored as their value with a
CHECK constraint; constraint names follow a fixed naming convention.

## Entities

### branches
| Column | Type | Notes |
|---|---|---|
| id | uuid | PK |
| code | str(16) | **UNIQUE** — `A`, `B`, `C` |
| name, role, location_label | str | fictional |
| site_id | int | **UNIQUE** — 20, 21, 22 (addressing `10.<site_id>.<vlan>.0/24`) |
| active | bool | |
| created_at | UTC datetime | |

### network_zones
| Column | Type | Notes |
|---|---|---|
| id | uuid | PK |
| branch_id | FK → branches | indexed |
| name, code | str | e.g. "Clinical Workstations", `CLN` |
| zone_type | enum | management, staff, clinical, application, medical, guest, security, dmz |
| vlan_id | int | **UNIQUE (branch_id, vlan_id)** |
| subnet_cidr | str | **UNIQUE** |
| description | text | |

### assets
| Column | Type | Notes |
|---|---|---|
| id | uuid | PK |
| asset_tag | str(32) | **UNIQUE**, e.g. `HSP-A-CLN-001` |
| name, operating_system, owner | str | |
| asset_type | enum | Network Device, Server, Database Server, Workstation, Medical Device, Access Point, Endpoint, Security Appliance, Web Server, VPN Gateway (indexed) |
| ip_address | str | validated IPv4 inside the zone subnet (service layer) |
| criticality | enum | Low, Medium, High, Critical (indexed) |
| data_classification | enum | Public, Internal, Confidential, Restricted — **separate from CIA** |
| confidentiality, integrity, availability | int | CHECK 1–5 |
| status | enum | Active, Warning, Offline, Maintenance (indexed) |
| branch_id, zone_id | FK | indexed; zone must belong to branch (service layer) |
| last_seen_at, created_at, updated_at | UTC datetime | |

### threats / vulnerabilities
| Column | Type | Notes |
|---|---|---|
| id | uuid | PK |
| code | str(16) | **UNIQUE** (T1…, V1…) |
| name, description | str/text | |
| category (threats) / weakness_type (vulnerabilities) | str | |
| source_type | enum | `Case Study` or `Proposed` |
| active | bool | |
| created_at | UTC datetime | |

### threat_vulnerability_pairs
Documented, technically plausible pairings only. `threat_id`, `vulnerability_id` (FKs, **UNIQUE pair**), `rationale` text.

### risks
| Column | Type | Notes |
|---|---|---|
| id | uuid | PK |
| reference | str | **UNIQUE**, `RSK-0001` |
| asset_id, threat_id, vulnerability_id | FK | **UNIQUE (asset, threat, vulnerability)** |
| likelihood, confidentiality_impact, integrity_impact, availability_impact | int | inputs, CHECK 1–5 |
| overall_impact | int | **derived**, CHECK 1–5 |
| risk_score | int | **derived**, CHECK 1–25 (indexed) |
| severity | enum | **derived**: Low, Moderate, High, Critical (indexed) |
| treatment | enum | Mitigate, Accept, Transfer, Avoid |
| owner | str | |
| status | enum | Open, In Treatment, Closed (indexed) |
| created_at, updated_at | UTC datetime | |

Derived fields are written only by `risk_service.apply_assessment` → `core.risk_model.assess_risk`;
the API rejects them as input.

### simulation_runs
`id`, `scenario_id`, `scenario_name`, `branch_id` (FK), `triggered_by`, `status`, `event_count`,
`matched_detection_count`, `incident_count`, `started_at` (indexed), `completed_at`.

### security_events
| Column | Type | Notes |
|---|---|---|
| id | uuid | PK |
| event_type | enum | network_access, auth_failure, vpn_login, device_observed, outbound_transfer, request_volume, file_activity, vendor_access, telemetry (indexed) |
| branch_id | FK | indexed; composite index (branch_id, occurred_at) |
| source_asset_id, destination_asset_id | FK, nullable | null for unregistered devices / external parties |
| source_zone_id, destination_zone_id | FK, nullable | |
| source_ip, destination_ip | str, nullable | IP or CIDR |
| severity | enum | indexed |
| message | text | human-readable description |
| is_simulated | bool | **CHECK is_simulated = 1** |
| scenario_id | str | S1–S8 or BASELINE (indexed) |
| simulation_run_id | FK, nullable | |
| metadata | JSON | scenario-specific fields (attribute `event_metadata` in the ORM) |
| occurred_at | UTC datetime | indexed |
| created_at | UTC datetime | |

### detections
`id`, `event_id` (FK), `rule_id`, `rule_name`, `matched`, `severity`, `explanation`, `evidence` (JSON),
`asset_id` (FK, nullable), `created_at`. **UNIQUE (event_id, rule_id)** — re-processing cannot duplicate.
A detection is kept separate from the raw event.

### incidents
| Column | Type | Notes |
|---|---|---|
| id | uuid | PK |
| incident_number | str | **UNIQUE**, `INC-0001` |
| title, description | str/text | |
| severity | enum | High or Critical in practice (indexed) |
| status | enum | Open, Investigating, Contained, Resolved, Closed (indexed) |
| assigned_to | str, nullable | operator label |
| detection_id | FK → detections | **UNIQUE** — one incident per detection |
| resolution_notes | text | concatenated Resolution notes |
| created_at, updated_at, resolved_at, closed_at | UTC datetime | |

Association tables: **incident_events** (incident_id, event_id) and **incident_assets** (incident_id, asset_id).

### incident_notes
`id`, `incident_id` (FK, cascade), `note_type` (Investigation, Containment, Resolution), `body`, `author`, `created_at`.

### audit_logs
`id`, `actor`, `action` (indexed), `entity_type` + `entity_id` (composite index), `details` (JSON),
`timestamp` (UTC, indexed). Append-only: no update/delete API.

## Version 2 additions (migration `0002`)

### users
`id`, `username` (**UNIQUE**, lowercase), `display_name`, `role` (Admin / Analyst / Viewer, indexed),
`password_hash` (PBKDF2-SHA256 `pbkdf2_sha256$iterations$salt$hash` — never returned by the API),
`active`, `created_at`, `updated_at`, `last_login_at`. **Kept on demo reset.**

### user_sessions
`id`, `token_hash` (**UNIQUE**, SHA-256 of the cookie token — the token itself is never stored),
`user_id` (FK, cascade), `created_at`, `expires_at` (indexed), `revoked_at`. **Kept on demo reset.**

### security_controls
`id`, `code` (**UNIQUE**, C01…), `name`, `description`, `control_type` (Preventive / Detective /
Corrective, indexed), `category`, `active`, `created_at`, `updated_at`.

### control_vulnerabilities
Association (control_id, vulnerability_id): which vulnerabilities a control is designed to address.
Used to suggest controls when linking; it does not affect the calculation.

### risk_controls
`id`, `risk_id` (FK, cascade), `control_id` (FK), **UNIQUE (risk_id, control_id)**,
`implementation_status` (Planned / Implemented), `effectiveness` (Partial / Substantial), `notes`,
`created_at`, `updated_at`.

### risks — new derived columns
`residual_likelihood` (CHECK 1–5), `residual_impact` (CHECK 1–5), `residual_score` (CHECK 1–25,
indexed), `residual_severity` (enum, indexed). Migration `0002` backfills existing rows with the
inherent values before adding NOT NULL and CHECK constraints; `downgrade` removes them cleanly.

## Relationships

```text
branches 1─* network_zones 1─* assets
branches 1─* assets
assets 1─* risks *─1 threats
           risks *─1 vulnerabilities
threats *─* vulnerabilities   (via threat_vulnerability_pairs, with rationale)
simulation_runs 1─* security_events 1─* detections 1─0..1 incidents
incidents *─* security_events (incident_events)
incidents *─* assets          (incident_assets)
incidents 1─* incident_notes
risks *─* security_controls     (via risk_controls: status + effectiveness)   [v2]
security_controls *─* vulnerabilities (control_vulnerabilities)               [v2]
users 1─* user_sessions                                                       [v2]
```
