# API reference

Base URL: `http://127.0.0.1:8000`. Versioned prefix: `/api/v1`. Interactive schema: `/docs`
(Swagger UI) and `/openapi.json` — these are generated from the code and always authoritative for
field-level request/response schemas.

## Conventions

- JSON everywhere (CSV/PDF only on `/exports`). Timestamps are UTC ISO 8601 with `Z`, e.g. `2026-11-16T16:21:42.474000Z`.
- **Authentication (V2):** every `/api/v1/*` endpoint except `/api/v1/auth/status`, `/auth/login` and
  `/auth/bootstrap` requires the `hospitra_session` cookie (HttpOnly, SameSite=Strict, 8 h). `/health` is public.
  Writes are attributed to the signed-in username in the audit log.
- **Roles:** reads and exports — any role; operate (marked **[Analyst]**) — Analyst or Admin; administer
  (marked **[Admin]**) — Admin only. Missing session → 401 `not_authenticated`; wrong role → 403 `forbidden`.
- **Collections** are paginated: `?limit=` (1–200, default 50) and `?offset=` (≥ 0):
  ```json
  { "items": [ ... ], "total": 48, "limit": 50, "offset": 0 }
  ```
  (`/branches`, `/zones`, `/simulation/scenarios`, `/detections/rules` return small fixed lists.)
- **Errors** never contain stack traces or SQL:
  ```json
  {"error": {"code": "validation_error", "message": "Request validation failed.",
             "details": [{"field": "risk_score", "message": "Extra inputs are not permitted", "type": "extra_forbidden"}]}}
  ```

| HTTP | `code` | When |
|---|---|---|
| 401 | `not_authenticated` | No/expired/revoked session, or wrong credentials at login |
| 403 | `forbidden` | Signed in, but the role lacks the permission (`details.required_permission`) |
| 429 | `too_many_attempts` | 5 failed sign-ins for a username within 15 minutes |
| 404 | `not_found` | Unknown ID or route |
| 409 | `conflict` | Duplicate asset tag / catalogue code / risk combination; modifying a Closed incident |
| 409 | `invalid_status_transition` | Incident status not equal to the single permitted next status |
| 409 | `integrity_error` | Database constraint violation not caught earlier |
| 422 | `validation_error` | Schema validation, unknown fields, enum/range errors, invalid references, IP outside zone subnet |
| 500 | `internal_error` | Unexpected failure (details logged server-side only) |

## Health

`GET /health` → `{"status":"ok","service":"hospitra","version":"2.0.0","database":"ok","timestamp":"…"}`

## Authentication (V2)

| Method & path | Notes |
|---|---|
| `GET /api/v1/auth/status` | Public. `{bootstrap_required, password_min_length, authenticated, user}` |
| `POST /api/v1/auth/bootstrap` | Public, **only while no user exists** (else 409). `{username, display_name, password}` → creates the first Admin and signs in (201) |
| `POST /api/v1/auth/login` | `{username, password}` → `Me` + `Set-Cookie`. Generic 401 for unknown user / wrong password / inactive; 429 after 5 failures |
| `POST /api/v1/auth/logout` | Revokes this session; 204 |
| `GET /api/v1/auth/me` | `{id, username, display_name, role, active, created_at, updated_at, last_login_at, permissions: ["read", "operate"?, "admin"?]}` |
| `POST /api/v1/auth/change-password` | `{current_password, new_password}`; revokes your other sessions; 204 |

Passwords: 10–128 characters, no leading/trailing whitespace. Usernames: 3–40 of `a–z 0–9 . _ -` (lower-cased).

## Users (V2) **[Admin]**

| Method & path | Notes |
|---|---|
| `GET /api/v1/users` | Paginated; never includes password hashes |
| `POST /api/v1/users` | `{username, display_name, role, password}`; duplicate → 409 |
| `PATCH /api/v1/users/{id}` | `display_name`, `role`, `active`, `password` (reset). Role change, deactivation or password reset revokes that user's sessions. Cannot deactivate yourself or remove the last active Admin (409). Username is immutable |

## Security controls (V2)

| Method & path | Notes |
|---|---|
| `GET /api/v1/controls` | `search`, `control_type`, `category`, `active`; items include `axis` (likelihood/impact), `vulnerabilities[]`, `linked_risk_count`, `implemented_link_count` |
| `GET /api/v1/controls/categories` | Distinct categories |
| `POST /api/v1/controls` **[Analyst]** | `{code, name, description, control_type, category, active?, vulnerability_ids?}`; duplicate code → 409 |
| `GET /api/v1/controls/{id}` | |
| `PATCH /api/v1/controls/{id}` **[Analyst]** | `name`, `description`, `control_type`, `category`, `active`, `vulnerability_ids`; changing type/active recalculates residual risk on linked risks (listed in the audit entry) |
| `POST /api/v1/risks/{id}/controls` **[Analyst]** | `{control_id, implementation_status: Planned|Implemented, effectiveness: Partial|Substantial, notes?}` → updated risk (201). Inactive control → 422; already linked → 409 |
| `PATCH /api/v1/risks/{id}/controls/{control_id}` **[Analyst]** | `implementation_status`, `effectiveness`, `notes` → updated risk |
| `DELETE /api/v1/risks/{id}/controls/{control_id}` **[Analyst]** | Unlinks (the control is kept) → updated risk |

## Dashboard

| Method & path | Query | Returns |
|---|---|---|
| `GET /api/v1/dashboard/summary` | `branch_id?` | `assets{total,active,warning,offline,maintenance}`, `incidents{total,open_total,open_by_severity,by_severity,by_status}`, `events{total,last_24h}`, `detections{matched_total,matched_last_24h,alerts_without_incident}`, `risks{total,by_severity}`, `recent_detections[]`, `branches[]` (posture + reason), `asset_distribution{by_branch,by_zone}`, `recent_activity[]` |
| `GET /api/v1/dashboard/event-trends` | `days` (1–30, default 7), `branch_id?` | `series[]` of `{date, Low, Moderate, High, Critical, total, detections}` per UTC day |
| `GET /api/v1/dashboard/risk-distribution` | `branch_id?` | `by_severity`, `by_branch[]`, `matrix.counts[likelihood-1][impact-1]`, `total` |

## Branches and zones (read-only)

| Method & path | Notes |
|---|---|
| `GET /api/v1/branches` | `[{id, code, name, role, site_id, location_label, active, created_at, zone_count, asset_count}]` |
| `GET /api/v1/branches/{branch_id}` | Branch + `zones[]` |
| `GET /api/v1/zones` | `?branch_id`, `?zone_type`; `[{id, branch_id, branch_code, name, code, zone_type, vlan_id, subnet_cidr, description, asset_count}]` |
| `GET /api/v1/zones/{zone_id}` | |

## Assets

| Method & path | Notes |
|---|---|
| `GET /api/v1/assets` | Filters: `search` (name/tag/IP), `branch_id`, `zone_id`, `zone_type`, `asset_type`, `criticality`, `status`; `sort` ∈ asset_tag, name, asset_type, ip_address, owner, criticality, data_classification, status, last_seen_at, branch, zone; `order` asc/desc |
| `POST /api/v1/assets` | 201. Body below. Tag normalised to upper case and must be unique (409); zone must belong to branch and IP must be inside the zone subnet (422) |
| `GET /api/v1/assets/{id}` | Asset + `risks[]` summary, `open_incident_count`, `event_count` |
| `PATCH /api/v1/assets/{id}` | Any subset of the create fields; relations re-validated; audited with a field diff |

Asset create body:
```json
{"asset_tag": "HSP-A-ADM-010", "name": "Reception Workstation", "asset_type": "Workstation",
 "ip_address": "10.20.20.40", "operating_system": "Windows 11 Enterprise", "criticality": "Medium",
 "data_classification": "Internal", "confidentiality": 2, "integrity": 3, "availability": 2,
 "status": "Active", "owner": "Corporate IT Service Desk", "branch_id": "<uuid>", "zone_id": "<uuid>"}
```
There is deliberately **no DELETE** (405).

## Threats and vulnerabilities

| Method & path | Notes |
|---|---|
| `GET /api/v1/threats` | `search`, `active`, `source_type` (`Case Study`/`Proposed`); each item includes `risk_count` and `related_vulnerabilities[{id, code, name, rationale}]` |
| `POST /api/v1/threats` | `{code, name, description, category, source_type?=Proposed, active?=true}`; duplicate code → 409 |
| `GET /api/v1/threats/{id}` | *(additional read endpoint)* |
| `PATCH /api/v1/threats/{id}` | `name`, `description`, `category`, `active` (code and source type are immutable) |
| `GET /api/v1/vulnerabilities` | as above, with `weakness_type` and `related_threats[]` |
| `POST /api/v1/vulnerabilities` | `{code, name, description, weakness_type, source_type?, active?}` |
| `GET /api/v1/vulnerabilities/{id}` | *(additional read endpoint)* |
| `PATCH /api/v1/vulnerabilities/{id}` | `name`, `description`, `weakness_type`, `active` |

## Risks

| Method & path | Notes |
|---|---|
| `GET /api/v1/risks` | `search`, `branch_id`, `asset_id`, `threat_id`, `vulnerability_id`, `control_id`, `severity`, `residual_severity`, `status`, `treatment`; `sort` ∈ reference, risk_score, severity, residual_score, residual_severity, likelihood, overall_impact, status, treatment, owner, updated_at, asset (default `risk_score desc`) |
| `POST /api/v1/risks` **[Analyst]** | 201. `{asset_id, threat_id, vulnerability_id, likelihood, confidentiality_impact, integrity_impact, availability_impact, treatment, owner, status?=Open}` — derived fields are rejected; inactive threat/vulnerability → 422; duplicate combination → 409 |
| `GET /api/v1/risks/{id}` | |
| `PATCH /api/v1/risks/{id}` | Any of the inputs + `treatment`, `owner`, `status`; recalculated server-side |

Risk response (abridged):
```json
{"id": "…", "reference": "RSK-0001",
 "asset": {"id": "…", "asset_tag": "HSP-A-CLN-001", "name": "…", "branch_code": "A", "zone_name": "Clinical Workstations", "criticality": "High", "data_classification": "Restricted"},
 "threat": {"id": "…", "code": "T1", "name": "Ransomware spread"},
 "vulnerability": {"id": "…", "code": "V6", "name": "Unpatched or unsupported systems"},
 "likelihood": 4, "confidentiality_impact": 4, "integrity_impact": 3, "availability_impact": 5,
 "overall_impact": 5, "risk_score": 20, "severity": "Critical", "treatment": "Mitigate", "owner": "…", "status": "In Treatment",
 "calculation": {"formula": "Risk Score = Likelihood × max(Confidentiality, Integrity, Availability)",
                 "impact_expression": "Impact = max(C 4, I 3, A 5) = 5", "score_expression": "Score = 4 × 5 = 20",
                 "severity_band": "17–25 → Critical", "explanation": "…"},
 "pairing_rationale": "Unpatched systems offer known exploitation paths …",
 "residual_likelihood": 3, "residual_impact": 3, "residual_score": 9, "residual_severity": "Moderate",
 "residual_calculation": {"rule": "Only implemented controls count. …",
   "likelihood_expression": "Residual L = max(1, 4 − 1) (C06) = 3",
   "impact_expression": "Residual Impact = max(1, 5 − 2) (C08) = 3",
   "score_expression": "Residual Score = 3 × 3 = 9", "severity_band": "5–9 → Moderate"},
 "controls": [{"control_id": "…", "code": "C06", "name": "Patch and vulnerability management", "control_type": "Preventive",
               "axis": "likelihood", "implementation_status": "Implemented", "effectiveness": "Partial",
               "reduction": 1, "counted": true, "applied": true, "…": "…"}]}
```

## Events and detections

| Method & path | Notes |
|---|---|
| `GET /api/v1/events` | `search` (message/IP/asset tag/id), `severity`, `event_type`, `branch_id`, `scenario_id`, `asset_id`, `detection_status` ∈ detected/no_match/not_evaluated, `since`, `until` (ISO datetimes), `order` (default desc by `occurred_at`) |
| `GET /api/v1/events/{id}` | Event + `detections[]` (all rule evaluations), `rules[]` (definitions), `risk_context[]`, `incident` |
| `GET /api/v1/detections` | `matched` (true = alerts), `rule_id`, `severity`, `branch_id`, `event_id`, `since` |
| `GET /api/v1/detections/rules` | *(additional)* rule catalogue R1–R8 |
| `GET /api/v1/detections/{id}` | Detection + `rule` + `risk_context[]` + incident link |

Event item fields: `id, event_type, branch_id, branch_code, source_asset, destination_asset, source_zone,
destination_zone, source_ip, destination_ip, severity, message, is_simulated, scenario_id,
simulation_run_id, metadata, occurred_at, created_at, detection_status, matched_rules[]`.

Detection fields: `id, event_id, rule_id, rule_name, matched, severity, explanation, evidence, asset_id,
asset_tag, created_at, event{…}, incident_id, incident_number`.

## Simulation

| Method & path | Notes |
|---|---|
| `GET /api/v1/simulation/scenarios` | S1–S8 with expected rule, severity, `creates_incident`, `event_count`, source/destination description |
| `POST /api/v1/simulation/trigger` | `{"scenario_id": "S1", "branch_code": "A"}` (branch optional, default A; only S1–S8 and A–C accepted). 201 → `{run, event_ids, matched_detection_ids, incident_ids, summary}` |
| `GET /api/v1/simulation/history` | Paginated `simulation_runs` (newest first) |
| `POST /api/v1/simulation/reset` **[Admin]** | `{"confirm": "RESET"}` (anything else → 422). Deletes all demo data (user accounts are kept) and reseeds → `{status, created}` |

## Incidents

| Method & path | Notes |
|---|---|
| `GET /api/v1/incidents` | `search`, `status`, `severity`, `branch_id`, `active_only` |
| `GET /api/v1/incidents/{id}` | Incident + `notes[]`, `events[]`, `assets[]`, `detection`, `risk_context[]`, `history[]` (audit), `allowed_next_status` |
| `PATCH /api/v1/incidents/{id}` | Any of `status`, `assigned_to`, `note: {note_type: Investigation|Containment|Resolution, body}`; at least one required. Status must equal `allowed_next_status`. Closed incidents are immutable (409). Returns the detail view |

Invalid transition example (`Open` → `Resolved`):
```json
{"error": {"code": "invalid_status_transition", "message": "Cannot change status from Open to Resolved.",
  "details": {"current_status": "Open", "requested_status": "Resolved", "allowed_next_status": "Investigating",
              "lifecycle": ["Open", "Investigating", "Contained", "Resolved", "Closed"]}}}
```

## Audit

| Method & path | Notes |
|---|---|
| `GET /api/v1/audit` | `entity_type`, `entity_id`, `action` (prefix match), `actor`, `since`, `until`; newest first |
| `GET /api/v1/audit/facets` | *(additional)* distinct `entity_types` and `actions` |

Audit item: `{id, actor, action, entity_type, entity_id, details, timestamp}`. Actions recorded:
`asset.created/updated`, `threat.created/updated`, `vulnerability.created/updated`, `risk.created/updated`,
`event.created`, `detection.matched/no_match`, `incident.created/status_changed/assigned/note_added`,
`simulation.triggered`, `seed.applied`, `data.reset`.

## Exports

| Path | Content |
|---|---|
| `GET /api/v1/exports/assets.csv` | `asset_tag, name, asset_type, branch, zone, vlan_id, ip_address, operating_system, owner, criticality, data_classification, confidentiality, integrity, availability, status, last_seen_at_utc, created_at_utc, updated_at_utc` |
| `GET /api/v1/exports/risks.csv` | `risk_reference, asset_tag, asset_name, branch, threat_code, threat, vulnerability_code, vulnerability, likelihood, confidentiality_impact, integrity_impact, availability_impact, overall_impact, risk_score, severity, treatment, owner, status, created_at_utc, updated_at_utc` |
| `GET /api/v1/exports/events.csv` | `event_id, occurred_at_utc, event_type, branch, source_asset, source_zone, source_ip, destination_asset, destination_zone, destination_ip, severity, detection_status, matched_rules, is_simulated, scenario_id, message` |
| `GET /api/v1/exports/incidents.csv` | `incident_number, title, severity, status, assigned_to, branch, rule_id, rule_name, asset_tags, event_count, created_at_utc, updated_at_utc, resolved_at_utc, closed_at_utc, resolution_notes` |
| `GET /api/v1/exports/summary.pdf` | A4 report: title, generation time, overview, branch status, risk distribution, top 15 risks, latest 25 incidents, recent detections, "Page X of Y" |

CSV files are UTF-8 with BOM, one header row, `_utc` columns in ISO 8601 `Z`. All exports are sent as
attachments named `hospitra-<name>-<UTC timestamp>.<ext>`.

## WebSocket

`ws://127.0.0.1:8000/ws/events` — requires the session cookie (V2); without a valid session the socket is
closed with code **4401**. Server → client notifications `{type, data, timestamp}` are published only
after a successful commit (see SIMULATION_AND_DETECTION.md). Client may send `"ping"` → `{"type":"pong"}`.
Messages are notifications only; clients re-read state over REST.
