# Simulation and detection

## Safety properties

- Scenarios are **pure functions** of (target branch, trigger time) that return event drafts. They
  never touch a network interface, open sockets, execute commands or contact external systems.
- Every event is persisted with `is_simulated = true` (DB CHECK constraint), a `scenario_id`, a
  timestamp, source/destination context and a description, **before** it is shown anywhere.
- "External" addresses come from the reserved documentation ranges 198.51.100.0/24 and 203.0.113.0/24.
- There is no event-ingestion endpoint; events are only created by the simulator.
- Mode: **operator-triggered only** (no continuous/autonomous simulation).

Content is deterministic: the same scenario on the same branch always produces the same assets,
addresses, metadata and rule outcome. Timestamps (trigger time) and UUIDs naturally differ per run.

## Scenarios (approved severity configuration)

| ID | Scenario | Events | Source → destination (per branch) | Rule | Severity | Incident |
|---|---|---:|---|---|---|---|
| S1 | Guest-to-Clinical Access Attempt | 1 | GST-002 kiosk → APP-001 records server, TCP/443 | R1 | High | Yes |
| S2 | Repeated Authentication Failures | 5 | ADM-001 → NET-002, SSH, one account, 50 s apart | R2 | Moderate | No |
| S3 | Unusual VPN Login | 1 | 198.51.100.23 → DMZ-002 VPN gateway, unrecognised region, unmanaged device | R3 | Moderate | No |
| S4 | Unknown Device in Sensitive Zone | 1 | Unregistered 10.<site>.50.199 in Medical Devices | R4 | High | Yes |
| S5 | Unusual Outbound Transfer | 1 | APP-002 database → 203.0.113.45, 2048 MB | R5 | High | Yes |
| S6 | DDoS-like Request Volume | 1 | 203.0.113.0/24 → DMZ-001 portal, 48 000 req/min (baseline 1 200) | R6 | High | Yes |
| S7 | Ransomware-like Behaviour | 6 | CLN-001 → ADM-002 file share: 1 benign read + 5 suspicious operations | R7 | Critical | Yes |
| S8 | Vendor Access Outside Approved Window | 1 | 198.51.100.77 → MED-002, window ended the previous day | R8 | Moderate | No |

`BASELINE` (seed only): benign activity of every event type (4 events per branch per day for 7 days).
All baseline events are evaluated by the rules; none match.

## Rules

Each rule has an ID, name, description, applicable event types, human-readable conditions, severity,
explanation template, enabled flag, and related threat/vulnerability codes (used for risk context).
`GET /api/v1/detections/rules` returns the catalogue.

| Rule | Event type | Conditions | Severity | Related |
|---|---|---|---|---|
| R1 Guest-to-restricted-zone access violation | network_access | source zone = guest **and** destination zone ∈ {management, staff, clinical, application, medical, security} | High | T3, T1 / V1, V3 |
| R2 Repeated authentication failures | auth_failure | ≥ 5 failures from the same source within 300 s, no earlier R2 match for that source within ±300 s | Moderate | T2, T6 / V2, V7 |
| R3 Unusual VPN access | vpn_login | login region ∉ approved regions **or** device posture ≠ managed | Moderate | T2 / V2 |
| R4 Unknown device in restricted zone | device_observed | no registered asset **and** zone ∈ {management, clinical, application, medical, security} | High | T8, T3 / V1 |
| R5 Unusual outbound transfer | outbound_transfer | destination outside 10.0.0.0/8 **and** bytes_out ≥ 500 MB | High | T6, T7 / V7, V5 |
| R6 DDoS-like request volume | request_volume | target zone = dmz **and** requests/min ≥ 10 × baseline | High | T5 / V5 |
| R7 Ransomware-like behaviour | file_activity | ≥ 5 suspicious operations (shadow_copy_delete, mass_rename, high_entropy_write, ransom_note_create) from one endpoint within 120 s, no earlier R7 match within ±120 s | Critical | T1 / V6, V8, V1 |
| R8 Vendor access policy violation | vendor_access | access time ∉ [approved_window_start, approved_window_end] (or no valid window) | Moderate | T7 / V7, V2 |

`telemetry` events have no applicable rule and are shown as **Not evaluated**.

### Detection output

For each applicable rule the engine returns and stores: rule ID, rule name, match result, severity,
evidence fields (JSON), a human-readable explanation, the related event ID and, where applicable, the
related asset ID. Non-matches are stored too, with an explanation of why the condition was not met
(e.g. *"Below threshold: 4 failed authentication(s) … (threshold 5)"*).

A detection is an **investigation lead**, not proof of malicious activity. This is stated in the UI,
the incident description and the PDF.

### Threshold rules and suppression

R2 and R7 look back over persisted events from the same source. They fire once per source per
window: further events inside ±window of an existing match are stored as non-matching with a
"Suppressed: …" explanation. Consequence for demos: re-triggering S2 within 5 minutes (or S7 within
2 minutes) on the **same branch** records the events but raises no new detection.

## Risk context

For a matched detection, the affected assets are the detection's asset plus the event's source and
destination assets; for an unregistered device (S4) they are the assets in the observed zone. Risk
context = risks on those assets whose threat **or** vulnerability is in the rule's related codes.
It is computed at read time and shown in the event, detection and incident views.

## Incident policy

| Detection severity | Result |
|---|---|
| Low, Moderate | No incident; the detection stays visible in Threat Monitoring and the dashboard ("alert only") |
| High, Critical | Exactly one incident (`incidents.detection_id` is UNIQUE) |

The incident links the triggering event, any contributing events listed in the evidence (R2/R7), and
the affected assets. No cross-event correlation or aggregation into existing incidents is performed.

## Duplicate-processing protection

`simulation_service.process_event(event)` may be called repeatedly: existing detections are reused
(UNIQUE event+rule), no new audit entries are written, and no second incident can be created.
Covered by `test_reprocessing_an_event_is_idempotent` and `test_reprocessing_via_pipeline_is_idempotent`.

## WebSocket messages

V2: the socket requires a valid session cookie (otherwise closed with code 4401). Triggering a
scenario requires the Analyst or Admin role; the run's `triggered_by` and the `simulation.triggered`
audit entry record the signed-in username.

| type | When | data |
|---|---|---|
| `connected` | on connect | `{clients}` |
| `simulation.completed` | after a committed run | run id, scenario, branch, event ids, matched detection ids, incidents, summary |
| `incident.updated` | after a committed incident PATCH | incident id, number, status |
| `risk.changed` | after risk create/update | risk id, reference, action |
| `data.reset` | after reset | created counts |
| `pong` | reply to client `"ping"` | `{}` |
