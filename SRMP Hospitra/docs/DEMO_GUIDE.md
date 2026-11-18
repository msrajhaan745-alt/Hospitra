# Demonstration guide

Start from a clean dataset so the walkthrough is repeatable:

```powershell
cd backend
.\.venv\Scripts\python.exe -m app.seed.cli reset --yes
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open **http://127.0.0.1:8000/**.

## 0 · Sign in (Version 2)
- On a brand-new database the **First-run setup** screen appears: create the first Admin (no default passwords).
- Otherwise sign in. To show roles, have an Analyst and a Viewer account ready (create them in
  **User Management** or with `python -m app.seed.cli create-user …`). The demo reset keeps accounts.
- Point out the user menu (name + role) top-right, and the
  "Live updates: connected" indicator (bottom-left).

## 1 · Command Centre
- KPIs: 48 assets (43 Active · 3 Warning · 1 Offline · 1 Maintenance), open incidents by severity,
  events, detections ("alert only" = Moderate detections without incidents), 42 illustrative risks.
- **Branch status** cards for the three fictional branches — the status is derived and the reason is shown.
- Charts: events over the last 7 days (click a day → filtered monitoring), risk severity distribution
  (click a slice → filtered register), incidents by severity, assets by branch & status.

## 2 · Network Infrastructure
- Open **Branch A** (or click its card on the dashboard). Show WAN → gateway → core layer → 8 VLAN zones.
- Click **VLAN 60 Guest Wi-Fi** (internet-only path), **VLAN 30 Clinical**, **VLAN 40 Application / Data**,
  **VLAN 50 Medical Devices** — the side panel shows subnet, policy intent and assets.
- Click an asset node (e.g. `A-APP-001`) → asset panel: type, branch, zone, IP, owner, criticality,
  classification, CIA, status and its illustrative risks.

## 3 · Trigger S1
Click **Run scenario** (header) or go to **Threat Monitoring**. Select **S1 — Guest-to-Clinical Access
Attempt**, target **Branch A**, click **Trigger scenario**. The status line reports the result; a toast
arrives over the WebSocket; the new row flashes at the top of the event stream.

## 4 · Observe the event
In the stream, show source asset `HSP-A-GST-002` / Guest Wi-Fi, destination `HSP-A-APP-001` /
Application / Data, the UTC timestamp and the **S1** scenario marker. Click the row.

## 5 · Explain the detection
The event panel shows **R1 Guest-to-restricted-zone access violation — Rule matched — High**, the
"Why the rule matched" sentence, the rule conditions and the evidence table (source/destination
zones, protocol/port, firewall action, policy). Note the reminder that a detection is an investigation
lead, not proof.

## 6 · Risk context
Scroll to **Risk context** and open the risk on `HSP-A-APP-001` (e.g. T1 × V1). Show the inputs,
`Impact = max(C 5, I 5, A 5) = 5`, `Score = 3 × 5 = 15`, band `10–16 → High`, the pairing rationale and
the "illustrative, not a confirmed finding" note. Use the back arrow to return.

## 7 · Incident creation
Because R1 is High, the event panel links to a new **INC-000n**. Open it — status **Open**, the
triggering detection, associated event, affected asset and risk context are attached.

## 8 · Lifecycle
- Assign it (e.g. "SOC Tier 1") → **Save**.
- Add an **Investigation** note → **Move to Investigating** (confirm).
- Add a **Containment** note → **Move to Contained** — the confirmation states that nothing is isolated,
  disabled or reconfigured.
- Optionally continue to **Resolved** and **Closed**. Only the next status is ever offered; the API
  rejects skips (`409 invalid_status_transition`).

Contrast: trigger **S2** or **S3** — the detection is **Moderate**, so it stays an alert with no incident.

## 9 · Audit history
**Reports & Audit → Audit history**: `simulation.triggered`, `event.created`, `detection.matched`,
`incident.created`, `incident.assigned`, `incident.note_added`, `incident.status_changed` with actor and
UTC time. Filter by entity type "Incident"; click a row to open the record; "Show JSON" reveals details.

## 10 · Export
In **Exports**, download the **Summary report (PDF)** — show the severity labels and
"Page X of Y" — and a **CSV** (e.g. Incidents).

## 11 · Controls and residual risk (Version 2)
- **Risk Register** → open `RSK-0001` (HSP-A-CLN-001, T1 × V6). Compare **Inherent 20 Critical** with
  **Residual 9 Moderate** and read the server's calculation: C06 (Preventive, Partial) lowers likelihood
  4 → 3; C08 (Corrective, Substantial) lowers impact 5 → 3; 3 × 3 = 9.
- Open the same risk for Branch C (`RSK-0029`): its controls are only *Planned*, so residual stays 20.
- On a risk with no controls (e.g. HSP-A-NET-001, T4 × V4) use **Link a control**: choose C04
  (marked "✓ addresses V4"), *Implemented*, *Substantial* → residual drops to 1 × 3 = 3 Low. Switch it to
  *Planned* → back to 6. Each change appears in the audit log with before/after values.
- **Security Controls** → open C05, **Deactivate** → its risks' residual returns to inherent; reactivate.
- **Command Centre** → toggle the risk chart between **Inherent** and **Residual**.

## 12 · Roles (Version 2)
- Sign out (user menu) and sign in as the **Viewer**: no Run scenario, trigger disabled, no edit buttons,
  no User Management; the risk drawer says "Read-only for your role". Exports still work.
- Sign in as the **Analyst**: can trigger scenarios and work incidents (the audit log shows the analyst's
  username), but has no reset button or User Management.

## Notes for presenters
- Re-triggering **S2** within 5 minutes (or **S7** within 2 minutes) on the same branch records the
  events but the threshold rule is suppressed — this is by design (one alert per source per window).
  Use another branch or wait.
- **Reset data** (Reports & Audit or the simulation console) restores the initial state in one step.
