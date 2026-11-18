# Hospitra User Guide

**Hospitra — Hospital Network Security & Risk Monitoring Platform · Version 2.0**

This guide explains what Hospitra is, how to install and start it, what every screen and number
means, and how to carry out everyday tasks. No programming knowledge is needed except for the
installation section.

---

## Contents

1. [What is Hospitra?](#1-what-is-hospitra)
2. [Key ideas in plain words](#2-key-ideas-in-plain-words)
3. [Installing and starting Hospitra](#3-installing-and-starting-hospitra)
4. [Signing in, accounts and roles](#4-signing-in-accounts-and-roles)
5. [Finding your way around the screen](#5-finding-your-way-around-the-screen)
6. [The pages, one by one](#6-the-pages-one-by-one)
7. [How to… (step-by-step tasks)](#7-how-to-step-by-step-tasks)
8. [Understanding the numbers and colours](#8-understanding-the-numbers-and-colours)
9. [Scenarios and detection rules](#9-scenarios-and-detection-rules)
10. [Reference lists](#10-reference-lists)
11. [Administration](#11-administration)
12. [Troubleshooting and FAQ](#12-troubleshooting-and-faq)

---

## 1. What is Hospitra?

Hospitra gives a hospital IT / security team **one place** to:

- **See the network**: three hospital branches, each split into eight security zones, with the
  devices (assets) in each zone.
- **Understand risk**: which threats could exploit which weaknesses on which assets, and how
  serious that is, both **before** (inherent) and **after** (residual) security controls.
- **Watch for suspicious activity**: security events are checked by eight detection rules. A
  match raises a **detection**; serious detections automatically open an **incident**.
- **Handle incidents** through a fixed lifecycle, with notes and assignment.
- **Report and audit**: download CSV/PDF reports and see who did what, and when.

### The big picture

```text
 Hospital network ──► Scenario run ──► Security event ──► Detection rules
 (branches, zones,    (S1 – S8)          (stored)            (R1 – R8)
  assets)                                                        │
                                                                 ▼
 Audit log ◄── Incident (High/Critical only) ◄── Risk context (related risks)
     │
     └──► Live update to every open browser
```

Everything you see on screen is read from Hospitra's database, so numbers always agree
between pages, and other signed-in users see changes live.

### What Hospitra does **not** do

- It does not read live network traffic or scan devices. Security events come from its
  eight built-in **scenarios** (see [section 9](#9-scenarios-and-detection-rules)) and from
  routine baseline activity in the seeded history.
- It does not change any real system. Marking an incident **Contained** records a status;
  it does not isolate a host or disable an account.

---

## 2. Key ideas in plain words

| Term | What it means |
|---|---|
| **Branch** | One hospital site. Hospitra has three: **A** Central Hospital, **B** Diagnostic Centre, **C** Specialty Clinic. |
| **Zone** | A separated part of a branch's network (a VLAN), e.g. *Clinical Workstations* or *Guest Wi-Fi*. Each branch has the same eight zones. |
| **Asset** | A device or system on the network: a server, workstation, medical device, firewall… Identified by a tag such as `HSP-A-MED-001` (Hospital, Branch A, Medical zone, number 1). |
| **CIA ratings** | How much harm a problem with this asset would cause to **C**onfidentiality (data leaking), **I**ntegrity (data being altered) and **A**vailability (system unavailable). Each is rated 1–5. |
| **Threat** | Something that could cause harm, e.g. *Ransomware spread* (T1). |
| **Vulnerability** | A weakness a threat could exploit, e.g. *Single-factor VPN authentication* (V2). |
| **Risk** | A record that links **one asset + one threat + one vulnerability**, with a likelihood and impact. Reference such as `RSK-0001`. |
| **Inherent risk** | How serious the risk is **without** considering security controls. |
| **Security control** | A safeguard that reduces risk, e.g. *Multi-factor authentication for remote access* (C02). |
| **Residual risk** | How serious the risk still is **after** the implemented controls are taken into account. |
| **Scenario** | A predefined situation (S1–S8) that generates security events, e.g. *Unusual VPN Login*. |
| **Security event** | A single recorded occurrence, e.g. "a VPN login from an unrecognised region". |
| **Detection** | The result of a detection rule checking an event. A **matched** detection is an alert worth looking at. |
| **Incident** | A case to investigate. Opened automatically for **High** or **Critical** detections. Numbered `INC-0001`, `INC-0002`… |
| **Audit log** | A permanent, append-only history of important actions and who performed them. |

---

## 3. Installing and starting Hospitra

> This section is for whoever sets up the application. Day-to-day users can skip to
> [section 4](#4-signing-in-accounts-and-roles).

### 3.1 What you need

- **Windows** with PowerShell (other operating systems work with equivalent commands).
- **Python 3.12 or newer.** Install with:
  `winget install -e --id Python.Python.3.12 --scope user`
- A modern browser: **Microsoft Edge** or **Google Chrome**.

### 3.2 One-time installation

Open **Windows PowerShell** in the project folder (for example `c:\SRMP Hospitra`) and run:

```powershell
cd backend
py -3.12 -m venv .venv                                         # create a private Python environment
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt  # install Hospitra's libraries
```

### 3.3 Create the database and load the starting data

```powershell
cd backend
.\.venv\Scripts\python.exe -m alembic upgrade head    # creates (or upgrades) the database
.\.venv\Scripts\python.exe -m app.seed.cli seed       # loads branches, assets, catalogue, risks, controls, history
```

Both commands are safe to run again. `seed` only adds what is missing.

The starting data contains: 3 branches · 24 zones · 48 assets · 8 threats · 8 vulnerabilities ·
42 risks · 12 security controls · 7 days of event history and a few past incidents.

### 3.4 Start the application

```powershell
cd backend
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Leave this window open while you use Hospitra; closing it stops the application. Then open
**http://127.0.0.1:8000/** in your browser.

### 3.5 First start: create the Administrator

The very first time, Hospitra shows **First-run setup**. Choose:

- a **username** (3–40 characters),
- a **display name**,
- a **password** of at least **10 characters**.

This becomes the first **Admin** account and you are signed in straight away. There are no
default passwords. Add everyone else afterwards in **User Management** (see
[section 11.1](#111-managing-users)).

### 3.6 Optional settings

Set these as environment variables before starting the server if you need to change the defaults.

| Setting | Default | What it controls |
|---|---|---|
| `HOSPITRA_DATABASE_URL` | `backend/data/hospitra.db` | Where the database file lives |
| `HOSPITRA_SESSION_HOURS` | `8` | How long a sign-in lasts before you must sign in again |
| `HOSPITRA_COOKIE_SECURE` | `false` | Set to `true` when Hospitra is served over HTTPS |
| `HOSPITRA_PBKDF2_ITERATIONS` | `600000` | Strength of password hashing |

> **Network access.** By default Hospitra listens only on this computer (`127.0.0.1`). Before
> making it reachable from other computers, put it behind **HTTPS**, set
> `HOSPITRA_COOKIE_SECURE=true`, and have its security reviewed.

---

## 4. Signing in, accounts and roles

### 4.1 Signing in and out

- Open Hospitra and enter your **username** and **password**.
- Your sign-in lasts **8 hours**; after that you are asked to sign in again.
- After **5 wrong passwords within 15 minutes**, that username is temporarily blocked. Wait
  15 minutes or ask an Admin.
- **Sign out** and **Change password** are in the **user menu** (your name, top-right).

### 4.2 Roles: who can do what

Every account has one of three roles.

| Action | Viewer | Analyst | Admin |
|---|:---:|:---:|:---:|
| See every page, open any record | ✔ | ✔ | ✔ |
| Download CSV / PDF exports | ✔ | ✔ | ✔ |
| Run scenarios | | ✔ | ✔ |
| Work on incidents (status, notes, assignment) | | ✔ | ✔ |
| Create / edit assets, threats, vulnerabilities, risks, controls | | ✔ | ✔ |
| Link controls to risks | | ✔ | ✔ |
| Manage users (create, change role, deactivate, reset password) | | | ✔ |
| Reset all data | | | ✔ |

Buttons you are not allowed to use are hidden, and drawers show **"Read-only for your role"**.
Even if a button were visible, the server checks your role on every request.

---

## 5. Finding your way around the screen

```text
┌──────────────┬──────────────────────────────────────────────────────────────┐
│ Hospitra     │  Page title                Context: [All branches ▾]  [Run    │
│              │  short description                                scenario] 👤│
│ OPERATIONS   ├──────────────────────────────────────────────────────────────┤
│ 01 Command…  │                                                              │
│ 02 Network…  │                    Page content                              │
│ 03 Assets    │                                                              │
│ …            │      (click any row or card to open a detail drawer          │
│ ADMIN        │       that slides in from the right)                         │
│ User Mgmt    │                                                              │
│──────────────│                                                              │
│ ● Live       │                                                              │
│ 👤 username  │                                                              │
└──────────────┴──────────────────────────────────────────────────────────────┘
```

| Element | What it does |
|---|---|
| **Sidebar** | Navigation between pages. Small numbers next to some items show counts (e.g. open incidents). |
| **Context selector** | Choose **All branches** or one branch. Dashboards and lists then focus on that branch. |
| **Run scenario** | Shortcut to the simulation console (Analyst and Admin only). |
| **User menu** | Your name and role, Change password, Sign out. |
| **Live updates indicator** (bottom-left) | Green *connected*: pages refresh themselves when something changes. Amber *connecting*. Red *offline — retrying*: the server cannot be reached. |
| **Detail drawer** | Opens on the right when you click a record. Drawers can stack (open an asset from inside a risk, and so on). Press **Esc** or the **×** to close. |
| **Toasts** | Short messages in the corner confirming an action, or announcing that a scenario finished. |

---

## 6. The pages, one by one

### 6.1 Command Centre (dashboard)

The overview of the whole operation.

- **KPI cards** (top row): total **Assets** (with Active / Warning / Offline / Maintenance),
  **Open incidents** by severity, **Security events** (and how many in the last 24 h),
  **Detections** (matched rules; "Alert only" = matched but below the incident threshold) and
  **Risks** (Critical/High, inherent and residual). Click a card to jump to that list.
- **Branch status**: one card per branch, showing **Normal**, **Elevated** or **Critical** and
  the reason (see [8.5](#85-branch-status)).
- **Charts**:
  - *Security events over time*: the last 7 days; click a day to see those events.
  - *Risk severity distribution*: use the **Inherent / Residual** switch to compare risk
    before and after controls. Click a bar to open the filtered Risk Register.
  - *Incidents by severity*: open vs. all-time.
  - *Assets by branch & status* (or *by zone* when one branch is selected).
- **Recent detections** and **Recent activity** (from the audit log).

### 6.2 Network Infrastructure

An interactive diagram of one branch's network.

- Pick a branch with the switch at the top.
- The diagram flows: **WAN / upstream → gateway → core switch → 8 zones → 2 assets per zone**.
- Each asset shows a coloured **status ring** (Active, Warning, Offline, Maintenance) and a
  badge if it has open incidents.
- Click a **zone** to see its VLAN, address range and policy intent (what traffic it should
  allow). Click an **asset** to open its details. Keyboard: Tab to a node, **Enter** to open.

### 6.3 Asset Inventory

The full list of assets.

- **Search** by name, tag or IP. **Filter** by branch, zone, type, criticality and status.
  **Sort** by clicking a column header. Use the pager at the bottom.
- **New asset** / **Edit asset** (Analyst, Admin). The server checks the details: the asset tag
  must be unique, and the IP address must belong to the chosen zone's subnet.
- An asset's drawer shows its identity, security profile (criticality, data classification,
  CIA ratings), its **risks**, and its event and incident activity. **Add risk** starts a new
  risk for that asset.
- Assets cannot be deleted (history must stay intact); set the status instead.

### 6.4 Threats & Vulnerabilities

The catalogue of possible threats (T…) and weaknesses (V…), on two tabs.

- **Case study** badge: the core entries T1–T7 and V1–V8.
- **Proposed** badge: additional entries (e.g. T8 *Unauthorised device connection*, or any you add).
- Each entry's drawer lists its **documented pairings** (which threats realistically exploit
  which vulnerabilities, with the reason) and every **related risk**.
- Analysts and Admins can add, edit, deactivate and reactivate entries.

### 6.5 Threat Monitoring

Where events are generated and reviewed.

**Simulation console** (top):
1. Pick a **scenario** (S1–S8). Each card shows its expected severity and whether it will
   open an incident (**→ incident**) or only raise an alert (**alert only**).
2. Pick the **target branch**.
3. Click **Trigger scenario**. The result appears in a few seconds, and every signed-in user
   gets a notification.

**Recent runs** lists previous scenario runs.

**Security event stream** (below): every stored event, newest first. Search by description,
IP or asset tag; filter by severity, event type, branch, detection status and date range. Each row shows the scenario marker
(e.g. `S1`, or `Baseline` for routine activity). Click a row to open the **event drawer**:

- **Event context**: time, type, source and destination (asset, zone, IP), description.
- **Detection**: each rule that checked this event, **why it matched** (or why not), the rule's
  conditions and the **evidence** values.
- **Incident**: the incident it opened, or why none was opened.
- **Risk context**: existing risks on the affected assets that relate to the rule.
- **Event metadata**: the raw details of the event.

### 6.6 Risk Register

All risks, with inherent and residual values side by side.

- Columns: reference, asset, threat × vulnerability, likelihood, impact, **inherent score and
  severity**, **residual score and severity**, number of controls, treatment, status.
- Search; filter by branch, inherent severity, residual severity, status and treatment; sort.
- **New risk** (Analyst, Admin): choose the asset, threat and vulnerability, and set the
  likelihood and the C / I / A impacts (1–5). Documented threat/vulnerability pairings are
  marked ✓. **You never type the score.** The server calculates it.
- The **risk drawer** shows:
  - **Inherent risk**: the calculation written out, e.g. `Score = 4 × 5 = 20`.
  - **Residual risk**: which controls counted and how they reduced likelihood or impact.
  - **Controls**: linked controls with their status (*Planned* / *Implemented*) and
    effectiveness (*Partial* / *Substantial*). Change them in place, unlink them, or
    **Link a control** (✓ marks controls that address this risk's vulnerability).
  - Related asset, threat, vulnerability, the pairing rationale, owner, treatment and status.

### 6.7 Security Controls

The library of safeguards (C01–C12 plus any you add).

- **Type** decides what a control reduces:
  - **Preventive** → lowers **likelihood** (makes the bad thing less likely).
  - **Detective** and **Corrective** → lower **impact** (find it sooner / recover faster).
- Each control lists the vulnerabilities it **addresses** and every risk it is linked to.
- **Deactivating** a control stops it counting anywhere; all linked risks are recalculated
  immediately. Reactivate it to restore its effect.

### 6.8 Incident Management

All incidents. Search by number, title or assignee; filter by branch, status (including
"Active" = Open, Investigating or Contained) and severity.

The **incident drawer** contains:
- A **lifecycle bar**: Open → Investigating → Contained → Resolved → Closed.
- **Move to …** button: advances the status **one step**. Steps cannot be skipped or undone.
- **Assigned operator label**: free text such as "SOC Tier 1".
- **Notes**: Investigation, Containment or Resolution notes, each with author and time.
- The **triggering detection** (with its evidence), **associated events**, **affected assets**,
  **risk context** and the incident's own **audit history**.
- Once **Closed**, an incident is locked and can no longer be changed.

### 6.9 Reports & Audit

- **Exports**: download
  - *Asset inventory* (CSV)
  - *Risk register* (CSV, including residual values and applied controls)
  - *Security events* (CSV)
  - *Incidents* (CSV)
  - *Summary report* (PDF): overview, branch status, inherent vs. residual distribution, top
    risks, recent incidents and detections, with page numbers.
  
  Times in exports are UTC.
- **Audit history**: every important action with time (UTC), actor (username), action,
  affected record and a readable summary. Filter by entity type, action and date range. Click a
  row to open the related record, or **Show JSON** for full details (for example a risk's
  before/after scores).
- **Reset data** (Admin only): see [11.2](#112-resetting-the-data).

### 6.10 User Management (Admin only)

Lists every account with role, status and last sign-in. See [11.1](#111-managing-users).

---

## 7. How to… (step-by-step tasks)

### Run a scenario and follow it through
1. **Threat Monitoring** → choose **S1 Guest-to-Clinical Access Attempt** → target **Branch A**
   → **Trigger scenario**.
2. A toast appears: *"Scenario S1 completed (Branch A)"* with **Open INC-…**.
3. In the event stream, click the new top row → read **Why the rule matched**.
4. Open the incident from the event drawer or the toast.

### Work an incident from start to finish
1. **Incident Management** → click the incident.
2. Enter an **Assigned operator label** → **Save**.
3. Add an **Investigation note** → **Add note**.
4. **Move to Investigating**, then add findings.
5. **Move to Contained** (add a Containment note describing what was done).
6. **Move to Resolved** (add a Resolution note), then **Move to Closed**.

### Record a new risk
1. **Risk Register** → **New risk** (or **Add risk** inside an asset drawer).
2. Pick asset, threat and vulnerability. Prefer pairings marked ✓.
3. Set likelihood and C / I / A impacts, treatment, owner and status → **Save**.
4. The drawer shows the server's calculation and severity.

### Show the effect of a control on a risk
1. Open a risk → **Controls** → **Link a control**.
2. Pick a control (✓ = addresses this vulnerability), set **Implemented** and
   **Partial** or **Substantial** → **Link**.
3. The **Residual risk** section updates immediately. A **Planned** link does not reduce risk
   until it is changed to **Implemented**.

### Compare inherent and residual risk across the hospital
- **Command Centre** → *Risk severity distribution* → switch **Inherent / Residual**, or
- **Risk Register** → filter by **Residual severity**.

### Focus on one branch
- Choose the branch in the **Context** selector (top bar). Choose **All branches** to go back.

### Export a report
- **Reports & Audit** → **Exports** → **Download CSV / PDF**. The saved file name and size are
  confirmed under the button.

### Find out who changed something
- **Reports & Audit** → **Audit history** → filter by entity type (e.g. *Risk*) and action
  (e.g. `risk.updated`) → **Show JSON** for exact before/after values.

### Change your password
- User menu (top-right) → **Change password** → current password + new password (≥ 10
  characters). Your other sign-in sessions are signed out.

---

## 8. Understanding the numbers and colours

### 8.1 Severity colours

Severity is always shown as **colour + word + bar glyph**, so it can be read without colour.

| Severity | Colour | Bars |
|---|---|---|
| Low | green | ▮▯▯▯ |
| Moderate | amber | ▮▮▯▯ |
| High | orange | ▮▮▮▯ |
| Critical | red | ▮▮▮▮ |

### 8.2 Inherent risk score

```text
Impact  = the highest of Confidentiality, Integrity and Availability impact (each 1–5)
Score   = Likelihood (1–5) × Impact (1–5)          → a number from 1 to 25
```

| Score | Severity |
|---|---|
| 1 – 4 | Low |
| 5 – 9 | Moderate |
| 10 – 16 | High |
| 17 – 25 | Critical |

*Example:* likelihood 4, impacts C 5 / I 4 / A 3 → impact = 5 → score = 4 × 5 = **20 Critical**.

Using the **highest** of C, I and A means one severe consequence is never averaged away.

### 8.3 Residual risk score

Residual risk applies the risk's **linked controls**, following four rules:

1. Only links marked **Implemented**, on **active** controls, count. *Planned* links do not.
2. **Preventive** controls lower **likelihood**; **Detective** and **Corrective** controls
   lower **impact**.
3. **Partial** lowers by **1** level, **Substantial** by **2** levels.
4. On each side (likelihood, impact) only the **strongest** control counts; effects do not
   add up. Values never go below 1.

The same score bands as above then give the residual severity.

*Example (continuing from 8.2):*
- C02 *MFA for remote access* (Preventive, Substantial) → likelihood 4 − 2 = **2**
- C09 *Centralised monitoring* (Detective, Partial) → impact 5 − 1 = **4**
- Residual score = 2 × 4 = **8 Moderate** (down from 20 Critical)

### 8.4 When is an incident opened?

| Detection severity | What happens |
|---|---|
| Low or Moderate | **Alert only**: the detection is visible in Threat Monitoring and the dashboard; no incident |
| High or Critical | **One incident** is opened automatically (never two for the same detection) |

### 8.5 Branch status

| Status | When |
|---|---|
| **Critical** | The branch has an open **Critical** incident |
| **Elevated** | Otherwise, if it has an open **High** incident, an **Offline** or **Warning** asset, or a matched detection in the last 24 hours |
| **Normal** | None of the above |

"Open" incidents are those in **Open**, **Investigating** or **Contained**.

### 8.6 Event detection status

| Label | Meaning |
|---|---|
| **Detected** | At least one rule matched |
| **No match** | Rules checked the event and none matched |
| **Not evaluated** | No rule applies to this kind of event (e.g. telemetry) |

An event's severity is the higher of its own reported severity and the severity of any
matched rule.

### 8.7 Asset status

| Status | Meaning |
|---|---|
| Active | Operating normally |
| Warning | Needs attention |
| Offline | Not reachable |
| Maintenance | Planned maintenance |

---

## 9. Scenarios and detection rules

### 9.1 The eight scenarios

| ID | Scenario | What happens | Rule | Severity | Incident? |
|---|---|---|---|---|---|
| S1 | Guest-to-Clinical Access Attempt | A guest Wi-Fi kiosk tries to reach the clinical records server | R1 | High | Yes |
| S2 | Repeated Authentication Failures | 5 failed SSH logins for one account within ~4 minutes | R2 | Moderate | No |
| S3 | Unusual VPN Login | VPN login from an unrecognised region on an unmanaged device, no MFA | R3 | Moderate | No |
| S4 | Unknown Device in Sensitive Zone | An unregistered device appears in the Medical Devices zone | R4 | High | Yes |
| S5 | Unusual Outbound Transfer | The clinical database sends 2 GB to an uncategorised external host | R5 | High | Yes |
| S6 | DDoS-like Request Volume | The patient portal receives ~40× its normal request rate | R6 | High | Yes |
| S7 | Ransomware-like Behaviour | A workstation deletes shadow copies, mass-renames files and drops a ransom note | R7 | Critical | Yes |
| S8 | Vendor Access Outside Approved Window | A vendor account connects to a medical device after its maintenance window | R8 | Moderate | No |

The same scenario on the same branch always produces the same content; only the time differs.

### 9.2 The eight detection rules

| Rule | Looks for |
|---|---|
| **R1** Guest-to-restricted-zone access | Traffic from Guest Wi-Fi to any internal restricted zone |
| **R2** Repeated authentication failures | 5 or more failures from the same source within 5 minutes |
| **R3** Unusual VPN access | Login region not approved, **or** device not managed |
| **R4** Unknown device in restricted zone | A device that is not in the inventory, in a restricted zone |
| **R5** Unusual outbound transfer | 500 MB or more sent to a destination outside the internal network |
| **R6** DDoS-like request volume | Requests per minute to a DMZ service at least 10× its baseline |
| **R7** Ransomware-like behaviour | 5 or more suspicious file operations from one endpoint within 2 minutes |
| **R8** Vendor access policy violation | Vendor access outside the approved maintenance window |

> **Tip:** R2 and R7 fire **once per source per time window**. If you run **S2** again on the
> same branch within **5 minutes** (or **S7** within **2 minutes**), the events are stored but
> marked *Suppressed* and no new detection is raised. Wait, or use another branch.

---

## 10. Reference lists

### 10.1 Network zones (identical in every branch)

| VLAN | Zone | Holds |
|---|---|---|
| 10 | Network Management | Switches, management servers |
| 20 | Staff / Administration | Office workstations, file server |
| 30 | Clinical Workstations | Ward and clinic workstations |
| 40 | Application / Data | Clinical application and database servers |
| 50 | Medical Devices | Infusion pump gateways, imaging and other modalities |
| 60 | Guest Wi-Fi | Guest access points and kiosks |
| 70 | Security Services | Log collector (SIEM), backup |
| 80 | DMZ | Patient portal web server, VPN gateway |

Addresses follow `10.<site>.<vlan>.0/24`: site 20 = Branch A, 21 = Branch B, 22 = Branch C.
Example: `10.20.50.11` is in Branch A's Medical Devices zone.

### 10.2 Threats and vulnerabilities

| Threats | Vulnerabilities |
|---|---|
| T1 Ransomware spread | V1 Inadequate security-zone separation |
| T2 VPN credential theft | V2 Single-factor VPN authentication |
| T3 Rogue or weak Wi-Fi | V3 Weak Wi-Fi encryption or authentication |
| T4 Man-in-the-middle attack | V4 Unencrypted internal traffic |
| T5 DDoS against patient portal | V5 Weak edge filtering |
| T6 Insider misuse / privileged account abuse | V6 Unpatched or unsupported systems |
| T7 Third-party / vendor compromise | V7 Excessive privileges / weak access control |
| T8 Unauthorised device connection *(proposed)* | V8 Inadequate backup isolation or recovery testing |

### 10.3 Security controls

| Code | Control | Type | Addresses |
|---|---|---|---|
| C01 | Inter-zone firewall segmentation | Preventive | V1 |
| C02 | Multi-factor authentication for remote access | Preventive | V2 |
| C03 | WPA3-Enterprise with 802.1X | Preventive | V3 |
| C04 | Internal TLS for clinical services | Preventive | V4 |
| C05 | Upstream DDoS filtering and rate limiting | Preventive | V5 |
| C06 | Patch and vulnerability management | Preventive | V6 |
| C07 | Least-privilege and privileged access reviews | Preventive | V7 |
| C08 | Immutable offline backups with restore testing | Corrective | V8 |
| C09 | Centralised security monitoring and alerting | Detective | V1, V5, V7 |
| C10 | Network access control for device registration | Preventive | V1 |
| C11 | Incident response playbooks | Corrective | — |
| C12 | Time-bound vendor access approval | Preventive | V2, V7 |

In the starting data, Branches A and B have their control links **Implemented**, while
Branch C's are all **Planned**, so you can see the difference residual risk makes.

### 10.4 Other values

| Field | Possible values |
|---|---|
| Asset criticality | Low · Medium · High · Critical |
| Data classification | Public · Internal · Confidential · Restricted |
| Risk treatment | Mitigate · Accept · Transfer · Avoid |
| Risk status | Open · In Treatment · Closed |
| Incident status | Open → Investigating → Contained → Resolved → Closed |
| Note types | Investigation · Containment · Resolution |

---

## 11. Administration

### 11.1 Managing users

**In the application** (Admin → **User Management**):
- **New user**: username, display name, role and an initial password (≥ 10 characters).
- **Change role**, **Deactivate / Activate**, **Reset password**.
- Any of these changes signs that user out of all their sessions.
- Safety rules: you cannot deactivate yourself, and the **last active Admin** cannot be
  removed or demoted.

**From the command line** (the password is asked for, never typed on the command line):

```powershell
cd backend
.\.venv\Scripts\python.exe -m app.seed.cli create-user --username alice --display-name "Alice" --role Analyst
```

### 11.2 Resetting the data

Resetting **deletes all records** (assets, risks, controls, events, detections, incidents and
the audit log) and reloads the starting data in one step. **User accounts are kept.**

- In the app: **Reports & Audit → Reset data…** (or the button in the simulation console),
  then type `RESET` to confirm.
- Command line: `.\.venv\Scripts\python.exe -m app.seed.cli reset`

A single `data.reset` entry is written to the new audit log.

### 11.3 Backups

All data lives in one file: `backend/data/hospitra.db`. To back it up, stop the server and
copy that file. To restore, stop the server and copy the backup back.

### 11.4 Upgrading

After receiving a new version, run `alembic upgrade head` and `app.seed.cli seed` again
([section 3.3](#33-create-the-database-and-load-the-starting-data)). Existing data is kept.

---

## 12. Troubleshooting and FAQ

**The page says "Could not load data — Sign in to continue" and there is no sign-in screen.**
Your browser is showing an older copy of the page. Press **F5** (or **Ctrl + Shift + R**) once.

**I was signed out unexpectedly.**
Sign-ins last 8 hours. An Admin changing your role, deactivating you or resetting your password
also signs you out.

**"Too many failed sign-in attempts".**
5 wrong passwords within 15 minutes block that username for 15 minutes.

**I ran S2 (or S7) again and no new detection appeared.**
That is by design; see the tip in [9.2](#92-the-eight-detection-rules).

**Why did a Moderate detection not create an incident?**
Only High and Critical detections open incidents. Moderate ones stay visible as alerts.

**I linked a control but the residual score didn't change.**
Check that the link is **Implemented** (not Planned), the control is **active**, and that
another control of the same kind isn't already stronger (only the strongest per side counts).

**I can't move an incident back to an earlier status.**
Statuses only move forward, one step at a time, and Closed incidents are locked.

**The "Live updates" dot is amber or red.**
The browser is (re)connecting to the server. Check that the server window is still running; the
page refreshes itself once reconnected.

**I can't see the Run scenario button or the edit buttons.**
Your role is **Viewer**. Ask an Admin for the Analyst role.

**Where is the API documentation?**
At **http://127.0.0.1:8000/docs**. Calls made from there use your browser's sign-in.

**Does Hospitra connect to the hospital's real network?**
No. Events come only from the built-in scenarios and the seeded baseline history, and Hospitra
never changes any device, account or network setting.
