"""Fixed, deterministic seed dataset definitions.

Branch names, locations, assets, owners and addresses do not describe any real hospital.
IP addressing follows the convention 10.<site_id>.<vlan_id>.0/24 from the specification.
"""

from __future__ import annotations

from app.core.constants import (
    AssetStatus,
    AssetType,
    CatalogueSource,
    ControlEffectiveness,
    ControlType,
    Criticality,
    DataClassification,
    ImplementationStatus,
    RiskStatus,
    Treatment,
)

BRANCHES: list[dict] = [
    {"code": "A", "name": "Branch A — Central Hospital", "role": "Main hospital / central services",
     "site_id": 20, "location_label": "Northfield"},
    {"code": "B", "name": "Branch B — Diagnostic Centre", "role": "Outpatient / diagnostic centre",
     "site_id": 21, "location_label": "Riverside"},
    {"code": "C", "name": "Branch C — Specialty Clinic", "role": "Specialty / satellite clinic",
     "site_id": 22, "location_label": "Hillcrest"},
]

_T = AssetType
_C = Criticality
_D = DataClassification

# Two representative assets per zone. Keys are zone codes from ZONE_TEMPLATE.
# host = last IPv4 octet inside 10.<site>.<vlan>.0/24.
ASSET_TEMPLATE: dict[str, list[dict]] = {
    "NET": [
        {"n": 1, "name": "Core Switch", "type": _T.NETWORK_DEVICE, "host": 2, "os": "Vendor network OS 17.x",
         "crit": _C.HIGH, "cls": _D.INTERNAL, "cia": (2, 4, 5), "owner": "Network Operations"},
        {"n": 2, "name": "Network Management Server", "type": _T.SERVER, "host": 10, "os": "Rocky Linux 9",
         "crit": _C.HIGH, "cls": _D.CONFIDENTIAL, "cia": (4, 4, 3), "owner": "Network Operations"},
    ],
    "ADM": [
        {"n": 1, "name": "Administration Workstation", "type": _T.WORKSTATION, "host": 21, "os": "Windows 11 Enterprise",
         "crit": _C.MEDIUM, "cls": _D.CONFIDENTIAL, "cia": (3, 3, 2), "owner": "Corporate IT Service Desk"},
        {"n": 2, "name": "Office File Server", "type": _T.SERVER, "host": 22, "os": "Windows Server 2022",
         "crit": _C.MEDIUM, "cls": _D.CONFIDENTIAL, "cia": (3, 4, 3), "owner": "Corporate IT Infrastructure"},
    ],
    "CLN": [
        {"n": 1, "name": "Ward Nurse Station Workstation", "type": _T.WORKSTATION, "host": 31, "os": "Windows 11 Enterprise",
         "crit": _C.HIGH, "cls": _D.RESTRICTED, "cia": (4, 4, 4), "owner": "Clinical Applications Team"},
        {"n": 2, "name": "Physician Workstation", "type": _T.WORKSTATION, "host": 32, "os": "Windows 11 Enterprise",
         "crit": _C.HIGH, "cls": _D.RESTRICTED, "cia": (4, 4, 4), "owner": "Clinical Applications Team"},
    ],
    "APP": [
        {"n": 1, "name": "Clinical Records Application Server", "type": _T.SERVER, "host": 41, "os": "RHEL 9",
         "crit": _C.CRITICAL, "cls": _D.RESTRICTED, "cia": (5, 5, 5), "owner": "Clinical Applications Team"},
        {"n": 2, "name": "Clinical Database Server", "type": _T.DATABASE_SERVER, "host": 42, "os": "RHEL 9",
         "crit": _C.CRITICAL, "cls": _D.RESTRICTED, "cia": (5, 5, 4), "owner": "Database Administration"},
    ],
    "MED": [
        {"n": 1, "name": "Infusion Pump Gateway", "type": _T.MEDICAL_DEVICE, "host": 51, "os": "Vendor embedded firmware",
         "crit": _C.CRITICAL, "cls": _D.RESTRICTED, "cia": (3, 5, 5), "owner": "Biomedical Engineering"},
        {"n": 2, "name": "Patient Monitoring Central Station", "type": _T.MEDICAL_DEVICE, "host": 52, "os": "Vendor embedded firmware",
         "crit": _C.CRITICAL, "cls": _D.RESTRICTED, "cia": (3, 5, 5), "owner": "Biomedical Engineering"},
    ],
    "GST": [
        {"n": 1, "name": "Guest Wi-Fi Access Point", "type": _T.ACCESS_POINT, "host": 2, "os": "Vendor AP firmware",
         "crit": _C.LOW, "cls": _D.PUBLIC, "cia": (1, 2, 2), "owner": "Network Operations"},
        {"n": 2, "name": "Guest Lounge Kiosk", "type": _T.ENDPOINT, "host": 50, "os": "Kiosk Linux",
         "crit": _C.LOW, "cls": _D.PUBLIC, "cia": (1, 1, 2), "owner": "Facilities IT"},
    ],
    "SEC": [
        {"n": 1, "name": "SIEM Log Collector", "type": _T.SECURITY_APPLIANCE, "host": 71, "os": "Security appliance OS",
         "crit": _C.HIGH, "cls": _D.CONFIDENTIAL, "cia": (4, 4, 3), "owner": "Security Operations"},
        {"n": 2, "name": "Backup Vault Server", "type": _T.SERVER, "host": 72, "os": "Rocky Linux 9",
         "crit": _C.HIGH, "cls": _D.RESTRICTED, "cia": (5, 5, 4), "owner": "Corporate IT Infrastructure"},
    ],
    "DMZ": [
        {"n": 1, "name": "Patient Portal Web Server", "type": _T.WEB_SERVER, "host": 81, "os": "Ubuntu Server 24.04",
         "crit": _C.HIGH, "cls": _D.CONFIDENTIAL, "cia": (4, 3, 4), "owner": "Digital Services"},
        {"n": 2, "name": "Remote Access VPN Gateway", "type": _T.VPN_GATEWAY, "host": 82, "os": "VPN appliance OS",
         "crit": _C.HIGH, "cls": _D.INTERNAL, "cia": (3, 4, 4), "owner": "Network Operations"},
    ],
}

# Branch-specific medical devices (branches have different illustrative roles).
MEDICAL_DEVICE_NAMES: dict[str, tuple[str, str]] = {
    "A": ("Infusion Pump Gateway", "Patient Monitoring Central Station"),
    "B": ("Imaging Modality Workstation", "Laboratory Analyser Interface"),
    "C": ("Dialysis Monitor Gateway", "Patient Monitoring Central Station"),
}

# Deterministic non-Active statuses. Every other asset is Active.
STATUS_OVERRIDES: dict[str, AssetStatus] = {
    "HSP-A-MED-002": AssetStatus.WARNING,
    "HSP-B-ADM-002": AssetStatus.OFFLINE,
    "HSP-B-GST-002": AssetStatus.MAINTENANCE,
    "HSP-C-CLN-002": AssetStatus.WARNING,
    "HSP-C-SEC-002": AssetStatus.WARNING,
}

# --------------------------------------------------------------------------------------
# Threat & vulnerability catalogue (spec §7). T8 is an additional *proposed* scenario.
# --------------------------------------------------------------------------------------
_CS = CatalogueSource.CASE_STUDY
_PR = CatalogueSource.PROPOSED

THREATS: list[dict] = [
    {"code": "T1", "name": "Ransomware spread", "category": "Malware", "source_type": _CS,
     "description": "Malicious software that encrypts files and systems and may propagate between hosts. "
                    "In the hospital, encryption of clinical applications, file shares or "
                    "backups could disrupt care delivery and record availability."},
    {"code": "T2", "name": "VPN credential theft", "category": "Credential compromise", "source_type": _CS,
     "description": "Theft or phishing of remote-access credentials. Stolen VPN credentials can provide "
                    "an initial foothold; on their own they do not prove that any later malicious "
                    "activity (such as ransomware execution) occurred."},
    {"code": "T3", "name": "Rogue or weak Wi-Fi", "category": "Wireless", "source_type": _CS,
     "description": "Unauthorised access points or weakly protected wireless networks that let devices "
                    "join or observe hospital traffic, or bridge guest and private networks."},
    {"code": "T4", "name": "Man-in-the-middle attack", "category": "Network interception", "source_type": _CS,
     "description": "Interception or modification of traffic between two parties, for example between "
                    "clinical workstations and application servers when internal traffic is unencrypted."},
    {"code": "T5", "name": "DDoS against patient portal", "category": "Availability", "source_type": _CS,
     "description": "High-volume request floods against the public patient portal. Primarily an "
                    "availability scenario: it degrades access to online services rather than "
                    "directly exposing data."},
    {"code": "T6", "name": "Insider misuse / privileged account abuse", "category": "Insider", "source_type": _CS,
     "description": "Misuse of legitimate access by staff or privileged administrators, including "
                    "excessive data access or unusual bulk data movement."},
    {"code": "T7", "name": "Third-party / vendor compromise", "category": "Supply chain", "source_type": _CS,
     "description": "Compromise or misuse of vendor remote-support access, for example to medical "
                    "devices maintained by external suppliers."},
    {"code": "T8", "name": "Unauthorised device connection", "category": "Network access", "source_type": _PR,
     "description": "Proposed additional scenario: an unregistered device connected to a sensitive zone. "
                    "Presented as a proposed scenario, not a confirmed finding."},
]

VULNERABILITIES: list[dict] = [
    {"code": "V1", "name": "Inadequate security-zone separation", "weakness_type": "Network architecture", "source_type": _CS,
     "description": "Insufficient filtering between security zones. It may facilitate lateral movement "
                    "between, for example, guest, clinical and medical-device networks — but does not by "
                    "itself prove that lateral movement occurred."},
    {"code": "V2", "name": "Single-factor VPN authentication", "weakness_type": "Authentication", "source_type": _CS,
     "description": "Remote access protected only by a password. A stolen or guessed password is "
                    "sufficient to establish a VPN session into the hospital network."},
    {"code": "V3", "name": "Weak Wi-Fi encryption or authentication", "weakness_type": "Wireless configuration", "source_type": _CS,
     "description": "Outdated wireless security (e.g. shared keys or legacy protocols) that makes "
                    "unauthorised association or eavesdropping easier."},
    {"code": "V4", "name": "Unencrypted internal traffic", "weakness_type": "Data in transit", "source_type": _CS,
     "description": "Internal services that exchange data in clear text, which exposes clinical and "
                    "administrative data to interception on the internal network."},
    {"code": "V5", "name": "Weak edge filtering", "weakness_type": "Perimeter", "source_type": _CS,
     "description": "Limited ingress/egress filtering and rate limiting at the internet edge. Note: "
                    "edge filtering does not prevent an attacker who holds valid VPN credentials."},
    {"code": "V6", "name": "Unpatched or unsupported systems", "weakness_type": "Patch management", "source_type": _CS,
     "description": "Systems missing security updates or running unsupported software, including "
                    "medical-device platforms whose update cycles depend on the vendor."},
    {"code": "V7", "name": "Excessive privileges / weak access control", "weakness_type": "Access control", "source_type": _CS,
     "description": "Accounts (staff, administrators or vendors) with more access than their role "
                    "requires, increasing the impact of misuse or compromise."},
    {"code": "V8", "name": "Inadequate backup isolation or recovery testing", "weakness_type": "Resilience", "source_type": _CS,
     "description": "Backups reachable from production networks or not regularly restore-tested, so "
                    "recovery after destructive malware may fail or take longer than expected."},
]

# Documented, plausible pairings only (spec §7.3). NOT every threat × vulnerability.
THREAT_VULNERABILITY_PAIRS: list[tuple[str, str, str]] = [
    ("T1", "V1", "Weak zone separation may allow ransomware on one host to reach others; it facilitates, but does not prove, lateral movement."),
    ("T1", "V6", "Unpatched systems offer known exploitation paths that ransomware commonly uses to execute or spread."),
    ("T1", "V8", "Ransomware impact is amplified when backups are reachable or untested, because recovery may fail."),
    ("T2", "V2", "With single-factor VPN, a stolen password alone grants remote network access (initial access only)."),
    ("T2", "V7", "Over-privileged remote accounts increase what an attacker can reach after credential theft."),
    ("T3", "V3", "Weak wireless security makes unauthorised association or rogue access points more effective."),
    ("T3", "V1", "If guest/wireless segments are not separated, a wireless foothold may reach private zones."),
    ("T4", "V4", "Clear-text internal protocols allow intercepted traffic to be read or altered."),
    ("T4", "V3", "Weak wireless encryption allows interception of traffic carried over Wi-Fi."),
    ("T5", "V5", "Without edge rate limiting or upstream filtering, request floods reach the portal directly (availability)."),
    ("T6", "V7", "Excessive privileges let an insider access or move more data than their role requires."),
    ("T7", "V7", "Broad, standing vendor access increases the impact of a compromised supplier account."),
    ("T7", "V2", "Vendor VPN accounts protected by a single factor are exposed to credential reuse or theft."),
    ("T8", "V1", "Without zone-level controls, an unregistered device may communicate with sensitive systems."),
]

# --------------------------------------------------------------------------------------
# Illustrative risk templates, applied per branch. (asset template key, threat, vuln,
# likelihood, C, I, A, treatment, owner, status). Branch B uses likelihood − 1 (clamped),
# reflecting its smaller outpatient footprint; this is an illustrative assumption.
# --------------------------------------------------------------------------------------
RISK_TEMPLATES: list[dict] = [
    {"asset": "CLN-001", "threat": "T1", "vuln": "V6", "l": 4, "cia": (4, 3, 5), "treatment": Treatment.MITIGATE, "owner": "Clinical Applications Team", "status": RiskStatus.IN_TREATMENT},
    {"asset": "APP-001", "threat": "T1", "vuln": "V1", "l": 3, "cia": (5, 5, 5), "treatment": Treatment.MITIGATE, "owner": "Clinical Applications Team", "status": RiskStatus.OPEN},
    {"asset": "APP-001", "threat": "T3", "vuln": "V1", "l": 2, "cia": (4, 3, 3), "treatment": Treatment.MITIGATE, "owner": "Network Operations", "status": RiskStatus.OPEN},
    {"asset": "APP-002", "threat": "T6", "vuln": "V7", "l": 2, "cia": (5, 3, 2), "treatment": Treatment.MITIGATE, "owner": "Database Administration", "status": RiskStatus.OPEN},
    {"asset": "NET-002", "threat": "T6", "vuln": "V7", "l": 2, "cia": (4, 4, 3), "treatment": Treatment.MITIGATE, "owner": "Network Operations", "status": RiskStatus.IN_TREATMENT},
    {"asset": "DMZ-002", "threat": "T2", "vuln": "V2", "l": 4, "cia": (4, 3, 3), "treatment": Treatment.MITIGATE, "owner": "Network Operations", "status": RiskStatus.OPEN},
    {"asset": "DMZ-001", "threat": "T5", "vuln": "V5", "l": 3, "cia": (1, 1, 4), "treatment": Treatment.TRANSFER, "owner": "Digital Services", "status": RiskStatus.IN_TREATMENT},
    {"asset": "MED-001", "threat": "T8", "vuln": "V1", "l": 2, "cia": (3, 5, 5), "treatment": Treatment.MITIGATE, "owner": "Biomedical Engineering", "status": RiskStatus.OPEN},
    {"asset": "MED-002", "threat": "T7", "vuln": "V7", "l": 2, "cia": (3, 4, 4), "treatment": Treatment.MITIGATE, "owner": "Biomedical Engineering", "status": RiskStatus.OPEN},
    {"asset": "ADM-002", "threat": "T1", "vuln": "V8", "l": 3, "cia": (3, 4, 4), "treatment": Treatment.MITIGATE, "owner": "Corporate IT Infrastructure", "status": RiskStatus.OPEN},
    {"asset": "SEC-002", "threat": "T1", "vuln": "V8", "l": 2, "cia": (3, 4, 5), "treatment": Treatment.MITIGATE, "owner": "Corporate IT Infrastructure", "status": RiskStatus.IN_TREATMENT},
    {"asset": "NET-001", "threat": "T4", "vuln": "V4", "l": 2, "cia": (3, 3, 2), "treatment": Treatment.MITIGATE, "owner": "Network Operations", "status": RiskStatus.OPEN},
    {"asset": "GST-001", "threat": "T3", "vuln": "V3", "l": 3, "cia": (2, 2, 2), "treatment": Treatment.MITIGATE, "owner": "Network Operations", "status": RiskStatus.OPEN},
    {"asset": "GST-002", "threat": "T3", "vuln": "V3", "l": 2, "cia": (1, 1, 2), "treatment": Treatment.ACCEPT, "owner": "Facilities IT", "status": RiskStatus.CLOSED},
]

BRANCH_LIKELIHOOD_ADJUSTMENT: dict[str, int] = {"A": 0, "B": -1, "C": 0}

# --------------------------------------------------------------------------------------
# V2 — illustrative security control library and risk–control links.
# --------------------------------------------------------------------------------------
_P, _D, _R = ControlType.PREVENTIVE, ControlType.DETECTIVE, ControlType.CORRECTIVE

CONTROLS: list[dict] = [
    {"code": "C01", "name": "Inter-zone firewall segmentation", "control_type": _P, "category": "Network", "vulns": ["V1"],
     "description": "Default-deny filtering between security zones, with explicit allow rules for approved clinical flows."},
    {"code": "C02", "name": "Multi-factor authentication for remote access", "control_type": _P, "category": "Identity", "vulns": ["V2"],
     "description": "A second factor is required for every VPN and vendor remote-access session."},
    {"code": "C03", "name": "WPA3-Enterprise with 802.1X", "control_type": _P, "category": "Wireless", "vulns": ["V3"],
     "description": "Certificate-based wireless authentication; guest SSID isolated from internal networks."},
    {"code": "C04", "name": "Internal TLS for clinical services", "control_type": _P, "category": "Data protection", "vulns": ["V4"],
     "description": "Encrypt traffic between workstations, devices and clinical application servers."},
    {"code": "C05", "name": "Upstream DDoS filtering and rate limiting", "control_type": _P, "category": "Perimeter", "vulns": ["V5"],
     "description": "Provider-side scrubbing and edge rate limits for public-facing services."},
    {"code": "C06", "name": "Patch and vulnerability management", "control_type": _P, "category": "Endpoint", "vulns": ["V6"],
     "description": "Risk-based patch cadence, including vendor-coordinated updates for medical devices."},
    {"code": "C07", "name": "Least-privilege and privileged access reviews", "control_type": _P, "category": "Identity", "vulns": ["V7"],
     "description": "Quarterly access reviews, privileged access workstations and removal of standing admin rights."},
    {"code": "C08", "name": "Immutable offline backups with restore testing", "control_type": _R, "category": "Resilience", "vulns": ["V8"],
     "description": "Backups isolated from production credentials, with scheduled restore exercises."},
    {"code": "C09", "name": "Centralised security monitoring and alerting", "control_type": _D, "category": "Monitoring", "vulns": ["V1", "V5", "V7"],
     "description": "Security telemetry from all zones correlated centrally with on-call alerting."},
    {"code": "C10", "name": "Network access control for device registration", "control_type": _P, "category": "Network", "vulns": ["V1"],
     "description": "Unregistered devices are placed in a quarantine VLAN until inventoried."},
    {"code": "C11", "name": "Incident response playbooks", "control_type": _R, "category": "Response", "vulns": [],
     "description": "Documented, exercised playbooks for ransomware, data exfiltration and availability incidents."},
    {"code": "C12", "name": "Time-bound vendor access approval", "control_type": _P, "category": "Third party", "vulns": ["V2", "V7"],
     "description": "Vendor accounts are enabled only for approved maintenance windows and logged."},
]

_IMP, _PLN = ImplementationStatus.IMPLEMENTED, ImplementationStatus.PLANNED
_PART, _SUB = ControlEffectiveness.PARTIAL, ControlEffectiveness.SUBSTANTIAL

# (asset template key, threat, vulnerability) -> [(control code, status, effectiveness)]
RISK_CONTROL_LINKS: dict[tuple[str, str, str], list[tuple[str, ImplementationStatus, ControlEffectiveness]]] = {
    ("CLN-001", "T1", "V6"): [("C06", _IMP, _PART), ("C08", _IMP, _SUB)],
    ("APP-001", "T1", "V1"): [("C01", _IMP, _PART), ("C09", _IMP, _PART)],
    ("DMZ-002", "T2", "V2"): [("C02", _PLN, _SUB), ("C09", _IMP, _PART)],
    ("DMZ-001", "T5", "V5"): [("C05", _IMP, _SUB)],
    ("MED-001", "T8", "V1"): [("C10", _PLN, _SUB)],
    ("MED-002", "T7", "V7"): [("C12", _IMP, _PART)],
    ("ADM-002", "T1", "V8"): [("C08", _IMP, _PART), ("C11", _IMP, _PART)],
    ("GST-001", "T3", "V3"): [("C03", _IMP, _SUB)],
}

# Branch C is mid-programme: its control links are recorded as Planned (no residual reduction yet).
BRANCHES_WITH_PLANNED_CONTROLS: frozenset[str] = frozenset({"C"})
