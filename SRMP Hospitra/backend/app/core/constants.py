"""Domain enumerations and fixed reference values.

These enums are the single source of truth for permitted values. They are used by the
SQLAlchemy models (as CHECK-constrained columns), the Pydantic schemas and the services.
"""

from __future__ import annotations

from enum import StrEnum


class Criticality(StrEnum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class DataClassification(StrEnum):
    PUBLIC = "Public"
    INTERNAL = "Internal"
    CONFIDENTIAL = "Confidential"
    RESTRICTED = "Restricted"


class AssetStatus(StrEnum):
    ACTIVE = "Active"
    WARNING = "Warning"
    OFFLINE = "Offline"
    MAINTENANCE = "Maintenance"


class AssetType(StrEnum):
    NETWORK_DEVICE = "Network Device"
    SERVER = "Server"
    DATABASE_SERVER = "Database Server"
    WORKSTATION = "Workstation"
    MEDICAL_DEVICE = "Medical Device"
    ACCESS_POINT = "Access Point"
    ENDPOINT = "Endpoint"
    SECURITY_APPLIANCE = "Security Appliance"
    WEB_SERVER = "Web Server"
    VPN_GATEWAY = "VPN Gateway"


class Severity(StrEnum):
    LOW = "Low"
    MODERATE = "Moderate"
    HIGH = "High"
    CRITICAL = "Critical"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.LOW: 1,
    Severity.MODERATE: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

# Detection severities that cause an automatic incident (spec §10.5).
INCIDENT_SEVERITIES: frozenset[Severity] = frozenset({Severity.HIGH, Severity.CRITICAL})


class Treatment(StrEnum):
    MITIGATE = "Mitigate"
    ACCEPT = "Accept"
    TRANSFER = "Transfer"
    AVOID = "Avoid"


class RiskStatus(StrEnum):
    OPEN = "Open"
    IN_TREATMENT = "In Treatment"
    CLOSED = "Closed"


class IncidentStatus(StrEnum):
    OPEN = "Open"
    INVESTIGATING = "Investigating"
    CONTAINED = "Contained"
    RESOLVED = "Resolved"
    CLOSED = "Closed"


# Strict forward, one step at a time (approved decision). Closed is terminal.
INCIDENT_TRANSITIONS: dict[IncidentStatus, IncidentStatus | None] = {
    IncidentStatus.OPEN: IncidentStatus.INVESTIGATING,
    IncidentStatus.INVESTIGATING: IncidentStatus.CONTAINED,
    IncidentStatus.CONTAINED: IncidentStatus.RESOLVED,
    IncidentStatus.RESOLVED: IncidentStatus.CLOSED,
    IncidentStatus.CLOSED: None,
}

ACTIVE_INCIDENT_STATUSES: frozenset[IncidentStatus] = frozenset(
    {IncidentStatus.OPEN, IncidentStatus.INVESTIGATING, IncidentStatus.CONTAINED}
)


class NoteType(StrEnum):
    INVESTIGATION = "Investigation"
    CONTAINMENT = "Containment"
    RESOLUTION = "Resolution"


class CatalogueSource(StrEnum):
    """Whether a threat/vulnerability comes from the initial case study or was proposed later."""

    CASE_STUDY = "Case Study"
    PROPOSED = "Proposed"


class ZoneType(StrEnum):
    MANAGEMENT = "management"
    STAFF = "staff"
    CLINICAL = "clinical"
    APPLICATION = "application"
    MEDICAL = "medical"
    GUEST = "guest"
    SECURITY = "security"
    DMZ = "dmz"


# Fixed VLAN / security-zone template (spec §6.2). Same for every branch.
ZONE_TEMPLATE: list[dict] = [
    {"vlan_id": 10, "zone_type": ZoneType.MANAGEMENT, "name": "Network Management", "code": "NET",
     "description": "Switch, router and server management interfaces. Reachable only through designated management paths."},
    {"vlan_id": 20, "zone_type": ZoneType.STAFF, "name": "Staff / Administration", "code": "ADM",
     "description": "Administrative and back-office workstations and file services."},
    {"vlan_id": 30, "zone_type": ZoneType.CLINICAL, "name": "Clinical Workstations", "code": "CLN",
     "description": "Clinical workstations. Permitted to reach approved clinical application services only."},
    {"vlan_id": 40, "zone_type": ZoneType.APPLICATION, "name": "Application / Data", "code": "APP",
     "description": "Clinical application and database servers."},
    {"vlan_id": 50, "zone_type": ZoneType.MEDICAL, "name": "Medical Devices", "code": "MED",
     "description": "Networked medical devices. Communicate only with approved clinical services."},
    {"vlan_id": 60, "zone_type": ZoneType.GUEST, "name": "Guest Wi-Fi", "code": "GST",
     "description": "Guest wireless access. Internet-only intent; no access to private hospital networks."},
    {"vlan_id": 70, "zone_type": ZoneType.SECURITY, "name": "Security Services", "code": "SEC",
     "description": "Security telemetry collection and backup services."},
    {"vlan_id": 80, "zone_type": ZoneType.DMZ, "name": "DMZ", "code": "DMZ",
     "description": "Public-facing services and remote-access termination."},
]

# Zones guest devices must never reach (everything private; DMZ is public-facing by design).
GUEST_RESTRICTED_ZONE_TYPES: frozenset[ZoneType] = frozenset(
    {ZoneType.MANAGEMENT, ZoneType.STAFF, ZoneType.CLINICAL, ZoneType.APPLICATION,
     ZoneType.MEDICAL, ZoneType.SECURITY}
)

# Zones in which an unregistered device is a policy concern (rule R4).
SENSITIVE_ZONE_TYPES: frozenset[ZoneType] = frozenset(
    {ZoneType.MANAGEMENT, ZoneType.CLINICAL, ZoneType.APPLICATION, ZoneType.MEDICAL,
     ZoneType.SECURITY}
)


class EventType(StrEnum):
    NETWORK_ACCESS = "network_access"
    AUTH_FAILURE = "auth_failure"
    VPN_LOGIN = "vpn_login"
    DEVICE_OBSERVED = "device_observed"
    OUTBOUND_TRANSFER = "outbound_transfer"
    REQUEST_VOLUME = "request_volume"
    FILE_ACTIVITY = "file_activity"
    VENDOR_ACCESS = "vendor_access"
    TELEMETRY = "telemetry"


BASELINE_SCENARIO_ID = "BASELINE"


# ---------------------------------------------------------------------------------------
# V2 — users and roles
# ---------------------------------------------------------------------------------------
class Role(StrEnum):
    ADMIN = "Admin"
    ANALYST = "Analyst"
    VIEWER = "Viewer"


class Permission(StrEnum):
    READ = "read"          # view everything, download exports
    OPERATE = "operate"    # simulations, incidents, assets, catalogue, risks, controls
    ADMIN = "admin"        # user management, data reset


ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.VIEWER: frozenset({Permission.READ}),
    Role.ANALYST: frozenset({Permission.READ, Permission.OPERATE}),
    Role.ADMIN: frozenset({Permission.READ, Permission.OPERATE, Permission.ADMIN}),
}


# ---------------------------------------------------------------------------------------
# V2 — security controls and residual risk
# ---------------------------------------------------------------------------------------
class ControlType(StrEnum):
    PREVENTIVE = "Preventive"
    DETECTIVE = "Detective"
    CORRECTIVE = "Corrective"


class ImplementationStatus(StrEnum):
    PLANNED = "Planned"
    IMPLEMENTED = "Implemented"


class ControlEffectiveness(StrEnum):
    PARTIAL = "Partial"
    SUBSTANTIAL = "Substantial"


class RiskAxis(StrEnum):
    LIKELIHOOD = "likelihood"
    IMPACT = "impact"


# Which risk axis a control type reduces (approved V2 residual model).
CONTROL_AXIS: dict[ControlType, RiskAxis] = {
    ControlType.PREVENTIVE: RiskAxis.LIKELIHOOD,
    ControlType.DETECTIVE: RiskAxis.IMPACT,
    ControlType.CORRECTIVE: RiskAxis.IMPACT,
}

# Levels removed from the axis by one implemented control.
EFFECTIVENESS_LEVELS: dict[ControlEffectiveness, int] = {
    ControlEffectiveness.PARTIAL: 1,
    ControlEffectiveness.SUBSTANTIAL: 2,
}
