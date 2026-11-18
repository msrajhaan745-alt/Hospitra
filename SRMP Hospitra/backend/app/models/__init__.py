"""ORM models. Importing this package registers every table on ``Base.metadata``."""

from app.models.asset import Asset
from app.models.audit_log import AuditLog
from app.models.branch import Branch
from app.models.detection import Detection
from app.models.incident import Incident, IncidentNote, incident_assets, incident_events
from app.models.network_zone import NetworkZone
from app.models.risk import Risk
from app.models.security_control import RiskControl, SecurityControl, control_vulnerabilities
from app.models.security_event import SecurityEvent
from app.models.simulation_run import SimulationRun
from app.models.threat import Threat, ThreatVulnerabilityPair
from app.models.user import User, UserSession
from app.models.vulnerability import Vulnerability

__all__ = [
    "RiskControl",
    "SecurityControl",
    "User",
    "UserSession",
    "control_vulnerabilities",
    "Asset",
    "AuditLog",
    "Branch",
    "Detection",
    "Incident",
    "IncidentNote",
    "NetworkZone",
    "Risk",
    "SecurityEvent",
    "SimulationRun",
    "Threat",
    "ThreatVulnerabilityPair",
    "Vulnerability",
    "incident_assets",
    "incident_events",
]
