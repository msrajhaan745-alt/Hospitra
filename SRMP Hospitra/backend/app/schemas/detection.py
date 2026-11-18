from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel

from app.core.constants import Severity


class RuleRead(BaseModel):
    rule_id: str
    name: str
    description: str
    event_types: list[str]
    conditions: list[str]
    severity: Severity
    explanation_template: str
    enabled: bool
    creates_incident: bool
    related_threat_codes: list[str]
    related_vulnerability_codes: list[str]
    scenario_ids: list[str]


class DetectionEventBrief(BaseModel):
    id: str
    event_type: str
    occurred_at: datetime
    branch_code: str
    scenario_id: str
    message: str


class DetectionRead(BaseModel):
    id: str
    event_id: str
    rule_id: str
    rule_name: str
    matched: bool
    severity: Severity
    explanation: str
    evidence: dict[str, Any]
    asset_id: str | None
    asset_tag: str | None
    created_at: datetime
    event: DetectionEventBrief
    incident_id: str | None = None
    incident_number: str | None = None


class DetectionDetail(DetectionRead):
    rule: RuleRead | None = None
    risk_context: list[Any] = []
