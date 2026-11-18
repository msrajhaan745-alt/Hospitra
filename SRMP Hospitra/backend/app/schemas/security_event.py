from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.core.constants import EventType, Severity


class AssetRef(BaseModel):
    id: str
    asset_tag: str
    name: str
    asset_type: str
    criticality: str


class ZoneBrief(BaseModel):
    id: str
    name: str
    code: str
    zone_type: str
    vlan_id: int


class MatchedRuleRef(BaseModel):
    detection_id: str
    rule_id: str
    rule_name: str
    severity: Severity


class EventRead(BaseModel):
    id: str
    event_type: EventType
    branch_id: str
    branch_code: str
    source_asset: AssetRef | None
    destination_asset: AssetRef | None
    source_zone: ZoneBrief | None
    destination_zone: ZoneBrief | None
    source_ip: str | None
    destination_ip: str | None
    severity: Severity
    message: str
    is_simulated: bool
    scenario_id: str
    simulation_run_id: str | None
    metadata: dict[str, Any] = Field(default_factory=dict)
    occurred_at: datetime
    created_at: datetime
    detection_status: str  # "detected" | "no_match" | "not_evaluated"
    matched_rules: list[MatchedRuleRef] = []


class EventDetail(EventRead):
    detections: list[Any] = []          # DetectionRead (all evaluations, matched or not)
    rules: list[Any] = []               # RuleRead definitions for evaluated rules
    risk_context: list[Any] = []        # RiskRead
    incident: dict[str, Any] | None = None
