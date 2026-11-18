from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.core.constants import Severity


class ScenarioRead(BaseModel):
    scenario_id: str
    name: str
    description: str
    expected_rule_id: str
    expected_rule_name: str
    expected_severity: Severity
    creates_incident: bool
    event_count: int
    source_description: str
    destination_description: str


class TriggerRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_id: str = Field(pattern=r"^S[1-8]$")
    branch_code: Literal["A", "B", "C"] = "A"


class SimulationRunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    scenario_id: str
    scenario_name: str
    branch_id: str
    branch_code: str
    triggered_by: str
    status: str
    event_count: int
    matched_detection_count: int
    incident_count: int
    started_at: datetime
    completed_at: datetime | None


class TriggerResponse(BaseModel):
    run: SimulationRunRead
    event_ids: list[str]
    matched_detection_ids: list[str]
    incident_ids: list[str]
    summary: str


class ResetRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    confirm: Literal["RESET"] = Field(description='Must be the literal string "RESET".')
