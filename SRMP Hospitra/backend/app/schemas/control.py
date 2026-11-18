from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.constants import ControlEffectiveness, ControlType, ImplementationStatus, RiskAxis
from app.schemas.threat import normalise_code, strip_required


class VulnerabilityRef(BaseModel):
    id: str
    code: str
    name: str


class ControlRead(BaseModel):
    id: str
    code: str
    name: str
    description: str
    control_type: ControlType
    axis: RiskAxis
    category: str
    active: bool
    created_at: datetime
    updated_at: datetime
    vulnerabilities: list[VulnerabilityRef] = []
    linked_risk_count: int = 0
    implemented_link_count: int = 0


class ControlCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str = Field(min_length=2, max_length=16)
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(min_length=1, max_length=4000)
    control_type: ControlType
    category: str = Field(min_length=1, max_length=60)
    active: bool = True
    vulnerability_ids: list[str] = Field(default_factory=list, max_length=50)

    @field_validator("code")
    @classmethod
    def _code(cls, v: str) -> str:
        return normalise_code(v)

    @field_validator("name", "description", "category")
    @classmethod
    def _text(cls, v: str) -> str:
        return strip_required(v)


class ControlUpdate(BaseModel):
    """Code is immutable. Changing type or active status recalculates residual risk on linked risks."""

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=120)
    description: str | None = Field(default=None, min_length=1, max_length=4000)
    control_type: ControlType | None = None
    category: str | None = Field(default=None, min_length=1, max_length=60)
    active: bool | None = None
    vulnerability_ids: list[str] | None = Field(default=None, max_length=50)

    @field_validator("name", "description", "category")
    @classmethod
    def _text(cls, v: str | None) -> str | None:
        return None if v is None else strip_required(v)


class RiskControlCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    control_id: str
    implementation_status: ImplementationStatus
    effectiveness: ControlEffectiveness
    notes: str = Field(default="", max_length=2000)


class RiskControlUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    implementation_status: ImplementationStatus | None = None
    effectiveness: ControlEffectiveness | None = None
    notes: str | None = Field(default=None, max_length=2000)


class RiskControlRead(BaseModel):
    control_id: str
    code: str
    name: str
    control_type: ControlType
    axis: RiskAxis
    category: str
    control_active: bool
    implementation_status: ImplementationStatus
    effectiveness: ControlEffectiveness
    notes: str
    reduction: int          # levels this link would remove if counted (1 or 2)
    counted: bool           # implemented and the control record is active
    applied: bool           # the strongest counted control on its axis (the one used in the calculation)
    created_at: datetime
    updated_at: datetime


class ResidualCalculation(BaseModel):
    rule: str = ("Only implemented controls count. Preventive → likelihood; detective/corrective → impact. "
                 "Partial = 1 level, Substantial = 2. Strongest control per axis only; minimum 1.")
    likelihood_expression: str
    impact_expression: str
    score_expression: str
    severity_band: str
