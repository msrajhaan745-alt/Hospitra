from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.constants import RiskStatus, Severity, Treatment
from app.schemas.control import ResidualCalculation, RiskControlRead


def _strip(v: str) -> str:
    v = v.strip()
    if not v:
        raise ValueError("Must not be blank.")
    return v


class RiskCreate(BaseModel):
    """Only the inputs. overall_impact, risk_score and severity are derived by the backend
    and are rejected if supplied (extra="forbid")."""

    model_config = ConfigDict(extra="forbid")

    asset_id: str
    threat_id: str
    vulnerability_id: str
    likelihood: int = Field(ge=1, le=5, strict=True)
    confidentiality_impact: int = Field(ge=1, le=5, strict=True)
    integrity_impact: int = Field(ge=1, le=5, strict=True)
    availability_impact: int = Field(ge=1, le=5, strict=True)
    treatment: Treatment
    owner: str = Field(min_length=1, max_length=120)
    status: RiskStatus = RiskStatus.OPEN

    @field_validator("owner")
    @classmethod
    def _owner(cls, v: str) -> str:
        return _strip(v)


class RiskUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    likelihood: int | None = Field(default=None, ge=1, le=5, strict=True)
    confidentiality_impact: int | None = Field(default=None, ge=1, le=5, strict=True)
    integrity_impact: int | None = Field(default=None, ge=1, le=5, strict=True)
    availability_impact: int | None = Field(default=None, ge=1, le=5, strict=True)
    treatment: Treatment | None = None
    owner: str | None = Field(default=None, min_length=1, max_length=120)
    status: RiskStatus | None = None

    @field_validator("owner")
    @classmethod
    def _owner(cls, v: str | None) -> str | None:
        return None if v is None else _strip(v)


class RiskAssetRef(BaseModel):
    id: str
    asset_tag: str
    name: str
    branch_code: str
    zone_name: str
    criticality: str
    data_classification: str


class CatalogueRef(BaseModel):
    id: str
    code: str
    name: str


class RiskCalculation(BaseModel):
    formula: str = "Risk Score = Likelihood × max(Confidentiality, Integrity, Availability)"
    impact_expression: str
    score_expression: str
    severity_band: str
    explanation: str


class RiskRead(BaseModel):
    id: str
    reference: str
    asset: RiskAssetRef
    threat: CatalogueRef
    vulnerability: CatalogueRef
    likelihood: int
    confidentiality_impact: int
    integrity_impact: int
    availability_impact: int
    overall_impact: int
    risk_score: int
    severity: Severity
    residual_likelihood: int
    residual_impact: int
    residual_score: int
    residual_severity: Severity
    residual_calculation: ResidualCalculation
    controls: list[RiskControlRead] = []
    treatment: Treatment
    owner: str
    status: RiskStatus
    created_at: datetime
    updated_at: datetime
    calculation: RiskCalculation
    pairing_rationale: str | None = None
