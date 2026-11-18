from __future__ import annotations

import ipaddress
import re
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.constants import AssetStatus, AssetType, Criticality, DataClassification, Severity
from app.schemas.common import ORMModel

ASSET_TAG_PATTERN = re.compile(r"^[A-Z0-9][A-Z0-9-]{2,31}$")

Rating = Field(ge=1, le=5, strict=True)


def _normalise_tag(value: str) -> str:
    value = value.strip().upper()
    if not ASSET_TAG_PATTERN.match(value):
        raise ValueError("Asset tag must be 3–32 characters of A–Z, 0–9 and hyphens (e.g. HSP-A-CLN-003).")
    return value


def _validate_ipv4(value: str) -> str:
    value = value.strip()
    try:
        ipaddress.IPv4Address(value)
    except ValueError as exc:
        raise ValueError("IP address must be a valid IPv4 address.") from exc
    return value


def _required_text(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("Must not be blank.")
    return value


class AssetBase(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AssetCreate(AssetBase):
    asset_tag: str = Field(min_length=3, max_length=32)
    name: str = Field(min_length=1, max_length=120)
    asset_type: AssetType
    ip_address: str
    operating_system: str = Field(default="", max_length=80)
    criticality: Criticality
    data_classification: DataClassification
    confidentiality: int = Rating
    integrity: int = Rating
    availability: int = Rating
    status: AssetStatus = AssetStatus.ACTIVE
    owner: str = Field(min_length=1, max_length=120)
    branch_id: str
    zone_id: str
    last_seen_at: datetime | None = None

    @field_validator("asset_tag")
    @classmethod
    def _tag(cls, v: str) -> str:
        return _normalise_tag(v)

    @field_validator("ip_address")
    @classmethod
    def _ip(cls, v: str) -> str:
        return _validate_ipv4(v)

    @field_validator("name", "owner")
    @classmethod
    def _text(cls, v: str) -> str:
        return _required_text(v)


class AssetUpdate(AssetBase):
    asset_tag: str | None = Field(default=None, min_length=3, max_length=32)
    name: str | None = Field(default=None, min_length=1, max_length=120)
    asset_type: AssetType | None = None
    ip_address: str | None = None
    operating_system: str | None = Field(default=None, max_length=80)
    criticality: Criticality | None = None
    data_classification: DataClassification | None = None
    confidentiality: int | None = Field(default=None, ge=1, le=5, strict=True)
    integrity: int | None = Field(default=None, ge=1, le=5, strict=True)
    availability: int | None = Field(default=None, ge=1, le=5, strict=True)
    status: AssetStatus | None = None
    owner: str | None = Field(default=None, min_length=1, max_length=120)
    branch_id: str | None = None
    zone_id: str | None = None
    last_seen_at: datetime | None = None

    @field_validator("asset_tag")
    @classmethod
    def _tag(cls, v: str | None) -> str | None:
        return None if v is None else _normalise_tag(v)

    @field_validator("ip_address")
    @classmethod
    def _ip(cls, v: str | None) -> str | None:
        return None if v is None else _validate_ipv4(v)

    @field_validator("name", "owner")
    @classmethod
    def _text(cls, v: str | None) -> str | None:
        return None if v is None else _required_text(v)


class AssetRead(ORMModel):
    id: str
    asset_tag: str
    name: str
    asset_type: AssetType
    ip_address: str
    operating_system: str
    criticality: Criticality
    data_classification: DataClassification
    confidentiality: int
    integrity: int
    availability: int
    status: AssetStatus
    owner: str
    branch_id: str
    branch_code: str
    branch_name: str
    zone_id: str
    zone_name: str
    zone_code: str
    zone_type: str
    vlan_id: int
    last_seen_at: datetime | None
    created_at: datetime
    updated_at: datetime


class AssetRiskSummary(BaseModel):
    id: str
    reference: str
    threat_code: str
    threat_name: str
    vulnerability_code: str
    vulnerability_name: str
    risk_score: int
    severity: Severity
    status: str


class AssetDetail(AssetRead):
    risks: list[AssetRiskSummary] = []
    open_incident_count: int = 0
    event_count: int = 0
