from __future__ import annotations

import re
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.constants import CatalogueSource

CODE_PATTERN = re.compile(r"^[A-Z][A-Z0-9-]{1,15}$")


def normalise_code(value: str) -> str:
    value = value.strip().upper()
    if not CODE_PATTERN.match(value):
        raise ValueError("Code must be 2–16 characters: a letter followed by A–Z, 0–9 or hyphens (e.g. T9).")
    return value


def strip_required(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("Must not be blank.")
    return value


class PairingRef(BaseModel):
    id: str
    code: str
    name: str
    rationale: str


class ThreatRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    code: str
    name: str
    description: str
    category: str
    source_type: CatalogueSource
    active: bool
    created_at: datetime
    risk_count: int = 0
    related_vulnerabilities: list[PairingRef] = []


class ThreatCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str = Field(min_length=2, max_length=16)
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(min_length=1, max_length=4000)
    category: str = Field(min_length=1, max_length=60)
    source_type: CatalogueSource = CatalogueSource.PROPOSED
    active: bool = True

    @field_validator("code")
    @classmethod
    def _code(cls, v: str) -> str:
        return normalise_code(v)

    @field_validator("name", "description", "category")
    @classmethod
    def _text(cls, v: str) -> str:
        return strip_required(v)


class ThreatUpdate(BaseModel):
    """Codes and source type are immutable; descriptive fields and active status may change."""

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=120)
    description: str | None = Field(default=None, min_length=1, max_length=4000)
    category: str | None = Field(default=None, min_length=1, max_length=60)
    active: bool | None = None

    @field_validator("name", "description", "category")
    @classmethod
    def _text(cls, v: str | None) -> str | None:
        return None if v is None else strip_required(v)
