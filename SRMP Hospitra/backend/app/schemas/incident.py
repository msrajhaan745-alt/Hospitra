from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.constants import IncidentStatus, NoteType, Severity


class NoteCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    note_type: NoteType
    body: str = Field(min_length=1, max_length=4000)

    @field_validator("body")
    @classmethod
    def _body(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Note must not be blank.")
        return v


class IncidentUpdate(BaseModel):
    """Status changes, assignment and notes. Status may only advance one step:
    Open → Investigating → Contained → Resolved → Closed."""

    model_config = ConfigDict(extra="forbid")

    status: IncidentStatus | None = None
    assigned_to: str | None = Field(default=None, max_length=80)
    note: NoteCreate | None = None

    @field_validator("assigned_to")
    @classmethod
    def _assignee(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        if not v:
            raise ValueError("Assignee must not be blank.")
        return v

    @model_validator(mode="after")
    def _not_empty(self) -> IncidentUpdate:
        if not self.model_fields_set:
            raise ValueError("Provide at least one of: status, assigned_to, note.")
        return self


class IncidentNoteRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    note_type: NoteType
    body: str
    author: str
    created_at: datetime


class IncidentRead(BaseModel):
    id: str
    incident_number: str
    title: str
    description: str
    severity: Severity
    status: IncidentStatus
    assigned_to: str | None
    resolution_notes: str | None
    detection_id: str
    rule_id: str
    rule_name: str
    branch_code: str | None
    asset_tags: list[str]
    event_count: int
    allowed_next_status: IncidentStatus | None
    created_at: datetime
    updated_at: datetime
    resolved_at: datetime | None
    closed_at: datetime | None


class IncidentDetail(IncidentRead):
    notes: list[IncidentNoteRead] = []
    events: list[Any] = []
    assets: list[Any] = []
    detection: Any | None = None
    risk_context: list[Any] = []
    history: list[Any] = []
