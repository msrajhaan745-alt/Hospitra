from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Column, ForeignKey, String, Table, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.constants import IncidentStatus, NoteType, Severity
from app.core.time import utcnow
from app.db.base import Base, UTCDateTime, enum_type, new_uuid

if TYPE_CHECKING:
    from app.models.asset import Asset
    from app.models.detection import Detection
    from app.models.security_event import SecurityEvent

incident_events = Table(
    "incident_events",
    Base.metadata,
    Column("incident_id", String(36), ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True),
    Column("event_id", String(36), ForeignKey("security_events.id", ondelete="RESTRICT"), primary_key=True),
)

incident_assets = Table(
    "incident_assets",
    Base.metadata,
    Column("incident_id", String(36), ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True),
    Column("asset_id", String(36), ForeignKey("assets.id", ondelete="RESTRICT"), primary_key=True),
)


class Incident(Base):
    """A security incident. Containment is a recorded state only — no real action is taken."""

    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    incident_number: Mapped[str] = mapped_column(String(16), unique=True, nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[Severity] = mapped_column(enum_type(Severity), nullable=False, index=True)
    status: Mapped[IncidentStatus] = mapped_column(enum_type(IncidentStatus), nullable=False, index=True)
    assigned_to: Mapped[str | None] = mapped_column(String(80), nullable=True)
    # The detection that caused this incident. UNIQUE: one detection -> at most one incident.
    detection_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("detections.id", ondelete="RESTRICT"), unique=True, nullable=False
    )
    resolution_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow, onupdate=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    detection: Mapped[Detection] = relationship()
    events: Mapped[list[SecurityEvent]] = relationship(secondary=incident_events, order_by="SecurityEvent.occurred_at")
    assets: Mapped[list[Asset]] = relationship(secondary=incident_assets, order_by="Asset.asset_tag")
    notes: Mapped[list[IncidentNote]] = relationship(
        back_populates="incident", order_by="IncidentNote.created_at", cascade="all, delete-orphan"
    )


class IncidentNote(Base):
    __tablename__ = "incident_notes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    incident_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    note_type: Mapped[NoteType] = mapped_column(enum_type(NoteType), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    author: Mapped[str] = mapped_column(String(80), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)

    incident: Mapped[Incident] = relationship(back_populates="notes")
