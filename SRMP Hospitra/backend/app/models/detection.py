from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import JSON, Boolean, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.constants import Severity
from app.core.time import utcnow
from app.db.base import Base, UTCDateTime, enum_type, new_uuid

if TYPE_CHECKING:
    from app.models.asset import Asset
    from app.models.security_event import SecurityEvent


class Detection(Base):
    """The result of evaluating one deterministic rule against one event.

    A matched detection is an investigation lead — not proof of malicious activity.
    The (event_id, rule_id) unique constraint guarantees that re-processing an event
    cannot produce duplicate detections.
    """

    __tablename__ = "detections"
    __table_args__ = (UniqueConstraint("event_id", "rule_id", name="uq_detections_event_rule"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    event_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("security_events.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    rule_id: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    rule_name: Mapped[str] = mapped_column(String(120), nullable=False)
    matched: Mapped[bool] = mapped_column(Boolean, nullable=False, index=True)
    severity: Mapped[Severity] = mapped_column(enum_type(Severity), nullable=False, index=True)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    asset_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("assets.id", ondelete="RESTRICT"), nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow, index=True)

    event: Mapped[SecurityEvent] = relationship(back_populates="detections")
    asset: Mapped[Asset | None] = relationship()
