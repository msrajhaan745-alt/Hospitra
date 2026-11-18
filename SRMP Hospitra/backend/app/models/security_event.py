from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import JSON, Boolean, CheckConstraint, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.constants import EventType, Severity
from app.core.time import utcnow
from app.db.base import Base, UTCDateTime, enum_type, new_uuid

if TYPE_CHECKING:
    from app.models.asset import Asset
    from app.models.branch import Branch
    from app.models.detection import Detection
    from app.models.network_zone import NetworkZone


class SecurityEvent(Base):
    """A raw synthetic security event. Distinct from a rule-based ``Detection``."""

    __tablename__ = "security_events"
    __table_args__ = (
        # V1 only ever stores synthetic events; the schema enforces it.
        CheckConstraint("is_simulated = 1", name="synthetic_only"),
        Index("ix_security_events_branch_occurred", "branch_id", "occurred_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    event_type: Mapped[EventType] = mapped_column(enum_type(EventType), nullable=False, index=True)
    branch_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("branches.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    source_asset_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("assets.id", ondelete="RESTRICT"), nullable=True, index=True
    )
    destination_asset_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("assets.id", ondelete="RESTRICT"), nullable=True, index=True
    )
    source_zone_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("network_zones.id", ondelete="RESTRICT"), nullable=True
    )
    destination_zone_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("network_zones.id", ondelete="RESTRICT"), nullable=True
    )
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    destination_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    severity: Mapped[Severity] = mapped_column(enum_type(Severity), nullable=False, index=True)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    is_simulated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    scenario_id: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    simulation_run_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("simulation_runs.id", ondelete="RESTRICT"), nullable=True, index=True
    )
    # "metadata" is reserved on declarative classes, so the attribute is renamed.
    event_metadata: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, nullable=False, default=dict)
    occurred_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)

    branch: Mapped[Branch] = relationship()
    source_asset: Mapped[Asset | None] = relationship(foreign_keys=[source_asset_id])
    destination_asset: Mapped[Asset | None] = relationship(foreign_keys=[destination_asset_id])
    source_zone: Mapped[NetworkZone | None] = relationship(foreign_keys=[source_zone_id])
    destination_zone: Mapped[NetworkZone | None] = relationship(foreign_keys=[destination_zone_id])
    detections: Mapped[list[Detection]] = relationship(back_populates="event", order_by="Detection.rule_id")
