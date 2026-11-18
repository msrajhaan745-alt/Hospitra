from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, Column, ForeignKey, String, Table, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.constants import ControlEffectiveness, ControlType, ImplementationStatus
from app.core.time import utcnow
from app.db.base import Base, UTCDateTime, enum_type, new_uuid

if TYPE_CHECKING:
    from app.models.risk import Risk
    from app.models.vulnerability import Vulnerability

# Which vulnerabilities a control is designed to address (used to suggest controls; not enforced).
control_vulnerabilities = Table(
    "control_vulnerabilities",
    Base.metadata,
    Column("control_id", String(36), ForeignKey("security_controls.id", ondelete="CASCADE"), primary_key=True),
    Column("vulnerability_id", String(36), ForeignKey("vulnerabilities.id", ondelete="RESTRICT"), primary_key=True),
)


class SecurityControl(Base):
    """An illustrative security control in the control library (V2)."""

    __tablename__ = "security_controls"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    code: Mapped[str] = mapped_column(String(16), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    control_type: Mapped[ControlType] = mapped_column(enum_type(ControlType), nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(60), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow, onupdate=utcnow)

    vulnerabilities: Mapped[list[Vulnerability]] = relationship(secondary=control_vulnerabilities, order_by="Vulnerability.code")
    risk_links: Mapped[list[RiskControl]] = relationship(back_populates="control")


class RiskControl(Base):
    """A control applied to a risk, with its implementation status and effectiveness."""

    __tablename__ = "risk_controls"
    __table_args__ = (UniqueConstraint("risk_id", "control_id", name="uq_risk_controls_risk_control"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    risk_id: Mapped[str] = mapped_column(String(36), ForeignKey("risks.id", ondelete="CASCADE"), nullable=False, index=True)
    control_id: Mapped[str] = mapped_column(String(36), ForeignKey("security_controls.id", ondelete="RESTRICT"), nullable=False, index=True)
    implementation_status: Mapped[ImplementationStatus] = mapped_column(enum_type(ImplementationStatus), nullable=False)
    effectiveness: Mapped[ControlEffectiveness] = mapped_column(enum_type(ControlEffectiveness), nullable=False)
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow, onupdate=utcnow)

    risk: Mapped[Risk] = relationship(back_populates="control_links")
    control: Mapped[SecurityControl] = relationship(back_populates="risk_links")
