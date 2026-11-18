from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.constants import RiskStatus, Severity, Treatment
from app.core.time import utcnow
from app.db.base import Base, UTCDateTime, enum_type, new_uuid

if TYPE_CHECKING:
    from app.models.asset import Asset
    from app.models.security_control import RiskControl
    from app.models.threat import Threat
    from app.models.vulnerability import Vulnerability


class Risk(Base):
    """An illustrative risk record.

    ``overall_impact``, ``risk_score`` and ``severity`` are derived values. They are written
    only by ``RiskService`` via ``app.core.risk_model.assess_risk`` and are never accepted
    from API input.
    """

    __tablename__ = "risks"
    __table_args__ = (
        UniqueConstraint("asset_id", "threat_id", "vulnerability_id", name="uq_risks_asset_threat_vuln"),
        CheckConstraint("likelihood BETWEEN 1 AND 5", name="likelihood_range"),
        CheckConstraint("confidentiality_impact BETWEEN 1 AND 5", name="c_impact_range"),
        CheckConstraint("integrity_impact BETWEEN 1 AND 5", name="i_impact_range"),
        CheckConstraint("availability_impact BETWEEN 1 AND 5", name="a_impact_range"),
        CheckConstraint("overall_impact BETWEEN 1 AND 5", name="overall_impact_range"),
        CheckConstraint("risk_score BETWEEN 1 AND 25", name="risk_score_range"),
        CheckConstraint("residual_likelihood BETWEEN 1 AND 5", name="residual_likelihood_range"),
        CheckConstraint("residual_impact BETWEEN 1 AND 5", name="residual_impact_range"),
        CheckConstraint("residual_score BETWEEN 1 AND 25", name="residual_score_range"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    reference: Mapped[str] = mapped_column(String(16), unique=True, nullable=False)
    asset_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("assets.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    threat_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("threats.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    vulnerability_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("vulnerabilities.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    likelihood: Mapped[int] = mapped_column(Integer, nullable=False)
    confidentiality_impact: Mapped[int] = mapped_column(Integer, nullable=False)
    integrity_impact: Mapped[int] = mapped_column(Integer, nullable=False)
    availability_impact: Mapped[int] = mapped_column(Integer, nullable=False)
    overall_impact: Mapped[int] = mapped_column(Integer, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    severity: Mapped[Severity] = mapped_column(enum_type(Severity), nullable=False, index=True)
    # V2 residual risk (derived from implemented controls via core.risk_model.assess_residual)
    residual_likelihood: Mapped[int] = mapped_column(Integer, nullable=False)
    residual_impact: Mapped[int] = mapped_column(Integer, nullable=False)
    residual_score: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    residual_severity: Mapped[Severity] = mapped_column(enum_type(Severity, name="residual_severity"), nullable=False, index=True)
    treatment: Mapped[Treatment] = mapped_column(enum_type(Treatment), nullable=False)
    owner: Mapped[str] = mapped_column(String(120), nullable=False)
    status: Mapped[RiskStatus] = mapped_column(enum_type(RiskStatus), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime, nullable=False, default=utcnow, onupdate=utcnow
    )

    asset: Mapped[Asset] = relationship()
    threat: Mapped[Threat] = relationship()
    vulnerability: Mapped[Vulnerability] = relationship()
    control_links: Mapped[list[RiskControl]] = relationship(
        back_populates="risk", cascade="all, delete-orphan", order_by="RiskControl.created_at"
    )
