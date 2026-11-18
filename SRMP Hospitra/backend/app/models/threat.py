from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.constants import CatalogueSource
from app.core.time import utcnow
from app.db.base import Base, UTCDateTime, enum_type, new_uuid

if TYPE_CHECKING:
    from app.models.vulnerability import Vulnerability


class Threat(Base):
    __tablename__ = "threats"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    code: Mapped[str] = mapped_column(String(16), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(String(60), nullable=False)
    source_type: Mapped[CatalogueSource] = mapped_column(
        enum_type(CatalogueSource, name="catalogue_source"), nullable=False
    )
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)

    pairs: Mapped[list[ThreatVulnerabilityPair]] = relationship(back_populates="threat")


class ThreatVulnerabilityPair(Base):
    """A documented, technically plausible threat–vulnerability relationship (spec §7.3).

    Threats are deliberately NOT paired with every vulnerability. Each pairing carries a
    rationale explaining the technical relationship and its limits.
    """

    __tablename__ = "threat_vulnerability_pairs"
    __table_args__ = (
        UniqueConstraint("threat_id", "vulnerability_id", name="uq_tv_pairs_threat_vulnerability"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    threat_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("threats.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    vulnerability_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("vulnerabilities.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    rationale: Mapped[str] = mapped_column(Text, nullable=False)

    threat: Mapped[Threat] = relationship(back_populates="pairs")
    vulnerability: Mapped[Vulnerability] = relationship(back_populates="pairs")
