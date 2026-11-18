from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.constants import AssetStatus, AssetType, Criticality, DataClassification
from app.core.time import utcnow
from app.db.base import Base, UTCDateTime, enum_type, new_uuid

if TYPE_CHECKING:
    from app.models.branch import Branch
    from app.models.network_zone import NetworkZone


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        CheckConstraint("confidentiality BETWEEN 1 AND 5", name="confidentiality_range"),
        CheckConstraint("integrity BETWEEN 1 AND 5", name="integrity_range"),
        CheckConstraint("availability BETWEEN 1 AND 5", name="availability_range"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    asset_tag: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    asset_type: Mapped[AssetType] = mapped_column(enum_type(AssetType), nullable=False, index=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    operating_system: Mapped[str] = mapped_column(String(80), nullable=False, default="")
    criticality: Mapped[Criticality] = mapped_column(enum_type(Criticality), nullable=False, index=True)
    data_classification: Mapped[DataClassification] = mapped_column(
        enum_type(DataClassification), nullable=False
    )
    confidentiality: Mapped[int] = mapped_column(Integer, nullable=False)
    integrity: Mapped[int] = mapped_column(Integer, nullable=False)
    availability: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[AssetStatus] = mapped_column(enum_type(AssetStatus), nullable=False, index=True)
    owner: Mapped[str] = mapped_column(String(120), nullable=False)
    branch_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("branches.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    zone_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("network_zones.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime, nullable=False, default=utcnow, onupdate=utcnow
    )

    branch: Mapped[Branch] = relationship(back_populates="assets")
    zone: Mapped[NetworkZone] = relationship(back_populates="assets")
