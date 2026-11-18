from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.time import utcnow
from app.db.base import Base, UTCDateTime, new_uuid

if TYPE_CHECKING:
    from app.models.asset import Asset
    from app.models.network_zone import NetworkZone


class Branch(Base):
    __tablename__ = "branches"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    code: Mapped[str] = mapped_column(String(16), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    role: Mapped[str] = mapped_column(String(120), nullable=False)
    site_id: Mapped[int] = mapped_column(Integer, unique=True, nullable=False)
    location_label: Mapped[str] = mapped_column(String(120), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)

    zones: Mapped[list[NetworkZone]] = relationship(
        back_populates="branch", order_by="NetworkZone.vlan_id"
    )
    assets: Mapped[list[Asset]] = relationship(back_populates="branch")
