from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.constants import ZoneType
from app.db.base import Base, enum_type, new_uuid

if TYPE_CHECKING:
    from app.models.asset import Asset
    from app.models.branch import Branch


class NetworkZone(Base):
    __tablename__ = "network_zones"
    __table_args__ = (
        UniqueConstraint("branch_id", "vlan_id", name="uq_network_zones_branch_vlan"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    branch_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("branches.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(80), nullable=False)
    code: Mapped[str] = mapped_column(String(8), nullable=False)
    zone_type: Mapped[ZoneType] = mapped_column(enum_type(ZoneType), nullable=False)
    vlan_id: Mapped[int] = mapped_column(Integer, nullable=False)
    subnet_cidr: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")

    branch: Mapped[Branch] = relationship(back_populates="zones")
    assets: Mapped[list[Asset]] = relationship(back_populates="zone", order_by="Asset.asset_tag")
