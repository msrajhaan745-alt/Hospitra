"""The Alembic migrations must produce exactly the schema described by the ORM models."""

from pathlib import Path

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext

import app.models  # noqa: F401
from app.db.base import Base
from app.db.session import build_engine

BACKEND_DIR = Path(__file__).resolve().parents[2]


def test_migrations_match_models(tmp_path):
    url = f"sqlite:///{(tmp_path / 'migrated.db').as_posix()}"
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.attributes["database_url"] = url
    cfg.attributes["configure_logger"] = False
    command.upgrade(cfg, "head")

    engine = build_engine(url)
    with engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    engine.dispose()
    assert diff == []


def test_v1_data_is_backfilled_by_0002(tmp_path):
    """A V1 database with risks upgrades cleanly: residual values start equal to inherent values."""
    from sqlalchemy import text

    url = f"sqlite:///{(tmp_path / 'v1.db').as_posix()}"
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.attributes["database_url"] = url
    cfg.attributes["configure_logger"] = False
    command.upgrade(cfg, "0001")
    engine = build_engine(url)
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO branches (id, code, name, role, site_id, location_label, active, created_at) "
                          "VALUES ('b','A','n','r',20,'l',1,'2026-01-01 00:00:00')"))
        conn.execute(text("INSERT INTO network_zones (id, branch_id, name, code, zone_type, vlan_id, subnet_cidr, description) "
                          "VALUES ('z','b','Z','CLN','clinical',30,'10.20.30.0/24','')"))
        conn.execute(text("INSERT INTO assets (id, asset_tag, name, asset_type, ip_address, operating_system, criticality, "
                          "data_classification, confidentiality, integrity, availability, status, owner, branch_id, zone_id, "
                          "created_at, updated_at) VALUES ('a','HSP-A-CLN-001','n','Workstation','10.20.30.1','', 'High', "
                          "'Restricted',4,4,4,'Active','o','b','z','2026-01-01 00:00:00','2026-01-01 00:00:00')"))
        conn.execute(text("INSERT INTO threats (id, code, name, description, category, source_type, active, created_at) "
                          "VALUES ('t','T1','n','d','c','Case Study',1,'2026-01-01 00:00:00')"))
        conn.execute(text("INSERT INTO vulnerabilities (id, code, name, description, weakness_type, source_type, active, created_at) "
                          "VALUES ('v','V1','n','d','w','Case Study',1,'2026-01-01 00:00:00')"))
        conn.execute(text("INSERT INTO risks (id, reference, asset_id, threat_id, vulnerability_id, likelihood, "
                          "confidentiality_impact, integrity_impact, availability_impact, overall_impact, risk_score, severity, "
                          "treatment, owner, status, created_at, updated_at) VALUES ('r','RSK-0001','a','t','v',4,4,3,5,5,20,"
                          "'Critical','Mitigate','o','Open','2026-01-01 00:00:00','2026-01-01 00:00:00')"))
    engine.dispose()
    command.upgrade(cfg, "head")
    engine = build_engine(url)
    with engine.connect() as conn:
        row = conn.execute(text("SELECT residual_likelihood, residual_impact, residual_score, residual_severity FROM risks")).one()
    engine.dispose()
    assert tuple(row) == (4, 5, 20, "Critical")


def test_downgrade_to_base_and_back(tmp_path):
    url = f"sqlite:///{(tmp_path / 'roundtrip.db').as_posix()}"
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.attributes["database_url"] = url
    cfg.attributes["configure_logger"] = False
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")
