"""Shared fixtures. Every test gets its own temporary SQLite database file."""

from __future__ import annotations

import os

# Fast password hashing for tests only (must be set before app settings are imported).
os.environ.setdefault("HOSPITRA_PBKDF2_ITERATIONS", "1000")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import select  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

import app.models  # noqa: E402,F401
from app.core.constants import Role  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.db.base import Base  # noqa: E402
from app.db.session import build_engine, get_db  # noqa: E402
from app.main import create_app  # noqa: E402
from app.models import Asset, Branch, NetworkZone, User  # noqa: E402
from app.seed.seeder import seed_reference_data  # noqa: E402
from app.services import user_service  # noqa: E402

TEST_PASSWORD = "correct-horse-battery"
ADMIN_USERNAME = "test-admin"


@pytest.fixture(autouse=True)
def _reset_login_throttle():
    user_service.reset_throttle()
    yield
    user_service.reset_throttle()


@pytest.fixture
def engine(tmp_path):
    eng = build_engine(f"sqlite:///{(tmp_path / 'test.db').as_posix()}")
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture
def session_factory(engine):
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


@pytest.fixture
def db(session_factory):
    session = session_factory()
    yield session
    session.close()


@pytest.fixture
def reference_db(db):
    """Database with branches, zones, 48 assets and the threat/vulnerability catalogue."""
    seed_reference_data(db)
    return db


@pytest.fixture
def seeded_db(db):
    """Complete demonstration dataset: network, catalogue, controls, risks and event history."""
    from app.seed.seeder import seed_all

    seed_all(db)
    return db


@pytest.fixture
def app(session_factory):
    application = create_app(serve_frontend=False)

    def _override():
        session = session_factory()
        try:
            yield session
        finally:
            session.close()

    application.dependency_overrides[get_db] = _override
    return application


def create_user(session_factory, username: str, role: Role, password: str = TEST_PASSWORD, active: bool = True) -> str:
    with session_factory() as s:
        user = User(username=username, display_name=username.replace("-", " ").title(), role=role,
                    password_hash=hash_password(password), active=active)
        s.add(user)
        s.commit()
        return user.id


def login(client: TestClient, username: str, password: str = TEST_PASSWORD) -> TestClient:
    r = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return client


@pytest.fixture
def anon_client(app):
    """A client with no session."""
    with TestClient(app) as c:
        yield c


@pytest.fixture
def client(app, session_factory):
    """A client signed in as an Admin (all permissions)."""
    create_user(session_factory, ADMIN_USERNAME, Role.ADMIN)
    with TestClient(app) as c:
        yield login(c, ADMIN_USERNAME)


@pytest.fixture
def client_as(app, session_factory):
    """Factory: client_as(Role.VIEWER) → a new client signed in with that role."""
    clients = []

    def _make(role: Role, username: str | None = None) -> TestClient:
        username = username or f"test-{role.value.lower()}"
        create_user(session_factory, username, role)
        c = TestClient(app)
        c.__enter__()
        clients.append(c)
        return login(c, username)

    yield _make
    for c in clients:
        c.__exit__(None, None, None)


# ---- lookup helpers ---------------------------------------------------------------------

def branch_by_code(db, code: str) -> Branch:
    return db.scalar(select(Branch).where(Branch.code == code))


def zone_by_code(db, branch_code: str, zone_code: str) -> NetworkZone:
    return db.scalar(
        select(NetworkZone).join(Branch).where(Branch.code == branch_code, NetworkZone.code == zone_code)
    )


def asset_by_tag(db, tag: str) -> Asset:
    return db.scalar(select(Asset).where(Asset.asset_tag == tag))
