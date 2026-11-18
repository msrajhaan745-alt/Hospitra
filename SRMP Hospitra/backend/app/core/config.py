"""Application configuration.

Settings are read from environment variables (optionally prefixed ``HOSPITRA_``).
No secrets are required: Hospitra V1 is a single-operator, localhost-only demonstrator.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[2]
PROJECT_ROOT = BACKEND_DIR.parent
DEFAULT_DB_PATH = BACKEND_DIR / "data" / "hospitra.db"


def _default_database_url() -> str:
    return f"sqlite:///{DEFAULT_DB_PATH.as_posix()}"


@dataclass(frozen=True)
class Settings:
    app_name: str = "Hospitra"
    app_full_name: str = "Hospital Network Security & Risk Monitoring Platform"
    database_url: str = field(
        default_factory=lambda: os.getenv("HOSPITRA_DATABASE_URL", _default_database_url())
    )
    host: str = field(default_factory=lambda: os.getenv("HOSPITRA_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: int(os.getenv("HOSPITRA_PORT", "8000")))
    frontend_dir: Path = PROJECT_ROOT / "frontend"
    # Actor recorded for CLI-initiated actions (the API records the signed-in username).
    operator_actor: str = "local_operator"
    system_actor: str = "system"
    default_page_limit: int = 50
    max_page_limit: int = 200

    # ---- V2 authentication ----
    session_cookie_name: str = "hospitra_session"
    session_hours: int = field(default_factory=lambda: int(os.getenv("HOSPITRA_SESSION_HOURS", "8")))
    # Set to true when serving over HTTPS so the session cookie is only sent on TLS connections.
    cookie_secure: bool = field(default_factory=lambda: os.getenv("HOSPITRA_COOKIE_SECURE", "false").lower() == "true")
    # PBKDF2-SHA256 work factor for new password hashes (OWASP 2023 guidance: 600 000).
    pbkdf2_iterations: int = field(default_factory=lambda: int(os.getenv("HOSPITRA_PBKDF2_ITERATIONS", "600000")))
    password_min_length: int = 10
    login_max_failures: int = 5
    login_lockout_minutes: int = 15


settings = Settings()
