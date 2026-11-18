from __future__ import annotations

from fastapi import APIRouter
from sqlalchemy import text

from app import __version__
from app.api.dependencies import DbSession
from app.core.time import utcnow

router = APIRouter(tags=["health"])


@router.get("/health", summary="Service and database health")
def health(db: DbSession) -> dict:
    try:
        db.execute(text("SELECT 1"))
        database = "ok"
    except Exception:  # pragma: no cover - defensive; details are never exposed
        database = "unavailable"
    return {
        "status": "ok" if database == "ok" else "degraded",
        "service": "hospitra",
        "version": __version__,
        "database": database,
        "timestamp": utcnow(),
    }
