"""Hospitra FastAPI application (modular monolith).

Serves the REST API under /api/v1, the WebSocket at /ws/events and the static
frontend at /. Version 2 requires a signed-in user for every API call except
/health and the public /api/v1/auth endpoints. Binds to localhost by default.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, FastAPI, Request
from fastapi.staticfiles import StaticFiles

from app import __version__
from app.api.dependencies import current_user
from app.api.routes import (
    assets,
    audit,
    auth,
    branches,
    controls,
    dashboard,
    detections,
    events,
    exports,
    health,
    incidents,
    risks,
    simulation,
    threats,
    users,
    vulnerabilities,
    ws,
    zones,
)
from app.core.config import settings
from app.core.exceptions import register_exception_handlers

logging.basicConfig(level=logging.INFO, format="%(levelname)s [%(name)s] %(message)s")

API_PREFIX = "/api/v1"


BUILD_COOKIE = "hospitra_build"


class FrontendFiles(StaticFiles):
    """Static frontend that browsers must revalidate on every load.

    Without Cache-Control, browsers heuristically cache ES modules and can keep running
    an old version after an upgrade. `no-cache` keeps the ETag/304 round trip cheap
    while guaranteeing the current code is used.

    Files cached by an earlier version (served without Cache-Control) are handled by
    `clear_stale_browser_cache` below.
    """

    async def get_response(self, path, scope):  # type: ignore[override]
        response = await super().get_response(path, scope)
        response.headers["Cache-Control"] = "no-cache"
        return response


async def clear_stale_browser_cache(request: Request, call_next):
    """One-off browser cache clear per version.

    A browser that cached the frontend of an earlier version without Cache-Control may
    serve the whole page from cache and never ask for the new files — but the stale page
    still calls the API. The first response (page, file or API) to a browser without the
    current build cookie therefore carries `Clear-Site-Data: "cache"`, which clears the
    HTTP cache only (cookies, including the session, are kept); the next reload gets the
    current version.
    """
    response = await call_next(request)
    if request.cookies.get(BUILD_COOKIE) != __version__:
        response.headers["Clear-Site-Data"] = '"cache"'
        response.set_cookie(BUILD_COOKIE, __version__, max_age=365 * 24 * 3600,
                            httponly=True, samesite="strict", secure=settings.cookie_secure)
    return response


def create_app(*, serve_frontend: bool = True) -> FastAPI:
    app = FastAPI(
        title="Hospitra API",
        description=(
            "Hospital Network Security & Risk Monitoring Platform v2. "
            "Session-cookie authentication with Viewer / Analyst / Admin roles. Bind to localhost; "
            "use HTTPS (and HOSPITRA_COOKIE_SECURE=true) before any network exposure."
        ),
        version=__version__,
    )
    register_exception_handlers(app)
    app.middleware("http")(clear_stale_browser_cache)

    # Public authentication endpoints.
    public = APIRouter(prefix=API_PREFIX)
    public.include_router(auth.router)

    # Everything else requires a valid session; write routes additionally check the role.
    api = APIRouter(prefix=API_PREFIX, dependencies=[Depends(current_user)])
    for module in (dashboard, branches, zones, assets, threats, vulnerabilities, controls, risks, events, detections,
                   simulation, incidents, audit, exports, users):
        api.include_router(module.router)

    app.include_router(health.router)
    app.include_router(public)
    app.include_router(api)
    app.include_router(ws.router)

    if serve_frontend and settings.frontend_dir.is_dir():
        app.mount("/", FrontendFiles(directory=settings.frontend_dir, html=True), name="frontend")
    return app


app = create_app()
