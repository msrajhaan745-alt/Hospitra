"""Browsers must never keep running a frontend from an earlier version."""

from fastapi.testclient import TestClient

from app import __version__
from app.main import BUILD_COOKIE, create_app


def test_frontend_files_require_revalidation():
    with TestClient(create_app(serve_frontend=True)) as c:
        for path in ("/", "/js/app.js", "/css/base.css"):
            r = c.get(path)
            assert r.status_code == 200, path
            assert r.headers["cache-control"] == "no-cache", path
            assert r.headers.get("etag"), path


def test_stale_browser_cache_is_cleared_once_per_version():
    with TestClient(create_app(serve_frontend=True)) as c:
        # A browser without the build cookie (e.g. a cached V1 page calling the API) gets a cache clear.
        first = c.get("/api/v1/dashboard/summary")
        assert first.status_code == 401
        assert first.headers["clear-site-data"] == '"cache"'
        assert c.cookies.get(BUILD_COOKIE) == __version__
        # Afterwards the header is not repeated.
        for path in ("/", "/js/app.js", "/api/v1/auth/status"):
            assert "clear-site-data" not in c.get(path).headers, path


def test_outdated_build_cookie_triggers_clear():
    with TestClient(create_app(serve_frontend=True)) as c:
        c.cookies.set(BUILD_COOKIE, "1.0.0")
        assert c.get("/").headers["clear-site-data"] == '"cache"'
