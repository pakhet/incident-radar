"""Read-only web service: the dashboard, its JSON API, and the Atom feed.

Run locally:  uv run uvicorn radar.api:app --port 8080
"""

from __future__ import annotations

import os
import time
from pathlib import Path

from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from . import config
from .feeds import atom
from .store import open_store

CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
    "img-src 'self' data:; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)
SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), browsing-topics=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}

rt = config.Runtime.from_env()
_store = None
_cache: dict = {"at": 0.0, "data": None}
CACHE_S = 60


def public_data() -> dict:
    """The public doc, cached in memory; the CDN caches in front of this too."""
    global _store
    if time.monotonic() - _cache["at"] > CACHE_S or _cache["data"] is None:
        _store = _store or open_store(rt.store, rt.gcp_project)
        _cache["data"] = _store.load("public") or {"generated": None, "incidents": [], "health": {}}
        _cache["at"] = time.monotonic()
    return _cache["data"]


def cached(resp: Response, seconds: int = 60) -> Response:
    resp.headers["Cache-Control"] = f"public, max-age={seconds}, s-maxage={seconds * 2}"
    return resp


async def incidents(request: Request) -> Response:
    return cached(JSONResponse(public_data()))


async def feed(request: Request) -> Response:
    base = rt.dashboard_url
    return cached(Response(atom(public_data(), base), media_type="application/atom+xml"), 300)


async def healthz(request: Request) -> Response:
    return PlainTextResponse("ok\n")


class Hardening(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method not in ("GET", "HEAD"):
            return PlainTextResponse("method not allowed\n", status_code=405, headers=SECURITY_HEADERS)
        resp = await call_next(request)
        resp.headers.update(SECURITY_HEADERS)
        if request.url.path.startswith("/_astro/"):
            resp.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        elif "cache-control" not in resp.headers:
            resp.headers["Cache-Control"] = "public, max-age=300, s-maxage=600"
        return resp


class CleanUrlStaticFiles(StaticFiles):
    """Serve /how-it-works from how-it-works.html (Astro's file-format output)."""

    async def get_response(self, path: str, scope):
        try:
            return await super().get_response(path, scope)
        except HTTPException as e:
            if e.status_code != 404 or not path or "." in Path(path).name:
                raise
            return await super().get_response(f"{path}.html", scope)


WEB_DIR = Path(os.environ.get("WEB_DIR", Path(__file__).resolve().parents[2] / "web" / "dist"))
routes = [
    Route("/api/incidents", incidents),
    Route("/feed.xml", feed),
    Route("/healthz", healthz),
]
if WEB_DIR.is_dir():
    routes.append(Mount("/", app=CleanUrlStaticFiles(directory=WEB_DIR, html=True)))

app = Starlette(routes=routes, middleware=[Middleware(Hardening)])
