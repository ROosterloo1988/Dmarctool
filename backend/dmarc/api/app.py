"""FastAPI application: API, authentication and the built React UI."""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker
from starlette.middleware.sessions import SessionMiddleware

from dmarc.config import Settings, get_settings
from dmarc.db.session import get_engine

from . import admin, auth, data

log = logging.getLogger(__name__)

SECURITY_HEADERS = {
    "Content-Security-Policy": ("default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                                "script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
                                "form-action 'self' https://login.microsoftonline.com"),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
}


def create_app(settings: Settings | None = None, sessions: sessionmaker[Session] | None = None) -> FastAPI:
    s = settings or get_settings()
    if s.secret_key is None or len(s.secret_key.get_secret_value()) < 32:
        raise RuntimeError("DMARC_SECRET_KEY must be set to a random value of at least 32 characters")

    app = FastAPI(title="DMARC reporting", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = s
    app.state.sessions = sessions or sessionmaker(bind=get_engine(s.database_url), expire_on_commit=False)
    app.state.oauth = auth.setup_oauth(s)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        if s.cookie_secure:
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
        if request.url.path.startswith(("/api", "/auth")):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    app.add_middleware(
        SessionMiddleware, secret_key=s.secret_key.get_secret_value(), session_cookie="dmarc_session",
        max_age=s.session_hours * 3600, same_site="lax", https_only=s.cookie_secure,
    )

    @app.get("/healthz", include_in_schema=False)
    def healthz():
        try:
            with app.state.sessions() as db:
                db.execute(text("SELECT 1"))
        except Exception:
            return JSONResponse({"status": "db unavailable"}, status_code=503)
        return {"status": "ok"}

    app.include_router(auth.router)
    app.include_router(data.router)
    app.include_router(admin.router)

    @app.api_route("/api/{rest:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"], include_in_schema=False)
    def api_not_found(rest: str):
        return JSONResponse({"detail": "not found"}, status_code=404)

    static = Path(s.static_dir) if s.static_dir else Path(__file__).resolve().parent.parent / "static"
    index = static / "index.html"
    if (static / "assets").is_dir():
        app.mount("/assets", StaticFiles(directory=static / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str):
        candidate = (static / path).resolve()
        if path and candidate.is_file() and static.resolve() in candidate.parents:
            return FileResponse(candidate)
        if index.is_file():
            return FileResponse(index, headers={"Cache-Control": "no-cache"})
        return PlainTextResponse("Frontend not built. Run `npm run build` in frontend/.", status_code=503)

    return app


def app_factory() -> FastAPI:  # uvicorn --factory dmarc.api.app:app_factory
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    return create_app()
