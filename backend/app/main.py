"""
ThreatLens — Threat Detection & URL Scanner.

A FastAPI application exposing:

* POST /api/scan-url          → full URL scan pipeline (heuristics + metadata + threat intel)
* POST /api/analyze-phishing  → rule-based NLP phishing content analysis
* GET  /api/history           → recent URL scans
* GET  /api/history/{id}      → full past scan report
* GET  /api/phishing-history  → recent phishing analyses
* GET  /api/health            → service health

The dashboard (plain HTML/CSS/JS in ``frontend/``) is served at ``/``.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from sqlalchemy import inspect, text

from .config import settings
from .database import Base, SessionLocal, engine
from .models import User
from .routers import admin, auth, history, intel, phishing, scanner, tools, users, audit, webhooks

# -- Database ---------------------------------------------------------------

def _ensure_legacy_columns() -> None:
    """Add columns introduced after the initial schema was created."""
    inspector = inspect(engine)
    with engine.begin() as conn:
        for table, column, ddl in (
            # NOTE: SQLite can't add an FK via ALTER TABLE, so legacy tables
            # get a plain INTEGER column. New databases create the column
            # with the proper REFERENCES clause via the ORM metadata.
            ("scans", "user_id", "INTEGER"),
            ("phishing_analyses", "user_id", "INTEGER"),
            ("users", "is_admin", "BOOLEAN DEFAULT 0"),
        ):
            if table not in inspector.get_table_names():
                continue
            columns = {c["name"] for c in inspector.get_columns(table)}
            if column not in columns:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}"))


def _promote_admin_from_env() -> None:
    """Promote the configured ADMIN_USERNAME (if any) at startup."""
    if not settings.ADMIN_USERNAME:
        return
    with SessionLocal() as db:
        user = db.query(User).filter(User.username == settings.ADMIN_USERNAME).first()
        if user is not None and not user.is_admin:
            user.is_admin = True
            db.commit()


Base.metadata.create_all(bind=engine)
_ensure_legacy_columns()
_promote_admin_from_env()

# -- App --------------------------------------------------------------------
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    description=settings.DESCRIPTION,
    docs_url="/api/docs",
    redoc_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)

# -- API routes --------------------------------------------------------------
app.include_router(auth.router)
app.include_router(users.router)
app.include_router(intel.router)
app.include_router(scanner.router)
app.include_router(phishing.router)
app.include_router(tools.router)
app.include_router(history.router)
app.include_router(admin.router)
app.include_router(audit.router)
app.include_router(webhooks.router)


@app.get("/api/health", tags=["meta"])
def health() -> dict:
    return {"status": "ok", "app": settings.APP_NAME, "version": settings.VERSION}


# -- Frontend (static dashboard) --------------------------------------------
FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"
STATIC_DIR = FRONTEND_DIR / "static"

if STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/{full_path:path}", include_in_schema=False)
def spa_fallback(full_path: str):
    """Serve static dashboard assets for any non-API path (SPA fallback).

    Path traversal is prevented by resolving the candidate and requiring it to
    stay inside the frontend directory.
    """
    frontend_root = FRONTEND_DIR.resolve()
    try:
        candidate = (frontend_root / full_path).resolve()
    except (OSError, ValueError):
        candidate = frontend_root
    if candidate.is_relative_to(frontend_root) and candidate.is_file():
        return FileResponse(candidate)
    # Log 404s for debugging (non-API paths only)
    return JSONResponse({"detail": "Not found"}, status_code=404)
