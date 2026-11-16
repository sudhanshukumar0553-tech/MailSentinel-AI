"""
MailSentinel AI - Vercel Serverless Function Entrypoint
Exposes the ASGI FastAPI application for Vercel's native Python runtime (@vercel/python).
"""

import sys
import os
import shutil
import tempfile
import traceback
from pathlib import Path
from contextlib import asynccontextmanager

# Add project root and backend to sys.path so all internal modules are importable
ROOT_DIR = Path(__file__).resolve().parent.parent
BACKEND_DIR = ROOT_DIR / "backend"

for p in [ROOT_DIR, BACKEND_DIR, Path(os.getcwd()), Path(os.getcwd()) / "backend"]:
    p_str = str(p)
    if p.exists() and p_str not in sys.path:
        sys.path.insert(0, p_str)

# Vercel Serverless SQLite Compatibility Layer:
# On Vercel, the code root (/var/task) is strictly read-only.
# Only /tmp is writable. We copy the existing seed database to /tmp if not present,
# and direct SQLite queries there so read/write operations succeed during function invocations.
is_vercel = bool(
    os.environ.get("VERCEL")
    or os.environ.get("AWS_LAMBDA_FUNCTION_NAME")
    or os.environ.get("NOW_REGION")
)

if is_vercel:
    tmp_dir = Path(tempfile.gettempdir())
    tmp_db = tmp_dir / "mailsentinel.db"
    seed_db = ROOT_DIR / "mailsentinel.db"

    if seed_db.exists() and not tmp_db.exists():
        try:
            shutil.copy2(seed_db, tmp_db)
        except Exception:
            pass

    current_db_url = os.environ.get("DATABASE_URL", "")
    if not current_db_url or "sqlite" in current_db_url:
        posix_path = tmp_db.as_posix()
        if not posix_path.startswith("/"):
            posix_path = f"/{posix_path}"
        os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{posix_path.lstrip('/')}"

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.core.exceptions import register_exception_handlers
from backend.app.api.v1.router import api_v1_router
from backend.app.api.v1.endpoints import health


@asynccontextmanager
async def lifespan(app_instance: FastAPI):
    """Lifespan context ensuring database tables are ready without blocking."""
    try:
        from backend.app.db.session import init_db
        await init_db()
    except Exception as exc:
        logger.warning("Database initialization deferred on serverless startup: %s", exc)
    yield


# Explicit top-level FastAPI instantiation for Vercel AST detection
app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="MailSentinel AI Serverless Engine",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Register custom exception handlers
register_exception_handlers(app)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_origin_regex=r"https://.*\.vercel\.app",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount health routes
app.include_router(health.router)
app.include_router(health.router, prefix="/api")
app.include_router(health.router, prefix="/api/v1")

# Mount Master API v1 router under both /api/v1 and /v1
app.include_router(api_v1_router, prefix="/api/v1")
app.include_router(api_v1_router, prefix="/v1")


@app.get("/ping", tags=["Root"])
@app.get("/api/ping", tags=["Root"])
@app.get("/api/v1/ping", tags=["Root"])
async def ping():
    return {"status": "ok", "app": settings.PROJECT_NAME}


@app.get("/", tags=["Root"])
@app.get("/api", tags=["Root"])
async def root():
    return {
        "name": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "status": "online",
        "health": "/api/v1/health",
        "api_v1": "/api/v1"
    }

handler = app
