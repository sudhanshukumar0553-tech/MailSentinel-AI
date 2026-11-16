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
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

# 1. Immediate Base Gateway App (Guaranteed to boot with 0 dependencies)
app = FastAPI(
    title="MailSentinel AI Gateway",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 2. Ultra-Fast Zero-Overhead Probes (Never fail)
@app.get("/api/ping")
@app.get("/api/v1/ping")
@app.get("/ping")
async def ping():
    return {
        "status": "ok",
        "app": "MailSentinel AI",
        "runtime": "vercel-serverless",
        "platform": sys.platform
    }

@app.get("/api/diagnostic")
async def diagnostic():
    cwd = os.getcwd()
    entries = []
    try:
        entries = os.listdir(cwd)
    except Exception as e:
        entries = [str(e)]

    diag = {
        "cwd": cwd,
        "entries": entries,
        "sys_path": sys.path[:8],
        "vercel_env": os.environ.get("VERCEL"),
        "python_version": sys.version,
    }

    try:
        from backend.app.main import app as backend_app
        diag["backend_import"] = "SUCCESS"
        diag["backend_routes_count"] = len(backend_app.routes)
    except Exception as exc:
        diag["backend_import"] = "FAILED"
        diag["error"] = str(exc)
        diag["traceback"] = traceback.format_exc().splitlines()[-15:]

    return diag

# 3. Path Setup & SQLite Vercel Compatibility
ROOT_DIR = Path(__file__).resolve().parent.parent
BACKEND_DIR = ROOT_DIR / "backend"

for p in [ROOT_DIR, BACKEND_DIR, Path(os.getcwd()), Path(os.getcwd()) / "backend"]:
    p_str = str(p)
    if p.exists() and p_str not in sys.path:
        sys.path.insert(0, p_str)

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

# 4. Mount / Delegate to Full Backend Application
try:
    from backend.app.main import app as backend_app
    app = backend_app
    handler = backend_app
except Exception as init_exc:
    init_err = str(init_exc)
    init_tb = traceback.format_exc()

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"])
    async def fallback_route(request: Request, path: str):
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": "MailSentinel FastAPI initialization failed on Vercel",
                "path": path,
                "detail": init_err,
                "traceback": init_tb.splitlines()[-15:],
            },
        )

    handler = app
