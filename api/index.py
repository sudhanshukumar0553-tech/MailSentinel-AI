"""
MailSentinel AI - Vercel Serverless Function Entrypoint
Exposes the ASGI FastAPI application for Vercel's native Python runtime (@vercel/python).
"""

import sys
import os
import traceback
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="MailSentinel AI Gateway",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/ping")
@app.get("/api/v1/ping")
@app.get("/ping")
async def ping():
    return {
        "status": "ok",
        "app": "MailSentinel AI",
        "python": sys.version,
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

    installed = []
    for mod in ["pydantic", "fastapi", "sqlalchemy", "sklearn", "numpy", "google.genai"]:
        try:
            m = __import__(mod)
            installed.append(f"{mod}: OK")
        except Exception as e:
            installed.append(f"{mod}: FAIL ({e})")

    backend_status = "NOT TESTED"
    backend_tb = ""
    try:
        from pathlib import Path
        ROOT_DIR = Path(__file__).resolve().parent.parent
        for p in [ROOT_DIR, ROOT_DIR / "backend", Path(cwd), Path(cwd) / "backend"]:
            p_str = str(p)
            if p.exists() and p_str not in sys.path:
                sys.path.insert(0, p_str)

        import backend.app.main as bm
        backend_status = "SUCCESS"
    except Exception as e:
        backend_status = f"FAILED: {e}"
        backend_tb = traceback.format_exc()

    return {
        "cwd": cwd,
        "entries": entries,
        "sys_path": sys.path[:8],
        "installed_packages": installed,
        "backend_import": backend_status,
        "traceback": backend_tb.splitlines()[-15:] if backend_tb else None
    }
