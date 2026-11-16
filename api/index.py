"""
MailSentinel AI - Vercel Serverless Function Entrypoint
Exposes the ASGI FastAPI application for Vercel's native Python runtime (@vercel/python).
"""

import sys
import os
import json
import shutil
import tempfile
import traceback
from pathlib import Path

# Add project root and backend to sys.path so all internal modules are importable
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

BACKEND_DIR = ROOT_DIR / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

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
        os.environ["DATABASE_URL"] = f"sqlite+aiosqlite://{posix_path}"

try:
    from backend.app.main import app
    handler = app
except Exception as init_exc:
    tb_str = traceback.format_exc()

    async def fallback_error_app(scope, receive, send):
        if scope["type"] == "http":
            error_payload = json.dumps({
                "status": "error",
                "detail": f"Application initialization failed: {init_exc}",
                "traceback": tb_str
            }).encode("utf-8")
            await send({
                "type": "http.response.start",
                "status": 500,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(error_payload)).encode("utf-8")),
                    (b"access-control-allow-origin", b"*"),
                ],
            })
            await send({
                "type": "http.response.body",
                "body": error_payload,
            })

    app = fallback_error_app
    handler = fallback_error_app
