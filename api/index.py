"""
MailSentinel AI - Vercel Serverless Function Entrypoint
Exposes the ASGI FastAPI application for Vercel's native Python runtime (@vercel/python).
"""

import sys
import os
import shutil
import tempfile
from pathlib import Path

# Add project root to sys.path so 'backend' package is importable
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Vercel Serverless SQLite Compatibility Layer:
# On Vercel, the code root (/var/task) is strictly read-only.
# Only /tmp (tempfile.gettempdir()) is writable. We copy the existing seed database to /tmp if not present,
# and direct SQLite queries there so read/write operations succeed during function invocations.
is_vercel = bool(os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"))

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
        # Ensure leading slash for Unix absolute path /tmp
        if not posix_path.startswith("/") and not ":" in posix_path:
            posix_path = f"/{posix_path}"
        os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{posix_path}"

# Now import the configured FastAPI application
from backend.app.main import app
