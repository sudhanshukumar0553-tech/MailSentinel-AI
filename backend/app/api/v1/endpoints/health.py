"""
MailSentinel AI - System Health & Diagnostics Endpoint
"""

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.db.session import get_db

router = APIRouter(tags=["Health & System"])


@router.get("/health", status_code=status.HTTP_200_OK)
async def check_health():
    """
    Returns system status, active database connectivity, and provider readiness.
    Safely reveals configuration status without exposing sensitive tokens.
    Guaranteed to return HTTP 200 OK without crashing serverless cold starts.
    """
    db_status = "disconnected"
    db_engine = "unknown"
    db_latency_ms = None
    try:
        import time
        from backend.app.db.session import AsyncSessionLocal, engine
        db_engine = engine.name  # 'sqlite' or 'postgresql'
        start_time = time.perf_counter()
        async with AsyncSessionLocal() as session:
            await session.execute(text("SELECT 1"))
            db_status = "connected"
        db_latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
    except Exception as exc:
        logger.warning("Database health check query warning: %s", exc)
        db_status = "degraded"

    return {
        "status": "healthy" if db_status == "connected" else "degraded",
        "project": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "database": db_status,
        "database_engine": db_engine,
        "database_latency_ms": db_latency_ms,
        "hf_model": settings.HF_MODEL_ID,
        "hf_configured": settings.is_hf_token_configured
    }

