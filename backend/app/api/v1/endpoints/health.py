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
    try:
        from backend.app.db.session import AsyncSessionLocal
        async with AsyncSessionLocal() as session:
            await session.execute(text("SELECT 1"))
            db_status = "connected"
    except Exception as exc:
        logger.warning("Database health check query warning: %s", exc)
        db_status = "degraded"

    return {
        "status": "healthy" if db_status == "connected" else "degraded",
        "project": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "database": db_status,
        "hf_model": settings.HF_MODEL_ID,
        "hf_configured": settings.is_hf_token_configured
    }

