"""
MailSentinel AI - Main FastAPI Application

Production-oriented email security platform combining Machine Learning,
heuristics analysis, and an AI investigation agent.
"""

import os
import sys
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.core.exceptions import register_exception_handlers
from backend.app.db.session import init_db
from backend.app.api.v1.router import api_v1_router
from backend.app.api.v1.endpoints import health


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan events:
    Executes table creation and startup health verification on application boot.
    Non-blocking to ensure serverless cold starts never abort.
    """
    logger.info("Launching %s (Version: %s)...", settings.PROJECT_NAME, settings.VERSION)
    try:
        await init_db()
    except Exception as exc:
        logger.warning("Database initialization deferred on startup: %s", exc)
    logger.info("Hugging Face Provider Token configured: %s", settings.is_hf_token_configured)
    logger.info("Target AI Model: %s", settings.HF_MODEL_ID)
    yield
    logger.info("Shutting down %s gracefully...", settings.PROJECT_NAME)


def create_application() -> FastAPI:
    """Factory creating and configuring the FastAPI instance."""
    app = FastAPI(
        title=settings.PROJECT_NAME,
        version=settings.VERSION,
        description="Advanced AI-powered Email Spam & Phishing Detection Platform",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan
    )

    # Register custom exception handlers
    register_exception_handlers(app)

    # Configure CORS for Frontend React access (Local development & Vercel production)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_origin_regex=r"https://.*\.vercel\.app",
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Include health diagnostics directly at /health, /api/health, and under /api/v1/health
    app.include_router(health.router)
    app.include_router(health.router, prefix="/api")
    app.include_router(health.router, prefix="/api/v1")
    app.include_router(api_v1_router, prefix="/api/v1")
    app.include_router(api_v1_router, prefix="/v1")

    @app.get("/ping", tags=["Root"])
    @app.get("/api/ping", tags=["Root"])
    @app.get("/api/v1/ping", tags=["Root"])
    async def ping():
        """Ultra-fast zero-overhead health probe."""
        return {"status": "ok", "app": settings.PROJECT_NAME}

    @app.get("/api/diagnostic", tags=["Root"])
    async def diagnostic():
        """Runtime diagnostic information."""
        import sys, os
        return {
            "status": "healthy",
            "app": settings.PROJECT_NAME,
            "version": settings.VERSION,
            "cwd": os.getcwd(),
            "demo_mode": settings.DEMO_MODE,
            "gemini_configured": settings.is_gemini_configured,
            "python": sys.version
        }

    @app.get("/", tags=["Root"])
    @app.get("/api", tags=["Root"])
    async def root():
        """Root API metadata and status."""
        return {
            "name": settings.PROJECT_NAME,
            "version": settings.VERSION,
            "status": "online",
            "health": "/api/v1/health",
            "docs": "/docs",
            "api_v1": "/api/v1"
        }

    return app


app = create_application()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "backend.app.main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=settings.DEBUG
    )
