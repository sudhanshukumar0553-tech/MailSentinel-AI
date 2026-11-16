"""
MailSentinel AI - Asynchronous Database Session Management

Manages asynchronous connections and sessions using SQLAlchemy 2.0.
Works seamlessly with SQLite (aiosqlite) for local development
and PostgreSQL (psycopg) for production deployments.
"""

from typing import AsyncGenerator
from sqlalchemy import text
from sqlalchemy.pool import NullPool
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine
)
from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.db.base import Base

# Configure engine connection arguments based on database dialect
connect_args = {}
engine_kwargs = {
    "echo": False,
    "future": True
}

if "sqlite" in settings.DATABASE_URL:
    # SQLite requires check_same_thread=False and increased timeout for asynchronous concurrency
    connect_args["check_same_thread"] = False
    connect_args["timeout"] = 30.0
    # Use NullPool for SQLite to avoid connection pool locks during concurrent writes
    engine_kwargs["poolclass"] = NullPool

engine_kwargs["connect_args"] = connect_args

# Create the primary async engine
engine: AsyncEngine = create_async_engine(
    settings.DATABASE_URL,
    **engine_kwargs
)

# Async session factory
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency that yields an asynchronous database session.
    Automatically handles commit, rollback on error, and clean closure.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """
    Initializes database tables defined in the ORM models.
    Called on application startup.
    """
    try:
        # Import all models to ensure they are registered with Base.metadata
        import backend.app.db.models  # noqa: F401

        logger.info("Initializing database tables...")
        async with engine.begin() as conn:
            if "sqlite" in settings.DATABASE_URL:
                try:
                    import os
                    if os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
                        await conn.execute(text("PRAGMA journal_mode=MEMORY;"))
                    else:
                        await conn.execute(text("PRAGMA journal_mode=WAL;"))
                    await conn.execute(text("PRAGMA busy_timeout=30000;"))
                except Exception:
                    pass
            await conn.run_sync(Base.metadata.create_all)
            # Non-destructive schema migration check for chat_sessions.analyst_id
            try:
                await conn.execute(text("ALTER TABLE chat_sessions ADD COLUMN analyst_id VARCHAR(64) DEFAULT 'analyst-default-dev'"))
                logger.info("Added missing 'analyst_id' column to chat_sessions table.")
            except Exception:
                pass
        logger.info("Database tables initialized successfully.")
    except Exception as exc:
        logger.warning("Database table initialization warning (non-fatal): %s", exc)
