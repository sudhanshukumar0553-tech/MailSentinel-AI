"""
MailSentinel AI - Asynchronous Database Session Management

Manages asynchronous connections and sessions using SQLAlchemy 2.0.
Works seamlessly with SQLite (aiosqlite) for local development
and PostgreSQL (psycopg) for production deployments.
"""

import socket
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
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

# Fallback to IPv4 for networks where router advertises IPv6 without outbound routing
orig_getaddrinfo = socket.getaddrinfo
def getaddrinfo_ipv4(host, port, family=0, type=0, proto=0, flags=0):
    if family == 0 or family == socket.AF_UNSPEC:
        family = socket.AF_INET
    return orig_getaddrinfo(host, port, family, type, proto, flags)

socket.getaddrinfo = getaddrinfo_ipv4


def resolve_db_url(url: str) -> str:
    """Normalizes database URLs to async dialects (asyncpg for PostgreSQL)."""
    cleaned = (url or "").strip()
    if not cleaned:
        return cleaned
    if cleaned.startswith("postgres://"):
        cleaned = "postgresql+asyncpg://" + cleaned[len("postgres://"):]
    elif cleaned.startswith("postgresql://") and not cleaned.startswith("postgresql+asyncpg://"):
        cleaned = "postgresql+asyncpg://" + cleaned[len("postgresql://"):]

    if "postgresql+asyncpg://" in cleaned and "?" in cleaned:
        parsed = urlparse(cleaned)
        qs = parse_qs(parsed.query)
        qs.pop("channel_binding", None)
        if "sslmode" in qs:
            qs.pop("sslmode", None)
            qs["ssl"] = ["require"]
        cleaned = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            urlencode(qs, doseq=True),
            parsed.fragment
        ))
    return cleaned


DB_URL = resolve_db_url(settings.DATABASE_URL)

# Configure engine connection arguments based on database dialect
connect_args = {}
engine_kwargs = {
    "echo": False,
    "future": True,
    "poolclass": NullPool  # Serverless safe for both SQLite and PgBouncer transaction pooling
}

if "sqlite" in DB_URL:
    # SQLite requires check_same_thread=False and increased timeout for asynchronous concurrency
    connect_args["check_same_thread"] = False
    connect_args["timeout"] = 30.0
else:
    # PostgreSQL with Neon / PgBouncer serverless transaction pooler
    # Disabling statement_cache_size is required for PgBouncer transaction mode
    connect_args["statement_cache_size"] = 0

engine_kwargs["connect_args"] = connect_args

# Create the primary async engine
engine: AsyncEngine = create_async_engine(
    DB_URL,
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


_DB_INITIALIZED = False


async def init_db() -> None:
    """
    Initializes database tables defined in the ORM models.
    Called on application startup.
    """
    global _DB_INITIALIZED
    if _DB_INITIALIZED:
        return
    try:
        # Import all models to ensure they are registered with Base.metadata
        import backend.app.db.models  # noqa: F401

        logger.info("Initializing database tables...")
        async with engine.begin() as conn:
            if "sqlite" in DB_URL:
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
            if "sqlite" in DB_URL:
                try:
                    await conn.execute(text("ALTER TABLE chat_sessions ADD COLUMN analyst_id VARCHAR(64) DEFAULT 'analyst-default-dev'"))
                    logger.info("Added missing 'analyst_id' column to chat_sessions table.")
                except Exception:
                    pass
        _DB_INITIALIZED = True
        logger.info("Database tables initialized successfully.")
    except Exception as exc:
        logger.warning("Database table initialization warning (non-fatal): %s", exc)
