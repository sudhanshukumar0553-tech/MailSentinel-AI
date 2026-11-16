"""
Integration tests for FastAPI application root and health endpoints.
"""

import pytest
from httpx import ASGITransport, AsyncClient
from backend.app.main import app
from backend.app.core.config import settings


@pytest.mark.asyncio
async def test_root_endpoint():
    """Verify that root endpoint returns valid metadata."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == settings.PROJECT_NAME
        assert data["version"] == settings.VERSION
        assert data["status"] == "online"


@pytest.mark.asyncio
async def test_health_endpoint():
    """Verify that /api/v1/health returns database connectivity and provider status."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["database"] == "connected"
        assert "hf_configured" in data
        assert isinstance(data["hf_configured"], bool)
        assert data["hf_model"] == "openai/gpt-oss-20b"

