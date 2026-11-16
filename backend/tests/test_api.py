"""
End-to-End API Integration Tests for MailSentinel AI endpoints.
"""

import pytest
from httpx import ASGITransport, AsyncClient
from backend.app.main import app


@pytest.mark.asyncio
async def test_scan_email_api_endpoint():
    """Verify that /api/v1/scan analyzes text, calculates scores, and saves to DB."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        payload = {
            "raw_content": "URGENT: Verify your account immediately at http://paypa1-security.xyz/login or your account will be suspended.",
            "subject": "Urgent Security Verification",
            "sender": "alert@paypa1-security.xyz"
        }
        response = await client.post("/api/v1/scan", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert "id" in data
        assert data["threat_level"] in ["SUSPICIOUS", "DANGEROUS", "CRITICAL"]
        assert len(data["detected_urls"]) >= 1
        assert "hxxp" in data["detected_urls"][0]["defanged_url"]
        assert data["has_headers"] is False  # Pasted text has no transport headers


@pytest.mark.asyncio
async def test_analytics_and_models_endpoints():
    """Verify analytics overview and model benchmark retrieval."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Analytics
        analytics_res = await client.get("/api/v1/analytics/overview")
        assert analytics_res.status_code == 200
        analytics_data = analytics_res.json()
        assert "total_scans" in analytics_data
        assert "threat_distribution" in analytics_data

        # Models
        models_res = await client.get("/api/v1/models/benchmarks")
        assert models_res.status_code == 200
        models_data = models_res.json()
        assert "models" in models_data


@pytest.mark.asyncio
async def test_agent_investigate_api_endpoint():
    """Verify autonomous AI agent investigation endpoint."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        payload = {
            "email_content": "Wire $5000 to this offshore account immediately to claim your lottery winnings.",
            "raw_headers": "none"
        }
        response = await client.post("/api/v1/agent/investigate", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "completed"
        assert "final_report" in data
        assert "MailSentinel AI" in data["final_report"]

