"""
Unit tests for database session management, ORM models, and CRUD operations.
"""

import pytest
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from backend.app.db.session import AsyncSessionLocal, init_db
from backend.app.db.models.scan import ScanRecord, DetectedUrlRecord
from backend.app.db.models.investigation import AgentInvestigationRecord


@pytest.mark.asyncio
async def test_database_table_creation_and_insertion():
    """Verify that tables are created and records can be inserted and queried."""
    await init_db()

    scan_id = None
    async with AsyncSessionLocal() as session:
        # 1. Create a sample scan record
        test_scan = ScanRecord(
            subject="Urgent: Verify Your Banking Account Immediately",
            sender="security@paypa1-alert.com",
            recipient="user@company.com",
            has_headers=True,
            body_preview="Please click the link below to verify your account.",
            risk_score=88.5,
            threat_level="CRITICAL",
            verdict="Phishing Attempt Detected",
            spam_probability=0.75,
            phishing_probability=0.92,
            header_risk_score=0.85,
            url_risk_score=0.90,
            indicators={"urgency": True, "spf_fail": True}
        )
        session.add(test_scan)
        await session.commit()
        await session.refresh(test_scan)
        scan_id = test_scan.id

        # 2. Add a detected URL linked to this scan
        test_url = DetectedUrlRecord(
            scan_id=scan_id,
            defanged_url="hxxps://paypa1-alert[.]com/login",
            domain="paypa1-alert.com",
            tld="com",
            entropy=3.85,
            is_suspicious=True,
            risk_reasons={"typosquatting": True}
        )
        session.add(test_url)

        # 3. Add an agent investigation record
        test_investigation = AgentInvestigationRecord(
            scan_id=scan_id,
            model_used="openai/gpt-oss-20b",
            steps_count=4,
            final_assessment="High confidence phishing campaign targeting PayPal credentials."
        )
        session.add(test_investigation)
        await session.commit()

    # 4. Open a clean session to verify persistent retrieval and relationships
    async with AsyncSessionLocal() as read_session:
        result = await read_session.execute(
            select(ScanRecord)
            .options(
                selectinload(ScanRecord.detected_urls),
                selectinload(ScanRecord.investigations)
            )
            .where(ScanRecord.id == scan_id)
        )
        retrieved_scan = result.scalar_one_or_none()
        assert retrieved_scan is not None
        assert retrieved_scan.threat_level == "CRITICAL"
        assert len(retrieved_scan.detected_urls) == 1
        assert retrieved_scan.detected_urls[0].domain == "paypa1-alert.com"
        assert len(retrieved_scan.investigations) == 1
        assert retrieved_scan.investigations[0].steps_count == 4
