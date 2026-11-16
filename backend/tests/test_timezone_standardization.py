"""
MailSentinel AI - Phase 3.8 Comprehensive Timezone & Timestamp Automated Tests
Tests:
1. UTC to IST conversion accuracy
2. Midnight date-boundary conversion
3. Month and year transitions
4. Daylight-saving-independent IST stability (+05:30 all year)
5. Existing SQLite records load as timezone-aware UTC
6. Detection History ordering by UTC creation timestamp
7. Forensic report timestamps and ISO 8601 'Z' suffix
8. Copilot chat message and session timestamps
9. Consistency across Scanner, History, and Detail APIs
"""

import pytest
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo
from httpx import AsyncClient, ASGITransport
from sqlalchemy import select, desc

from backend.app.main import app
from backend.app.core.time import (
    now_utc,
    now_ist,
    ensure_utc,
    to_iso_utc,
    to_ist,
    format_ist,
    UTCDateTime,
    TIMEZONE_NAME,
    TIMEZONE_ABBR
)
from backend.app.db.session import AsyncSessionLocal
from backend.app.db.models.scan import ScanRecord
from backend.app.db.models.chat import ChatSessionRecord, ChatMessageRecord


DEV_AUTH_HEADERS = {
    "Authorization": "Bearer mailsentinel-dev-secret-key-2026",
    "X-Analyst-ID": "analyst-default-dev"
}


def test_utc_to_ist_conversion():
    """Verifies that a UTC timestamp is converted exactly +05:30 to IST."""
    utc_dt = datetime(2026, 11, 16, 8, 59, 15, tzinfo=timezone.utc)
    ist_dt = to_ist(utc_dt)
    assert ist_dt is not None
    assert ist_dt.hour == 14  # 8 + 5 = 13, 59 + 30 = 89 -> 14:29:15
    assert ist_dt.minute == 29
    assert ist_dt.second == 15
    formatted = format_ist(utc_dt)
    assert formatted == "16 Nov 2026, 02:29:15 PM IST"


def test_midnight_date_boundary_conversion():
    """Verifies that late UTC times cleanly cross over the midnight date boundary into next day IST."""
    # 22:30 UTC on Nov 15 is 04:00 IST on Nov 16
    utc_late = datetime(2026, 11, 15, 22, 30, 0, tzinfo=timezone.utc)
    ist_late = to_ist(utc_late)
    assert ist_late.day == 16
    assert ist_late.month == 11
    assert ist_late.year == 2026
    assert ist_late.hour == 4
    assert ist_late.minute == 0
    formatted = format_ist(utc_late)
    assert formatted == "16 Nov 2026, 04:00:00 AM IST"


def test_month_and_year_transitions():
    """Verifies month and year rollover when converting UTC to IST."""
    # Month rollover: 31 Oct 20:00 UTC -> 01 Nov 01:30 IST
    oct_utc = datetime(2026, 10, 31, 20, 0, 0, tzinfo=timezone.utc)
    oct_ist = to_ist(oct_utc)
    assert oct_ist.day == 1
    assert oct_ist.month == 11
    assert oct_ist.year == 2026
    assert format_ist(oct_utc) == "01 Nov 2026, 01:30:00 AM IST"

    # Year rollover: 31 Dec 2026 20:00 UTC -> 01 Jan 2027 01:30 IST
    dec_utc = datetime(2026, 12, 31, 20, 0, 0, tzinfo=timezone.utc)
    dec_ist = to_ist(dec_utc)
    assert dec_ist.day == 1
    assert dec_ist.month == 1
    assert dec_ist.year == 2027
    assert format_ist(dec_utc) == "01 Jan 2027, 01:30:00 AM IST"


def test_daylight_saving_independent_ist_stability():
    """Verifies that IST is permanently UTC+05:30 across both summer and winter."""
    summer_utc = datetime(2026, 6, 21, 12, 0, 0, tzinfo=timezone.utc)
    winter_utc = datetime(2026, 12, 21, 12, 0, 0, tzinfo=timezone.utc)

    summer_ist = to_ist(summer_utc)
    winter_ist = to_ist(winter_utc)

    assert summer_ist.utcoffset() == timedelta(hours=5, minutes=30)
    assert winter_ist.utcoffset() == timedelta(hours=5, minutes=30)
    assert format_ist(summer_utc) == "21 Jun 2026, 05:30:00 PM IST"
    assert format_ist(winter_utc) == "21 Dec 2026, 05:30:00 PM IST"


def test_to_iso_utc_formatting():
    """Verifies that to_iso_utc produces standard ISO 8601 with trailing 'Z'."""
    dt = datetime(2026, 11, 16, 8, 59, 15, 123456, tzinfo=timezone.utc)
    iso = to_iso_utc(dt)
    assert iso == "2026-11-16T08:59:15.123456Z"
    assert iso.endswith("Z")

    # Naive datetime string from SQLite
    sqlite_str = "2026-11-16 08:59:15.661673"
    iso_sqlite = to_iso_utc(sqlite_str)
    assert iso_sqlite == "2026-11-16T08:59:15.661673Z"


@pytest.mark.asyncio
async def test_existing_sqlite_records_load_as_timezone_aware():
    """Verifies that existing records in the database load with tzinfo=timezone.utc."""
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(ScanRecord).limit(1))
        scan = result.scalar_one_or_none()
        if scan:
            assert scan.created_at is not None
            assert scan.created_at.tzinfo is not None
            assert scan.created_at.tzinfo == timezone.utc

        chat_res = await session.execute(select(ChatSessionRecord).limit(1))
        chat_sess = chat_res.scalar_one_or_none()
        if chat_sess:
            assert chat_sess.created_at is not None
            assert chat_sess.created_at.tzinfo == timezone.utc
            assert chat_sess.updated_at.tzinfo == timezone.utc


@pytest.mark.asyncio
async def test_detection_history_ordering_and_iso_format():
    """Verifies GET /api/v1/history returns records sorted by UTC creation timestamp descending with 'Z' suffix."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/v1/history?limit=10", headers=DEV_AUTH_HEADERS)
        assert res.status_code == 200
        data = res.json()
        scans = data["scans"]
        assert len(scans) > 0

        # Verify ISO 8601 format with Z
        for s in scans:
            assert "created_at" in s
            assert s["created_at"].endswith("Z")

        # Verify descending order
        parsed_dates = [datetime.fromisoformat(s["created_at"].replace("Z", "+00:00")) for s in scans]
        for i in range(len(parsed_dates) - 1):
            assert parsed_dates[i] >= parsed_dates[i + 1]


@pytest.mark.asyncio
async def test_scan_api_consistency_across_endpoints():
    """
    Verifies that a newly created scan returns consistent timestamps
    across POST /scan, GET /history, and GET /history/{id}.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Perform a scan
        payload = {
            "subject": "Timezone Verification Notice",
            "sender": "sec-audit@internal-test.local",
            "raw_content": "Please verify your account security timestamp at https://verify.internal-test.local"
        }
        scan_res = await client.post("/api/v1/scan", json=payload, headers=DEV_AUTH_HEADERS)
        assert scan_res.status_code == 200
        scan_data = scan_res.json()
        scan_id = scan_data["id"]
        created_at_scan = scan_data["created_at"]
        assert created_at_scan.endswith("Z")

        # 2. Query scan detail
        detail_res = await client.get(f"/api/v1/history/{scan_id}", headers=DEV_AUTH_HEADERS)
        assert detail_res.status_code == 200
        detail_data = detail_res.json()
        created_at_detail = detail_data["created_at"]
        assert created_at_detail == created_at_scan

        # 3. Query history list
        hist_res = await client.get("/api/v1/history?limit=5", headers=DEV_AUTH_HEADERS)
        assert hist_res.status_code == 200
        hist_data = hist_res.json()
        top_scan = hist_data["scans"][0]
        assert top_scan["id"] == scan_id
        assert top_scan["created_at"] == created_at_scan


@pytest.mark.asyncio
async def test_copilot_chat_timestamps_iso_z():
    """Verifies that Copilot chat message and session endpoints return ISO 8601 UTC timestamps with 'Z'."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        chat_payload = {
            "message": "Explain SPF authentication in email security.",
            "language": "en-US"
        }
        res = await client.post("/api/v1/chat/message", json=chat_payload, headers=DEV_AUTH_HEADERS)
        assert res.status_code == 200
        data = res.json()
        assert "created_at" in data
        assert data["created_at"].endswith("Z")

        session_id = data["session_id"]

        # Check session retrieval
        sess_res = await client.get(f"/api/v1/chat/sessions/{session_id}", headers=DEV_AUTH_HEADERS)
        assert sess_res.status_code == 200
        sess_data = sess_res.json()
        assert sess_data["created_at"].endswith("Z")
        assert sess_data["updated_at"].endswith("Z")
        for m in sess_data["messages"]:
            assert m["created_at"].endswith("Z")


@pytest.mark.asyncio
async def test_url_intel_timestamp_iso_z():
    """Verifies that URL Threat Intelligence returns analyzed_at ending in 'Z'."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post("/api/v1/url/analyze", json={"url": "https://example.com/login"}, headers=DEV_AUTH_HEADERS)
        assert res.status_code == 200
        data = res.json()
        assert "analyzed_at" in data
        assert data["analyzed_at"].endswith("Z")

