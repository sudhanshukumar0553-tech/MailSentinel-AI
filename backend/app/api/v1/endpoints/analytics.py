"""
MailSentinel AI - Security Analytics & Dashboard Metrics Endpoint
"""

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import func, select, case
from backend.app.core.auth import AuthenticatedUser, get_current_user, ROLE_CUSTOMER
from backend.app.core.logging import logger
from backend.app.db.session import get_db
from backend.app.db.models.scan import ScanRecord, DetectedUrlRecord
from backend.app.core.time import to_iso_utc, now_utc

router = APIRouter(prefix="/analytics", tags=["Analytics & Dashboard"])


@router.get("/overview", status_code=status.HTTP_200_OK)
async def get_security_overview(
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Returns aggregated metrics and threat breakdown for the executive dashboard.
    Scoped strictly to the authenticated Customer's scans, or enterprise-wide for Analysts/Admins.
    Optimized with consolidated single-roundtrip aggregation for minimal latency.
    """
    base_filter = []
    if current_user.role == ROLE_CUSTOMER:
        base_filter.append(ScanRecord.user_id == current_user.id)

    try:
        # Consolidated metrics aggregation query (1 roundtrip instead of 8)
        stmt = (
            select(
                func.count(ScanRecord.id).label("total_scans"),
                func.count(case((ScanRecord.threat_level == "SAFE", 1))).label("safe_count"),
                func.count(case((ScanRecord.threat_level == "SUSPICIOUS", 1))).label("suspicious_count"),
                func.count(case((ScanRecord.threat_level == "DANGEROUS", 1))).label("dangerous_count"),
                func.count(case((ScanRecord.threat_level == "CRITICAL", 1))).label("critical_count"),
                func.avg(ScanRecord.risk_score).label("avg_score"),
                func.count(case((ScanRecord.phishing_probability >= 0.5, 1))).label("phishing_count"),
                func.count(case((ScanRecord.spam_probability >= 0.5, 1))).label("spam_count"),
            )
            .where(*base_filter)
        )
        res = await db.execute(stmt)
        row = res.one()

        total_scans = row.total_scans or 0
        safe_count = row.safe_count or 0
        suspicious_count = row.suspicious_count or 0
        dangerous_count = row.dangerous_count or 0
        critical_count = row.critical_count or 0
        avg_score = round(float(row.avg_score or 0.0), 1)
        phishing_count = row.phishing_count or 0
        spam_count = row.spam_count or 0

        # Malicious URLs count (scoped via join if Customer)
        if current_user.role == ROLE_CUSTOMER:
            url_stmt = (
                select(func.count(DetectedUrlRecord.id))
                .join(ScanRecord, DetectedUrlRecord.scan_id == ScanRecord.id)
                .where(DetectedUrlRecord.is_suspicious.is_(True), ScanRecord.user_id == current_user.id)
            )
        else:
            url_stmt = select(func.count(DetectedUrlRecord.id)).where(DetectedUrlRecord.is_suspicious.is_(True))

        suspicious_urls_res = await db.execute(url_stmt)
        suspicious_urls_count = suspicious_urls_res.scalar() or 0

        return {
            "total_scans": total_scans,
            "clean_emails": safe_count,
            "threats_blocked": dangerous_count + critical_count,
            "phishing_detected": phishing_count,
            "spam_detected": spam_count,
            "malicious_urls_intercepted": suspicious_urls_count,
            "average_risk_score": avg_score,
            "synced_at": to_iso_utc(now_utc()),
            "threat_distribution": [
                {"tier": "Safe", "count": safe_count, "color": "#10B981"},
                {"tier": "Suspicious", "count": suspicious_count, "color": "#F59E0B"},
                {"tier": "Dangerous", "count": dangerous_count, "color": "#F97316"},
                {"tier": "Critical", "count": critical_count, "color": "#EF4444"}
            ]
        }
    except Exception as exc:
        logger.error("Failed to aggregate security analytics: %s", exc)
        # Return valid empty telemetry rather than failing
        return {
            "total_scans": 0,
            "clean_emails": 0,
            "threats_blocked": 0,
            "phishing_detected": 0,
            "spam_detected": 0,
            "malicious_urls_intercepted": 0,
            "average_risk_score": 0.0,
            "synced_at": to_iso_utc(now_utc()),
            "threat_distribution": [
                {"tier": "Safe", "count": 0, "color": "#10B981"},
                {"tier": "Suspicious", "count": 0, "color": "#F59E0B"},
                {"tier": "Dangerous", "count": 0, "color": "#F97316"},
                {"tier": "Critical", "count": 0, "color": "#EF4444"}
            ]
        }

