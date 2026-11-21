"""
MailSentinel AI - Security Analytics & Dashboard Metrics Endpoint
"""

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import func, select
from backend.app.core.auth import AuthenticatedUser, get_current_user, ROLE_CUSTOMER
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
    """
    base_filter = []
    if current_user.role == ROLE_CUSTOMER:
        base_filter.append(ScanRecord.user_id == current_user.id)

    # Total Scans
    total_scans_res = await db.execute(select(func.count(ScanRecord.id)).where(*base_filter))
    total_scans = total_scans_res.scalar() or 0

    # Severity Counts
    safe_res = await db.execute(select(func.count(ScanRecord.id)).where(ScanRecord.threat_level == "SAFE", *base_filter))
    safe_count = safe_res.scalar() or 0

    suspicious_res = await db.execute(select(func.count(ScanRecord.id)).where(ScanRecord.threat_level == "SUSPICIOUS", *base_filter))
    suspicious_count = suspicious_res.scalar() or 0

    dangerous_res = await db.execute(select(func.count(ScanRecord.id)).where(ScanRecord.threat_level == "DANGEROUS", *base_filter))
    dangerous_count = dangerous_res.scalar() or 0

    critical_res = await db.execute(select(func.count(ScanRecord.id)).where(ScanRecord.threat_level == "CRITICAL", *base_filter))
    critical_count = critical_res.scalar() or 0

    # Average Risk Score
    avg_score_res = await db.execute(select(func.avg(ScanRecord.risk_score)).where(*base_filter))
    avg_score = round(float(avg_score_res.scalar() or 0.0), 1)

    # Malicious URLs count (scoped via join if Customer)
    if current_user.role == ROLE_CUSTOMER:
        suspicious_urls_res = await db.execute(
            select(func.count(DetectedUrlRecord.id))
            .join(ScanRecord, DetectedUrlRecord.scan_id == ScanRecord.id)
            .where(DetectedUrlRecord.is_suspicious.is_(True), ScanRecord.user_id == current_user.id)
        )
    else:
        suspicious_urls_res = await db.execute(select(func.count(DetectedUrlRecord.id)).where(DetectedUrlRecord.is_suspicious.is_(True)))
    suspicious_urls_count = suspicious_urls_res.scalar() or 0

    # Phishing vs Spam flags
    phish_res = await db.execute(select(func.count(ScanRecord.id)).where(ScanRecord.phishing_probability >= 0.5, *base_filter))
    phishing_count = phish_res.scalar() or 0

    spam_res = await db.execute(select(func.count(ScanRecord.id)).where(ScanRecord.spam_probability >= 0.5, *base_filter))
    spam_count = spam_res.scalar() or 0

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

