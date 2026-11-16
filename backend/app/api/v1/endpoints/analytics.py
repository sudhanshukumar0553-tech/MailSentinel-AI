"""
MailSentinel AI - Security Analytics & Dashboard Metrics Endpoint
"""

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import func, select
from backend.app.db.session import get_db
from backend.app.db.models.scan import ScanRecord, DetectedUrlRecord
from backend.app.core.time import to_iso_utc, now_utc

router = APIRouter(prefix="/analytics", tags=["Analytics & Dashboard"])


@router.get("/overview", status_code=status.HTTP_200_OK)
async def get_security_overview(db: AsyncSession = Depends(get_db)):
    """
    Returns aggregated metrics and threat breakdown for the executive dashboard.
    """
    # Total Scans
    total_scans_res = await db.execute(select(func.count(ScanRecord.id)))
    total_scans = total_scans_res.scalar() or 0

    # Severity Counts
    safe_res = await db.execute(select(func.count(ScanRecord.id)).where(ScanRecord.threat_level == "SAFE"))
    safe_count = safe_res.scalar() or 0

    suspicious_res = await db.execute(select(func.count(ScanRecord.id)).where(ScanRecord.threat_level == "SUSPICIOUS"))
    suspicious_count = suspicious_res.scalar() or 0

    dangerous_res = await db.execute(select(func.count(ScanRecord.id)).where(ScanRecord.threat_level == "DANGEROUS"))
    dangerous_count = dangerous_res.scalar() or 0

    critical_res = await db.execute(select(func.count(ScanRecord.id)).where(ScanRecord.threat_level == "CRITICAL"))
    critical_count = critical_res.scalar() or 0

    # Average Risk Score
    avg_score_res = await db.execute(select(func.avg(ScanRecord.risk_score)))
    avg_score = round(float(avg_score_res.scalar() or 0.0), 1)

    # Malicious URLs count
    suspicious_urls_res = await db.execute(select(func.count(DetectedUrlRecord.id)).where(DetectedUrlRecord.is_suspicious.is_(True)))
    suspicious_urls_count = suspicious_urls_res.scalar() or 0

    # Phishing vs Spam flags
    phish_res = await db.execute(select(func.count(ScanRecord.id)).where(ScanRecord.phishing_probability >= 0.5))
    phishing_count = phish_res.scalar() or 0

    spam_res = await db.execute(select(func.count(ScanRecord.id)).where(ScanRecord.spam_probability >= 0.5))
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

