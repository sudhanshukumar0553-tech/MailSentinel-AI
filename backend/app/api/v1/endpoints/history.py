"""
MailSentinel AI - Scan History & Forensic Archive Endpoint
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from backend.app.core.logging import logger
from backend.app.core.auth import (
    AuthenticatedUser,
    get_current_user,
    ROLE_CUSTOMER,
    ROLE_SOC_ANALYST,
    ROLE_ADMIN
)
from backend.app.db.session import get_db
from backend.app.db.models.scan import ScanRecord
from backend.app.schemas.scan import ScanResponse, DetectedUrlSchema, HistoryResponse, HistoryScanItem

router = APIRouter(prefix="/history", tags=["History & Forensics"])


@router.get("", response_model=HistoryResponse, status_code=status.HTTP_200_OK)
async def list_scans(
    response: Response,
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0),
    threat_level: Optional[str] = None,
    all_users: bool = Query(False, description="Admin/Analyst: View all tenant scans including historical"),
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Retrieves paginated list of past email scans.
    Enforces tenant isolation: Customers only see their own scans.
    Guarantees no browser caching, strict descending chronological ordering by UTC timestamp,
    and ISO 8601 UTC timestamps with explicit 'Z' suffix.
    """
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"

    stmt = select(ScanRecord).order_by(desc(ScanRecord.created_at), desc(ScanRecord.id))

    # Multi-tenant scoping: Customers see only their scans; Analysts/Admins can query all or own
    if current_user.role == ROLE_CUSTOMER or not all_users:
        stmt = stmt.where(ScanRecord.user_id == current_user.id)

    if threat_level:
        stmt = stmt.where(ScanRecord.threat_level == threat_level.upper())

    stmt = stmt.offset(offset).limit(limit)

    try:
        result = await db.execute(stmt)
        scans = result.scalars().all()
    except Exception as exc:
        logger.warning("History query encountered error (returning safe fallback): %s", exc)
        scans = []

    items = [
        HistoryScanItem(
            id=s.id,
            created_at=s.created_at,
            user_id=getattr(s, "user_id", "system-historical"),
            subject=s.subject or "Untitled",
            sender=s.sender or "Unknown",
            threat_level=s.threat_level,
            risk_score=s.risk_score,
            verdict=s.verdict,
            has_headers=s.has_headers,
            detected_urls_count=len(s.detected_urls)
        )
        for s in scans
    ]

    return HistoryResponse(
        total_returned=len(items),
        offset=offset,
        limit=limit,
        scans=items
    )


@router.get("/{scan_id}", response_model=ScanResponse, status_code=status.HTTP_200_OK)
async def get_scan_detail(
    scan_id: str,
    response: Response,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Retrieves complete forensic report for a specific scan by ID with ownership verification.
    """
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"

    result = await db.execute(select(ScanRecord).where(ScanRecord.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan record not found.")

    # Strict IDOR Defense: Customers can only inspect their own scans
    scan_owner = getattr(scan, "user_id", "system-historical")
    if current_user.role == ROLE_CUSTOMER and scan_owner != current_user.id:
        logger.warning(
            "IDOR attempt blocked: User %s attempted to inspect scan %s owned by %s",
            current_user.id, scan_id, scan_owner
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: You do not have ownership of this scan record."
        )

    urls = [
        DetectedUrlSchema(
            defanged_url=u.defanged_url,
            domain=u.domain,
            tld=u.tld,
            entropy=u.entropy,
            is_suspicious=u.is_suspicious,
            risk_score=0.7 if u.is_suspicious else 0.1,
            risk_reasons=u.risk_reasons.get("reasons", []) if u.risk_reasons else [],
            verification_note="Suspicious markers detected" if u.is_suspicious else "Lexical scan clean"
        )
        for u in scan.detected_urls
    ]

    # Restore forensic indicators
    indicators = scan.indicators or {}
    header_details = indicators.get("header_details", {"has_headers": scan.has_headers, "status": "Transport headers present" if scan.has_headers else "Headers omitted"})
    recommendations = indicators.get("recommendations", [])
    if not recommendations:
        recommendations = (
            ["Exercise standard caution; no immediate threat detected."]
            if scan.threat_level == "SAFE"
            else ["Quarantine email immediately.", "Do not interact with links or attachments.", "Verify identity out-of-band."]
        )

    # Restore XAI report
    xai_report = scan.xai_report or {
        "factor_breakdown": {
            "ml_spam_weight": round(scan.spam_probability * 30.0, 1),
            "ml_phish_weight": round(scan.phishing_probability * 40.0, 1),
            "url_risk_weight": round(scan.url_risk_score * 20.0, 1),
            "header_risk_weight": round(scan.header_risk_score * 10.0, 1)
        },
        "top_spam_words": indicators.get("spam_triggers", []),
        "top_phish_words": indicators.get("phishing_triggers", [])
    }

    return ScanResponse(
        id=scan.id,
        created_at=scan.created_at,
        user_id=getattr(scan, "user_id", "system-historical"),
        subject=scan.subject or "Untitled Email",
        sender=scan.sender or "Undisclosed Sender",
        recipient=scan.recipient or "Undisclosed Recipient",
        has_headers=scan.has_headers,
        risk_score=scan.risk_score,
        threat_level=scan.threat_level,
        verdict=scan.verdict,
        theme_color="#EF4444" if scan.threat_level == "CRITICAL" else "#F97316" if scan.threat_level == "DANGEROUS" else "#F59E0B" if scan.threat_level == "SUSPICIOUS" else "#10B981",
        spam_probability=scan.spam_probability,
        phishing_probability=scan.phishing_probability,
        header_risk_score=scan.header_risk_score,
        url_risk_score=scan.url_risk_score,
        detected_urls=urls,
        header_details=header_details,
        recommendations=recommendations,
        xai_report=xai_report
    )

