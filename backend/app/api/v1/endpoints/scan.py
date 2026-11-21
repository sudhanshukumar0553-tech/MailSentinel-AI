"""
MailSentinel AI - Live Email Scanning Endpoint

Executes the complete multi-tier detection pipeline:
1. Email MIME/Text Parsing
2. Dual Machine Learning Classification (Spam & Phishing)
3. Lexical URL Analysis & Defanging
4. Transport Header Verification (SPF/DKIM/DMARC)
5. Unified Risk Scoring & Database Persistence
"""

from backend.app.core.auth import AuthenticatedUser, get_current_user
from backend.app.core.time import now_utc
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.core.logging import logger
from backend.app.db.session import get_db
from backend.app.db.models.scan import ScanRecord, DetectedUrlRecord
from backend.app.services.email_parser import parse_email_input
from backend.app.services.header_analyzer import analyze_email_headers
from backend.app.services.url_analyzer import analyze_email_urls
from backend.app.services.risk_engine import calculate_unified_risk
from backend.app.ml.models import SpamClassifier, PhishingClassifier
from backend.app.schemas.scan import ScanRequest, ScanResponse, DetectedUrlSchema

router = APIRouter(prefix="/scan", tags=["Scanning & Detection"])


@router.post("", response_model=ScanResponse, status_code=status.HTTP_200_OK)
async def scan_email(
    payload: ScanRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Submits an email for instant multi-engine threat analysis.
    Stores the forensic record in the database and associates it with the authenticated Clerk user.
    """
    # 1. Parse Email Content & Transport Headers
    parsed = parse_email_input(payload.raw_content)
    subject = payload.subject or parsed["subject"]
    sender = payload.sender or parsed["sender"]
    recipient = payload.recipient or parsed["recipient"]
    body = parsed["body"]
    has_headers = parsed["has_headers"]

    # 2. Run Dual Machine Learning Models
    spam_res = SpamClassifier.predict(body)
    phish_res = PhishingClassifier.predict(body)

    # 3. Analyze URLs (Zero Execution & Defanged)
    url_res = analyze_email_urls(body)

    # 4. Analyze Transport Headers (Strict Authenticity)
    header_res = analyze_email_headers(parsed["raw_headers"], has_headers)

    # 5. Compute Synthesized Unified Risk Score
    risk_summary = calculate_unified_risk(
        spam_prob=spam_res["probability"],
        phish_prob=phish_res["probability"],
        url_risk=url_res["aggregate_risk"],
        header_risk=header_res["risk_score"],
        has_headers=has_headers
    )

    # 6. Assemble Forensic Indicators & Structured XAI Telemetry
    indicators = {
        "spam_triggers": spam_res["triggers"],
        "phishing_triggers": phish_res["triggers"],
        "suspicious_urls_count": url_res["suspicious_count"],
        "header_findings": header_res["findings"],
        "is_spoofed": header_res.get("is_spoofed", False),
        "recommendations": risk_summary["recommendations"],
        "header_details": header_res
    }
    xai_dict = {
        "factor_breakdown": risk_summary["factor_breakdown"],
        "top_spam_words": spam_res["triggers"],
        "top_phish_words": phish_res["triggers"]
    }

    # 7. Persist Scan Record to Database (Zero-Loss Reliability)
    detected_url_schemas: list[DetectedUrlSchema] = []
    try:
        scan_entity = ScanRecord(
            created_at=now_utc(),
            user_id=current_user.id,
            subject=subject or "Untitled Email",
            sender=sender or "Undisclosed Sender",
            recipient=recipient or "Undisclosed Recipient",
            has_headers=has_headers,
            body_preview=body[:400] if body else "",
            risk_score=risk_summary["risk_score"],
            threat_level=risk_summary["threat_level"],
            verdict=risk_summary["verdict"],
            summary=f"Analysis: {risk_summary['verdict']} with {risk_summary['risk_score']}% threat score.",
            spam_probability=spam_res["probability"],
            phishing_probability=phish_res["probability"],
            header_risk_score=header_res["risk_score"],
            url_risk_score=url_res["aggregate_risk"],
            indicators=indicators,
            xai_report=xai_dict
        )
        db.add(scan_entity)
        await db.flush()  # Generates scan_entity.id

        # Persist Extracted URLs
        for u in url_res["urls"]:
            url_entity = DetectedUrlRecord(
                scan_id=scan_entity.id,
                defanged_url=u["raw_url_defanged"],
                domain=u["domain"],
                tld=u["tld"],
                entropy=u["entropy"],
                is_suspicious=u["is_suspicious"],
                risk_reasons={"reasons": u["risk_reasons"]}
            )
            db.add(url_entity)

            detected_url_schemas.append(DetectedUrlSchema(
                defanged_url=u["raw_url_defanged"],
                domain=u["domain"],
                tld=u["tld"],
                entropy=u["entropy"],
                is_suspicious=u["is_suspicious"],
                risk_score=u["risk_score"],
                risk_reasons=u["risk_reasons"],
                verification_note=u["verification_note"]
            ))

        await db.commit()
        await db.refresh(scan_entity)
    except Exception as db_err:
        logger.error("Database persistence failed for scan: %s", db_err, exc_info=True)
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database persistence failure: Unable to commit scan audit record ({str(db_err)})"
        )

    logger.info(
        "Completed scan %s: Score=%.1f | Threat=%s | Verdict=%s",
        scan_entity.id, scan_entity.risk_score, scan_entity.threat_level, scan_entity.verdict
    )

    return ScanResponse(
        id=scan_entity.id,
        created_at=scan_entity.created_at,
        user_id=scan_entity.user_id,
        subject=scan_entity.subject or "Untitled",
        sender=scan_entity.sender or "Unknown",
        recipient=scan_entity.recipient or "Unknown",
        has_headers=scan_entity.has_headers,
        risk_score=scan_entity.risk_score,
        threat_level=scan_entity.threat_level,
        verdict=scan_entity.verdict,
        theme_color=risk_summary["theme_color"],
        spam_probability=scan_entity.spam_probability,
        phishing_probability=scan_entity.phishing_probability,
        header_risk_score=scan_entity.header_risk_score,
        url_risk_score=scan_entity.url_risk_score,
        detected_urls=detected_url_schemas,
        header_details=header_res,
        recommendations=risk_summary["recommendations"],
        xai_report={
            "factor_breakdown": risk_summary["factor_breakdown"],
            "top_spam_words": spam_res["triggers"],
            "top_phish_words": phish_res["triggers"]
        }
    )

