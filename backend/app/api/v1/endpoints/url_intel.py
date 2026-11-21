"""
MailSentinel AI - URL Threat Intelligence Endpoints

Endpoints for multi-engine URL threat reputation, SSRF-safe redirect tracing, and lexical analysis:
- POST /api/v1/url/analyze (Inspect single URL)
- POST /api/v1/url/batch (Inspect multiple URLs concurrently)
- GET /api/v1/url/providers (Status of configured threat intelligence providers)
"""

from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.core.auth import AuthenticatedUser, get_current_user
from backend.app.schemas.url_intel import (
    UrlAnalyzeRequest,
    UrlBatchAnalyzeRequest,
    UrlExtractRequest,
    UrlThreatIntelResponse,
    CustomUrlInvestigationRequest,
    CustomUrlInvestigationResponse
)
from backend.app.services.url_threat_intel import (
    analyze_url_threat_intelligence,
    analyze_url_batch,
    extract_urls_from_content,
    investigate_custom_url
)

router = APIRouter(prefix="/url", tags=["AI URL Threat Intelligence"])


@router.post("/analyze", response_model=UrlThreatIntelResponse, status_code=status.HTTP_200_OK)
async def analyze_url(
    payload: UrlAnalyzeRequest,
    current_user: AuthenticatedUser = Depends(get_current_user)
):
    """
    Submits a URL for comprehensive threat intelligence analysis:
    - SSRF prevention & DNS validation
    - Multi-engine reputation checks (VirusTotal, Google Safe Browsing)
    - Local heuristic analysis (Shannon entropy, typosquatting, shorteners, punycode)
    - Safe redirect tracing
    """
    logger.info("Analyzing URL for threat intelligence: %s", payload.url[:60])
    try:
        result = await analyze_url_threat_intelligence(
            raw_url=payload.url,
            follow_redirects=payload.follow_redirects if payload.follow_redirects is not None else True
        )
        return result
    except Exception as exc:
        logger.error("Failed to analyze URL %s: %s", payload.url, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"URL threat intelligence analysis failed: {str(exc)}"
        )


@router.post("/batch", response_model=List[UrlThreatIntelResponse], status_code=status.HTTP_200_OK)
async def analyze_url_batch_endpoint(
    payload: UrlBatchAnalyzeRequest,
    current_user: AuthenticatedUser = Depends(get_current_user)
):
    """Analyzes a batch of up to 50 URLs concurrently."""
    logger.info("Batch analyzing %d URLs for threat intelligence...", len(payload.urls))
    try:
        results = await analyze_url_batch(payload.urls)
        return results
    except Exception as exc:
        logger.error("Batch URL analysis failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Batch URL threat intelligence analysis failed: {str(exc)}"
        )


@router.post("/extract", response_model=List[UrlThreatIntelResponse], status_code=status.HTTP_200_OK)
async def extract_and_analyze_urls_endpoint(
    payload: UrlExtractRequest,
    current_user: AuthenticatedUser = Depends(get_current_user)
):
    """
    Safely extracts all unique URLs from plain text or HTML email content,
    normalizes and defangs them, and runs batch multi-engine threat intelligence analysis.
    """
    if not payload.content or not payload.content.strip():
        return []
    logger.info("Extracting and analyzing URLs from email payload (%d chars)...", len(payload.content))
    try:
        extracted = extract_urls_from_content(payload.content)[:50]
        if not extracted:
            return []
        results = await analyze_url_batch(extracted)
        return results
    except Exception as exc:
        logger.error("URL extraction & threat analysis failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"URL extraction and threat intelligence failed: {str(exc)}"
        )


@router.post("/investigate", response_model=CustomUrlInvestigationResponse, status_code=status.HTTP_200_OK)
async def investigate_custom_url_endpoint(
    payload: CustomUrlInvestigationRequest,
    current_user: AuthenticatedUser = Depends(get_current_user)
):
    """
    Submits a user-provided URL or defanged IOC for deep AI threat investigation:
    - Input validation & defanged syntax detection
    - Zero-trust SSRF & DNS pre-flight verification
    - Hostname, subdomain, and TLD pattern analysis
    - Passive TLS certificate inspection
    - SSRF-hardened multi-hop HTTP redirect tracing
    - Empirical Threat Score (0-100) & Verdict classification
    - Structured checks audit matrix (succeeded/failed/unavailable)
    - AI-generated forensic reasoning based strictly on actual findings
    """
    from backend.app.core.security import defang_url
    safe_log_url = defang_url(payload.url)[:80]
    logger.info("Custom URL investigation requested (mode: %s): %s", payload.mode, safe_log_url)

    try:
        result = await investigate_custom_url(raw_url=payload.url, mode=payload.mode)
        return result
    except ValueError as val_err:
        logger.warning("Custom URL validation error: %s", val_err)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err)
        )
    except Exception as exc:
        logger.error("Custom URL investigation unexpected error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"URL threat investigation failed: {str(exc)}"
        )


@router.get("/providers", response_model=Dict[str, Any], status_code=status.HTTP_200_OK)
async def get_url_intel_providers():
    """Returns the operational status of configured threat intelligence providers."""
    return {
        "status": "ready",
        "providers": {
            "virustotal": {
                "configured": settings.is_virustotal_configured,
                "status": "active" if settings.is_virustotal_configured else "unconfigured",
                "attribution": "VirusTotal API v3"
            },
            "google_safebrowsing": {
                "configured": settings.is_safe_browsing_configured,
                "status": "active" if settings.is_safe_browsing_configured else "unconfigured",
                "attribution": "Google Safe Browsing v4"
            },
            "local_heuristics": {
                "configured": True,
                "status": "active",
                "attribution": "MailSentinel Shannon Entropy & Typosquatting Engine"
            },
            "ssrf_protection": {
                "configured": True,
                "status": "enforced",
                "attribution": "RFC1918 & Cloud Metadata Filter"
            }
        }
    }

