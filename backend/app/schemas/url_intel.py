"""
MailSentinel AI - URL Threat Intelligence Pydantic Schemas
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class UrlAnalyzeRequest(BaseModel):
    """Payload for submitting a URL for multi-engine threat intelligence analysis."""
    url: str = Field(..., description="Target URL to inspect", min_length=3, max_length=4096)
    follow_redirects: Optional[bool] = Field(True, description="Whether to safely follow public HTTP redirects")


class UrlBatchAnalyzeRequest(BaseModel):
    """Payload for analyzing multiple URLs concurrently."""
    urls: List[str] = Field(..., min_length=1, max_length=50, description="List of URLs to inspect")


class UrlExtractRequest(BaseModel):
    """Payload for extracting and inspecting all URLs from email content."""
    content: str = Field("", description="Email text or HTML payload containing URLs to extract and inspect", min_length=0)
    follow_redirects: Optional[bool] = Field(True, description="Whether to follow public HTTP redirects")


class UrlProviderResult(BaseModel):
    """Reputation telemetry from a specific external threat intelligence provider."""
    provider: str
    status: str  # "checked", "unconfigured", "error", "rate_limited", "clean", "flagged"
    is_malicious: bool = False
    detections_count: int = 0
    total_engines: int = 0
    threat_tags: List[str] = []
    message: Optional[str] = None


class UrlHeuristicDetails(BaseModel):
    """Comprehensive local heuristic & lexical risk analysis."""
    entropy: float
    is_ip_address: bool
    has_suspicious_tld: bool
    is_shortener: bool
    is_typosquatting: bool
    impersonated_brand: Optional[str] = None
    has_punycode: bool
    suspicious_keywords: List[str] = []
    risk_reasons: List[str] = []
    heuristic_score: float


class UrlRedirectHop(BaseModel):
    """Single hop in a safe HTTP redirect chain."""
    hop: int
    url: str
    status_code: int
    resolved_ip: Optional[str] = None


class UrlThreatIntelResponse(BaseModel):
    """Definitive URL Threat Intelligence Report."""
    original_url: str
    normalized_url: str
    defanged_url: str
    domain: str
    tld: str
    verdict: str  # "SAFE", "SUSPICIOUS", "MALICIOUS", "UNKNOWN"
    confidence: float
    threat_reasons: List[str] = []
    reputation: Dict[str, UrlProviderResult] = {}
    heuristics: UrlHeuristicDetails
    redirect_chain: List[UrlRedirectHop] = []
    final_destination: Optional[str] = None
    ssrf_blocked: bool = False
    cached: bool = False
    analyzed_at: str


class CheckStatusItem(BaseModel):
    """Status of an individual security check in the custom URL scanner."""
    status: str  # "succeeded", "failed", "unavailable"
    message: str
    details: Optional[Dict[str, Any]] = None


class TlsCertificateDetails(BaseModel):
    """TLS/SSL certificate telemetry gathered during passive handshake."""
    has_tls: bool = False
    issuer: Optional[str] = None
    subject: Optional[str] = None
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None
    is_expired: Optional[bool] = None
    cipher: Optional[str] = None
    version: Optional[str] = None
    error: Optional[str] = None


class CustomUrlInvestigationRequest(BaseModel):
    """Payload for custom user URL / IOC threat investigation."""
    url: str = Field(..., description="Target URL or defanged IOC to investigate", min_length=1, max_length=4096)
    mode: str = Field("deep", description="Investigation mode: 'quick' or 'deep'")


class CustomUrlInvestigationResponse(BaseModel):
    """Comprehensive forensic report for custom user-submitted URL."""
    original_url: str
    normalized_url: str
    defanged_url: str
    is_defanged: bool
    domain: str
    subdomain: Optional[str] = None
    tld: str
    path: str
    query: str
    threat_score: int  # 0-100
    verdict: str  # "MALICIOUS", "SUSPICIOUS", "CLEAN", "UNKNOWN"
    mode: str  # "quick" or "deep"
    heuristics: UrlHeuristicDetails
    checks: Dict[str, CheckStatusItem]
    tls_details: Optional[TlsCertificateDetails] = None
    redirect_chain: List[UrlRedirectHop] = []
    final_destination: Optional[str] = None
    ai_explanation: str
    ai_model_used: Optional[str] = None
    analyzed_at: str


