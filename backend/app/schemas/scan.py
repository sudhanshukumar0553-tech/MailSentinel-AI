"""
MailSentinel AI - Pydantic Schemas for Email Scanning
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_serializer
from backend.app.core.time import to_iso_utc


class ScanRequest(BaseModel):
    """Payload for submitting an email for multi-engine security scanning."""
    raw_content: str = Field(
        ...,
        description="Raw RFC822 email text or plain email message body.",
        min_length=1,
        max_length=1_000_000
    )
    subject: Optional[str] = Field(None, max_length=500)
    sender: Optional[str] = Field(None, max_length=255)
    recipient: Optional[str] = Field(None, max_length=255)


class DetectedUrlSchema(BaseModel):
    """Normalized forensic URL record."""
    defanged_url: str
    domain: Optional[str] = None
    tld: Optional[str] = None
    entropy: float = 0.0
    is_suspicious: bool = False
    risk_score: float = 0.0
    risk_reasons: List[str] = []
    verification_note: str = ""


class ScanResponse(BaseModel):
    """Complete forensic threat report returned by the scanning engine."""
    id: str
    created_at: datetime
    user_id: Optional[str] = "system-historical"
    subject: str
    sender: str
    recipient: str
    has_headers: bool
    risk_score: float
    threat_level: str
    verdict: str
    theme_color: str
    spam_probability: float
    phishing_probability: float
    header_risk_score: float
    url_risk_score: float
    detected_urls: List[DetectedUrlSchema]
    header_details: Dict[str, Any]
    recommendations: List[str]
    xai_report: Optional[Dict[str, Any]] = None

    @field_serializer("created_at", when_used="json")
    def serialize_created_at(self, dt: datetime) -> str:
        return to_iso_utc(dt) or dt.isoformat()


class HistoryScanItem(BaseModel):
    """Summarized scan record for detection history archive listing."""
    id: str
    created_at: datetime
    user_id: Optional[str] = "system-historical"
    subject: str
    sender: str
    threat_level: str
    risk_score: float
    verdict: str
    has_headers: bool
    detected_urls_count: int

    @field_serializer("created_at", when_used="json")
    def serialize_created_at(self, dt: datetime) -> str:
        return to_iso_utc(dt) or dt.isoformat()


class HistoryResponse(BaseModel):
    """Paginated collection of historical threat scans."""
    total_returned: int
    offset: int
    limit: int
    scans: List[HistoryScanItem]

