"""
MailSentinel AI - Pydantic Schemas for Security Audit Logging & Monitoring
"""

from typing import Optional, Dict, Any, List
from datetime import datetime
from pydantic import BaseModel, Field


class AuditEventCreate(BaseModel):
    """Payload to create an append-only audit event."""
    actor_id: str = "anonymous"
    actor_email: Optional[str] = None
    actor_role: str = "Anonymous"
    event_type: str
    event_category: str = "SYSTEM"
    severity: str = "INFO"
    outcome: str = "SUCCESS"
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    endpoint: Optional[str] = None
    http_method: Optional[str] = None
    http_status: Optional[int] = None
    request_correlation_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class AuditEventResponse(BaseModel):
    """Serialized audit log event record."""
    id: str
    timestamp: str
    actor_id: str
    actor_email: Optional[str] = None
    actor_role: str
    event_type: str
    event_category: str
    severity: str
    outcome: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    endpoint: Optional[str] = None
    http_method: Optional[str] = None
    http_status: Optional[int] = None
    request_correlation_id: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        from_attributes = True


class AuditLogsPaginationResponse(BaseModel):
    """Paginated response containing audit events."""
    items: List[AuditEventResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class AuditMetricsResponse(BaseModel):
    """Aggregated security metrics and monitoring KPIs."""
    total_events: int
    critical_alerts: int
    high_alerts: int
    auth_failures: int
    unauthorized_attempts: int
    threats_detected: int
    severity_breakdown: Dict[str, int]
    category_breakdown: Dict[str, int]
    recent_timeline: List[AuditEventResponse]
