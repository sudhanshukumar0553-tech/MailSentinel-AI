"""
MailSentinel AI - Database ORM Model for Enterprise Security Audit Logging
"""

import uuid
from datetime import datetime
from typing import Optional, Dict, Any
from sqlalchemy import (
    String,
    Text,
    Integer,
    JSON,
    Index,
    desc
)
from sqlalchemy.orm import Mapped, mapped_column
from backend.app.db.base import Base
from backend.app.core.time import UTCDateTime, now_utc


class AuditEventRecord(Base):
    """
    Immutable, append-only record of security, authentication, authorization,
    and administrative events across the MailSentinel AI platform.
    """
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )
    timestamp: Mapped[datetime] = mapped_column(
        UTCDateTime,
        default=now_utc,
        index=True
    )

    # Actor identity
    actor_id: Mapped[str] = mapped_column(String(100), default="anonymous", index=True)
    actor_email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    actor_role: Mapped[str] = mapped_column(String(50), default="Anonymous", index=True)

    # Event classification
    event_type: Mapped[str] = mapped_column(String(100), index=True)
    event_category: Mapped[str] = mapped_column(String(50), default="SYSTEM", index=True)
    severity: Mapped[str] = mapped_column(String(20), default="INFO", index=True)
    outcome: Mapped[str] = mapped_column(String(20), default="SUCCESS", index=True)

    # Request telemetry
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    endpoint: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    http_method: Mapped[Optional[str]] = mapped_column(String(10), nullable=True)
    http_status: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    request_correlation_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)

    # Sanitized structured payload
    details: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)

    __table_args__ = (
        Index("ix_audit_logs_timestamp_desc", desc("timestamp")),
        Index("ix_audit_logs_category_severity", "event_category", "severity"),
        Index("ix_audit_logs_actor_timestamp", "actor_id", desc("timestamp")),
    )

    def to_dict(self) -> Dict[str, Any]:
        """Converts ORM record to dictionary."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "actor_id": self.actor_id,
            "actor_email": self.actor_email,
            "actor_role": self.actor_role,
            "event_type": self.event_type,
            "event_category": self.event_category,
            "severity": self.severity,
            "outcome": self.outcome,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "endpoint": self.endpoint,
            "http_method": self.http_method,
            "http_status": self.http_status,
            "request_correlation_id": self.request_correlation_id,
            "details": self.details or {}
        }
