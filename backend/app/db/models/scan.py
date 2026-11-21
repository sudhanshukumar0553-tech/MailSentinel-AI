"""
MailSentinel AI - Database ORM Models for Scanned Emails & URLs
"""

import uuid
from datetime import datetime
from typing import List, Optional
from sqlalchemy import (
    Boolean,
    Column,
    Float,
    ForeignKey,
    String,
    Text,
    JSON
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.db.base import Base
from backend.app.core.time import UTCDateTime, now_utc


class ScanRecord(Base):
    """
    Stores the forensic analysis record for an individual email scan.
    """
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime,
        default=now_utc,
        index=True
    )
    user_id: Mapped[str] = mapped_column(
        String(64),
        index=True,
        default="system-historical"
    )

    # Email Metadata
    subject: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    sender: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    recipient: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    has_headers: Mapped[bool] = mapped_column(Boolean, default=False)
    body_preview: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Core Threat Scoring & Classification
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)  # 0.0 to 100.0
    threat_level: Mapped[str] = mapped_column(String(50), default="SAFE", index=True)
    verdict: Mapped[str] = mapped_column(String(200), default="Clean Email")
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Individual Engine Scores
    spam_probability: Mapped[float] = mapped_column(Float, default=0.0)
    phishing_probability: Mapped[float] = mapped_column(Float, default=0.0)
    header_risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    url_risk_score: Mapped[float] = mapped_column(Float, default=0.0)

    # Structured Forensic Indicators & XAI Explanations
    indicators: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    xai_report: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # Relationships
    detected_urls: Mapped[List["DetectedUrlRecord"]] = relationship(
        "DetectedUrlRecord",
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="selectin"
    )
    investigations: Mapped[List["AgentInvestigationRecord"]] = relationship(
        "AgentInvestigationRecord",
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="selectin"
    )


class DetectedUrlRecord(Base):
    """
    Stores extracted and defanged URLs associated with a specific email scan.
    """
    __tablename__ = "detected_urls"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )
    scan_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("scans.id", ondelete="CASCADE"),
        index=True
    )
    defanged_url: Mapped[str] = mapped_column(Text, nullable=False)
    domain: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    tld: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    entropy: Mapped[float] = mapped_column(Float, default=0.0)
    is_suspicious: Mapped[bool] = mapped_column(Boolean, default=False)
    risk_reasons: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    scan: Mapped["ScanRecord"] = relationship("ScanRecord", back_populates="detected_urls")

