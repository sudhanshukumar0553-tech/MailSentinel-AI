"""
MailSentinel AI - Database ORM Model for smolagents Investigations
"""

import uuid
from datetime import datetime
from typing import Optional
from sqlalchemy import (
    ForeignKey,
    Integer,
    String,
    Text,
    JSON
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.db.base import Base
from backend.app.core.time import UTCDateTime, now_utc


class AgentInvestigationRecord(Base):
    """
    Stores forensic session history from the smolagents ToolCallingAgent,
    including thoughts, tool calls, and final analyst verdicts.
    """
    __tablename__ = "agent_investigations"

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
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime,
        default=now_utc,
        index=True
    )

    model_used: Mapped[str] = mapped_column(String(100), default="openai/gpt-oss-20b")
    steps_count: Mapped[int] = mapped_column(Integer, default=0)
    tools_invoked: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    thought_process: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    final_assessment: Mapped[str] = mapped_column(Text, nullable=False)

    scan: Mapped["ScanRecord"] = relationship("backend.app.db.models.scan.ScanRecord", back_populates="investigations")

