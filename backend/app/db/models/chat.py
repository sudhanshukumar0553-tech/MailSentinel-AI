"""
MailSentinel AI - Database ORM Models for Conversational Security Assistant

Tables:
- chat_sessions: Manages multi-turn conversation sessions.
- chat_messages: Stores individual user, assistant, and tool interaction messages.
"""

import uuid
from datetime import datetime
from typing import List, Optional
from sqlalchemy import (
    ForeignKey,
    String,
    Text,
    JSON
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.db.base import Base
from backend.app.core.time import UTCDateTime, now_utc


class ChatSessionRecord(Base):
    """
    Stores conversational session metadata for the Cyber SOC Assistant.
    """
    __tablename__ = "chat_sessions"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )
    title: Mapped[str] = mapped_column(String(255), default="New Security Conversation")
    analyst_id: Mapped[str] = mapped_column(String(64), index=True, default="analyst-default-dev")
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime,
        default=now_utc,
        index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime,
        default=now_utc,
        onupdate=now_utc
    )
    associated_scan_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("scans.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )

    messages: Mapped[List["ChatMessageRecord"]] = relationship(
        "ChatMessageRecord",
        back_populates="session",
        cascade="all, delete-orphan",
        order_by="ChatMessageRecord.created_at"
    )


class ChatMessageRecord(Base):
    """
    Stores individual messages, tool calls, and assistant responses.
    """
    __tablename__ = "chat_messages"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )
    session_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("chat_sessions.id", ondelete="CASCADE"),
        index=True
    )
    role: Mapped[str] = mapped_column(String(20), default="user") # 'user', 'assistant', 'system', 'tool'
    content: Mapped[str] = mapped_column(Text, nullable=False)
    tool_calls: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime,
        default=now_utc,
        index=True
    )

    session: Mapped["ChatSessionRecord"] = relationship(
        "ChatSessionRecord",
        back_populates="messages"
    )

