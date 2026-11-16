"""
MailSentinel AI - Pydantic Schemas for Conversational Security Assistant
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_serializer
from backend.app.core.time import to_iso_utc


class ChatMessageRequest(BaseModel):
    """Payload for submitting a message to the Conversational Security Assistant."""
    message: str = Field(
        ...,
        description="User question, forensic instruction, or prompt.",
        min_length=1,
        max_length=50_000
    )
    session_id: Optional[str] = Field(
        None,
        description="Optional UUID of an existing conversation thread."
    )
    email_content: Optional[str] = Field(
        None,
        description="Optional raw email body or snippet to analyze."
    )
    raw_headers: Optional[str] = Field(
        "none",
        description="Optional RFC822 transport headers."
    )
    scan_id: Optional[str] = Field(
        None,
        description="Optional scan ID to associate this conversation with."
    )
    language: Optional[str] = Field(
        "en-US",
        description="Language code: 'en-US' (default)."
    )


class ChatToolExecutionSchema(BaseModel):
    """Details of a tool executed during a conversational interaction."""
    tool: str
    output: Dict[str, Any]


class ChatMessageResponse(BaseModel):
    """Assistant conversational response payload."""
    session_id: str
    role: str = "assistant"
    reply: str
    mode: str = "gemini_direct"  # or "gemini_grounded_investigation", "deterministic_fallback"
    is_llm_generated: bool = False
    operational_status: str = "nominal"
    disclaimer: Optional[str] = None
    model_used: Optional[str] = None
    latency_ms: Optional[float] = None
    tools_invoked: List[Dict[str, Any]] = []
    evidence: Dict[str, Any] = {}
    created_at: datetime

    @field_serializer("created_at", when_used="json")
    def serialize_created_at(self, dt: datetime) -> str:
        return to_iso_utc(dt) or dt.isoformat()


class ChatMessageDetail(BaseModel):
    """Single message item in a conversation thread."""
    id: str
    role: str
    content: str
    tool_calls: Optional[Dict[str, Any]] = None
    created_at: datetime

    @field_serializer("created_at", when_used="json")
    def serialize_created_at(self, dt: datetime) -> str:
        return to_iso_utc(dt) or dt.isoformat()

    class Config:
        from_attributes = True


class ChatSessionSummary(BaseModel):
    """Metadata summary of a conversation session."""
    id: str
    title: str
    analyst_id: str = "analyst-default-dev"
    created_at: datetime
    updated_at: datetime
    associated_scan_id: Optional[str] = None
    message_count: int = 0

    @field_serializer("created_at", "updated_at", when_used="json")
    def serialize_timestamps(self, dt: datetime) -> str:
        return to_iso_utc(dt) or dt.isoformat()

    class Config:
        from_attributes = True


class ChatSessionDetail(BaseModel):
    """Complete conversation session including message history."""
    id: str
    title: str
    analyst_id: str = "analyst-default-dev"
    created_at: datetime
    updated_at: datetime
    associated_scan_id: Optional[str] = None
    messages: List[ChatMessageDetail] = []

    @field_serializer("created_at", "updated_at", when_used="json")
    def serialize_timestamps(self, dt: datetime) -> str:
        return to_iso_utc(dt) or dt.isoformat()

    class Config:
        from_attributes = True

