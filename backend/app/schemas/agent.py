"""
MailSentinel AI - Pydantic Schemas for AI Agent Investigations
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_serializer
from backend.app.core.time import now_utc, to_iso_utc


class AgentInvestigationRequest(BaseModel):
    """Payload for launching an interactive or deep AI investigation."""
    email_content: str = Field(
        ...,
        description="Untrusted email text to be forensically investigated.",
        min_length=1,
        max_length=1_000_000
    )
    raw_headers: Optional[str] = Field("none", description="RFC822 transport headers if available.")
    scan_id: Optional[str] = Field(None, description="Optional scan ID to associate this investigation with.")


class AgentStepSchema(BaseModel):
    """Single forensic tool execution step."""
    step: int
    tool: str
    output: Dict[str, Any]


class AgentInvestigationResponse(BaseModel):
    """Result of autonomous SOC AI agent investigation."""
    status: str
    model_used: str
    agent_mode: str
    steps_count: int
    steps: List[Dict[str, Any]] = []
    risk_score: float = 0.0
    threat_level: str = "SAFE"
    verdict: str = ""
    final_report: str
    investigation_id: Optional[str] = None
    created_at: datetime = Field(default_factory=now_utc)

    @field_serializer("created_at", when_used="json")
    def serialize_created_at(self, dt: datetime) -> str:
        return to_iso_utc(dt) or dt.isoformat()

