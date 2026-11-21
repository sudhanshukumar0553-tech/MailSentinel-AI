"""
MailSentinel AI - AI Investigation Agent Endpoint

High-performance endpoints for:
- POST /api/v1/agent/investigate (Fast asynchronous autonomous investigation)
- POST /api/v1/agent/investigate/stream (Real-time SSE progressive execution feedback)
"""

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.core.logging import logger
from backend.app.core.auth import AuthenticatedUser, get_current_user, ROLE_CUSTOMER
from backend.app.db.session import get_db
from backend.app.db.models.scan import ScanRecord
from backend.app.db.models.investigation import AgentInvestigationRecord
from backend.app.ai.agent import run_agent_investigation_async, stream_agent_investigation_events
from backend.app.schemas.agent import AgentInvestigationRequest, AgentInvestigationResponse

router = APIRouter(prefix="/agent", tags=["AI Investigation Agent"])


@router.post("/investigate", response_model=AgentInvestigationResponse, status_code=status.HTTP_200_OK)
async def investigate_email(
    payload: AgentInvestigationRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Launches an autonomous forensic investigation on an email.
    Runs non-blocking async execution with Gemini acceleration and empirical SOC tools.
    """
    # Verify scan ownership if scan_id is provided
    if payload.scan_id:
        scan_ref = await db.get(ScanRecord, payload.scan_id)
        if scan_ref and current_user.role == ROLE_CUSTOMER and getattr(scan_ref, "user_id", "") != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: You do not have ownership of this scan record."
            )
    logger.info("Received request for AI agent investigation...")
    result = await run_agent_investigation_async(
        email_text=payload.email_content,
        raw_headers=payload.raw_headers or "none"
    )

    investigation_id = None
    inv_created_at = None
    if payload.scan_id:
        try:
            inv_record = AgentInvestigationRecord(
                scan_id=payload.scan_id,
                model_used=result.get("model_used", "gemini-3.1-flash-lite"),
                steps_count=result.get("steps_count", 0),
                tools_invoked={"steps": result.get("steps", [])},
                thought_process=result.get("agent_mode", "autonomous"),
                final_assessment=result.get("final_report", "Investigation finalized.")
            )
            db.add(inv_record)
            await db.commit()
            await db.refresh(inv_record)
            investigation_id = inv_record.id
            inv_created_at = inv_record.created_at
        except Exception as exc:
            logger.warning("Could not persist investigation to database: %s", exc)

    kwargs = {}
    if inv_created_at:
        kwargs["created_at"] = inv_created_at

    return AgentInvestigationResponse(
        status=result.get("status", "completed"),
        model_used=result.get("model_used", "gemini-3.1-flash-lite"),
        agent_mode=result.get("agent_mode", "gemini_tool_correlation"),
        steps_count=result.get("steps_count", 0),
        steps=result.get("steps", []),
        risk_score=result.get("risk_score", 0.0),
        threat_level=result.get("threat_level", "SAFE"),
        verdict=result.get("verdict", ""),
        final_report=result.get("final_report", ""),
        investigation_id=investigation_id,
        **kwargs
    )


@router.post("/investigate/stream")
async def investigate_email_stream(
    payload: AgentInvestigationRequest,
    current_user: AuthenticatedUser = Depends(get_current_user)
):
    """
    Real-time Server-Sent Events (SSE) stream for progressive agent execution.
    Yields step-by-step updates from CONNECTING to TOOL_EXECUTION and COMPLETED.
    """
    logger.info("Received request for progressive AI agent investigation stream...")
    return StreamingResponse(
        stream_agent_investigation_events(
            email_text=payload.email_content,
            raw_headers=payload.raw_headers or "none"
        ),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )
