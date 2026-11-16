"""
MailSentinel AI - Conversational Security Assistant Endpoints

Provides RESTful endpoints for:
- POST /api/v1/chat/message (Chat interactions with tool execution & persistent history)
- GET /api/v1/chat/sessions (List conversation threads with analyst ownership filtering)
- GET /api/v1/chat/sessions/{session_id} (Retrieve conversation history with ownership validation)
- DELETE /api/v1/chat/sessions/{session_id} (Delete conversation thread with ownership validation)
"""

from backend.app.core.time import now_utc
import json
import time
import asyncio
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select, desc
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.core.auth import AuthenticatedAnalyst, get_current_analyst
from backend.app.db.session import get_db, AsyncSessionLocal
from backend.app.db.models.chat import ChatSessionRecord, ChatMessageRecord
from backend.app.db.models.scan import ScanRecord
from backend.app.schemas.chat import (
    ChatMessageRequest,
    ChatMessageResponse,
    ChatSessionSummary,
    ChatSessionDetail,
    ChatMessageDetail
)
from backend.app.ai.chat_assistant import (
    run_conversational_assistant,
    run_conversational_assistant_async,
    detect_user_intent,
    execute_deterministic_chat_response,
    format_bounded_history
)
from backend.app.ai.gemini_provider import call_gemini_stream

router = APIRouter(prefix="/chat", tags=["Conversational Security Assistant"])


@router.post("/message", response_model=ChatMessageResponse, status_code=status.HTTP_200_OK)
async def send_chat_message(
    payload: ChatMessageRequest,
    current_analyst: AuthenticatedAnalyst = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db)
):
    """
    Submits a message to the Sentinel Copilot.
    Enforces server-side analyst authentication and conversation ownership.
    """
    session_id = payload.session_id

    # 1. If scan_id is referenced, verify it exists
    if payload.scan_id:
        scan_ref = await db.get(ScanRecord, payload.scan_id)
        if not scan_ref:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Referenced scan ID '{payload.scan_id}' not found."
            )

    # 2. Resolve or create chat session
    session_record = None
    if session_id:
        stmt = (
            select(ChatSessionRecord)
            .options(selectinload(ChatSessionRecord.messages))
            .where(ChatSessionRecord.id == session_id)
        )
        res = await db.execute(stmt)
        session_record = res.scalar_one_or_none()
        if not session_record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Chat session '{session_id}' not found."
            )

        # Enforce server-side ownership verification
        if session_record.analyst_id != current_analyst.id:
            logger.warning(
                "Access denied: Analyst %s attempted to post to session %s owned by %s",
                current_analyst.id, session_id, session_record.analyst_id
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: You do not have ownership of this conversation session."
            )

    if not session_record:
        # Create new session owned by authenticated analyst
        short_title = payload.message.strip()[:40]
        if len(payload.message.strip()) > 40:
            short_title += "..."
        session_record = ChatSessionRecord(
            title=short_title or "Security Investigation",
            analyst_id=current_analyst.id,
            associated_scan_id=payload.scan_id
        )
        db.add(session_record)
        await db.flush()
        # Refresh to ensure relationships are loaded
        stmt = (
            select(ChatSessionRecord)
            .options(selectinload(ChatSessionRecord.messages))
            .where(ChatSessionRecord.id == session_record.id)
        )
        res = await db.execute(stmt)
        session_record = res.scalar_one()
        session_id = session_record.id

    # 3. Extract recent conversation context (last 8 messages)
    history_context = []
    if session_record.messages:
        for m in session_record.messages[-8:]:
            history_context.append({"role": m.role, "content": m.content})

    # 4. Store user message in database
    user_msg = ChatMessageRecord(
        session_id=session_id,
        role="user",
        content=payload.message
    )
    db.add(user_msg)
    await db.flush()

    # 5. Invoke Conversational Assistant
    result = await run_conversational_assistant_async(
        message=payload.message,
        email_content=payload.email_content,
        raw_headers=payload.raw_headers or "none",
        conversation_history=history_context,
        language=payload.language or "en-US"
    )

    now = now_utc()

    # 6. Store assistant response
    assistant_msg = ChatMessageRecord(
        session_id=session_id,
        role="assistant",
        content=result.get("reply", "Response generated."),
        tool_calls={
            "tools": result.get("tools_invoked", []),
            "evidence": result.get("evidence", {}),
            "mode": result.get("mode"),
            "operational_status": result.get("operational_status"),
            "model_used": result.get("model_used"),
            "latency_ms": result.get("latency_ms"),
            "disclaimer": result.get("disclaimer")
        },
        created_at=now
    )
    db.add(assistant_msg)

    # Update session timestamp
    session_record.updated_at = now
    await db.commit()

    return ChatMessageResponse(
        session_id=session_id,
        role="assistant",
        reply=result.get("reply", ""),
        mode=result.get("mode", "deterministic_fallback"),
        is_llm_generated=result.get("is_llm_generated", False),
        operational_status=result.get("operational_status", "nominal"),
        disclaimer=result.get("disclaimer"),
        model_used=result.get("model_used"),
        latency_ms=result.get("latency_ms"),
        tools_invoked=result.get("tools_invoked", []),
        evidence=result.get("evidence", {}),
        created_at=now
    )


@router.post("/message/stream")
async def send_chat_message_stream(
    payload: ChatMessageRequest,
    current_analyst: AuthenticatedAnalyst = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db)
):
    """
    Submits a message and streams the response tokens in real-time via Server-Sent Events (SSE).
    """
    session_id = payload.session_id

    # 1. If scan_id is referenced, verify it exists
    if payload.scan_id:
        scan_ref = await db.get(ScanRecord, payload.scan_id)
        if not scan_ref:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Associated scan ID '{payload.scan_id}' does not exist."
            )

    # 2. Session creation or ownership enforcement
    history_context = []
    if not session_id:
        title = payload.message.strip()[:45] + ("..." if len(payload.message.strip()) > 45 else "")
        session_record = ChatSessionRecord(
            title=title or "Investigation Session",
            analyst_id=current_analyst.id,
            associated_scan_id=payload.scan_id
        )
        db.add(session_record)
        await db.flush()
        session_id = session_record.id
    else:
        stmt = (
            select(ChatSessionRecord)
            .options(selectinload(ChatSessionRecord.messages))
            .where(ChatSessionRecord.id == session_id)
        )
        res = await db.execute(stmt)
        session_record = res.scalar_one_or_none()
        if not session_record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Conversation session '{session_id}' not found."
            )
        if session_record.analyst_id != current_analyst.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: You do not have ownership of this conversation session."
            )

        # 3. Extract recent conversation context (last 4 messages)
        if session_record.messages:
            for m in session_record.messages[-4:]:
                history_context.append({"role": m.role, "content": m.content})

    # 4. Store user message in database
    user_msg = ChatMessageRecord(
        session_id=session_id,
        role="user",
        content=payload.message
    )
    db.add(user_msg)
    await db.commit()

    async def sse_event_stream():
        start_time = time.perf_counter()
        lang = payload.language or "en-US"
        has_email = bool(payload.email_content and len(payload.email_content.strip()) > 5)
        intent = detect_user_intent(payload.message, has_email)

        # Handle Prompt Injection immediately
        if intent == "ADVERSARIAL_PROMPT_INJECTION":
            res = execute_deterministic_chat_response(
                payload.message, payload.email_content, payload.raw_headers, history_context, language=lang
            )
            yield f"data: {json.dumps({'type': 'chunk', 'text': res['reply']})}\n\n"
            yield f"data: {json.dumps({'type': 'complete', 'session_id': session_id, 'reply': res['reply'], 'mode': res['mode'], 'is_llm_generated': False, 'operational_status': 'guardrail_triggered', 'model_used': None, 'latency_ms': 5.0, 'tools_invoked': [], 'evidence': {}})}\n\n"
            return

        # Handle Out of Scope requests immediately (no external LLM call)
        if intent == "OUT_OF_SCOPE":
            out_reply = (
                "I am MailSentinel Cybersecurity Copilot. I specialize in cybersecurity, email security, threat investigations, and MailSentinel AI. Please ask me something related to these areas."
            )
            yield f"data: {json.dumps({'type': 'chunk', 'text': out_reply})}\n\n"
            yield f"data: {json.dumps({'type': 'complete', 'session_id': session_id, 'reply': out_reply, 'mode': 'domain_restriction', 'is_llm_generated': False, 'operational_status': 'nominal', 'model_used': None, 'latency_ms': 1.0, 'tools_invoked': [], 'evidence': {}})}\n\n"
            return

        # Handle Greetings immediately (no external LLM call)
        if intent == "GENERAL_GREETING":
            greet_reply = (
                "Hello! I am **MailSentinel Cybersecurity Copilot**, your Tier-3 SOC Security Advisor.\n\n"
                "I specialize in email security, phishing detection, threat intelligence, and MailSentinel AI. "
                "How can I assist your security operations today?"
            )
            yield f"data: {json.dumps({'type': 'chunk', 'text': greet_reply})}\n\n"
            yield f"data: {json.dumps({'type': 'complete', 'session_id': session_id, 'reply': greet_reply, 'mode': 'direct_greeting', 'is_llm_generated': False, 'operational_status': 'nominal', 'model_used': None, 'latency_ms': 1.0, 'tools_invoked': [], 'evidence': {}})}\n\n"
            return

        # If Gemini is configured and it is normal conversation: stream directly
        if settings.is_gemini_configured and intent not in ("SECURITY_INVESTIGATION", "ANALYZE_EMAIL") and not has_email:
            full_text = []
            history_str = format_bounded_history(history_context)
            prompt = f"{history_str}User Request: {payload.message}"
            sys_inst = (
                "You are MailSentinel AI SOC Assistant, a principal enterprise cybersecurity advisor. "
                "Provide accurate, professional, and actionable security insights. When explaining workflows, "
                "incident response steps, email protocols (SPF, DKIM, DMARC), or threat lifecycles, include a "
                "clean, valid Mermaid diagram inside a ```mermaid code fence."
            )
            try:
                async for chunk in call_gemini_stream(prompt, sys_inst, settings.GEMINI_MAX_OUTPUT_TOKENS):
                    full_text.append(chunk)
                    yield f"data: {json.dumps({'type': 'chunk', 'text': chunk})}\n\n"
                
                elapsed_ms = round((time.perf_counter() - start_time) * 1000, 1)
                complete_reply = "".join(full_text)

                # Persist to database in new session
                async with AsyncSessionLocal() as save_db:
                    now = now_utc()
                    save_msg = ChatMessageRecord(
                        session_id=session_id,
                        role="assistant",
                        content=complete_reply,
                        tool_calls={"mode": "gemini_direct", "model_used": settings.GEMINI_MODEL, "latency_ms": elapsed_ms},
                        created_at=now
                    )
                    save_db.add(save_msg)
                    # Update session
                    sess = await save_db.get(ChatSessionRecord, session_id)
                    if sess:
                        sess.updated_at = now
                    await save_db.commit()

                yield f"data: {json.dumps({'type': 'complete', 'session_id': session_id, 'reply': complete_reply, 'mode': 'gemini_direct', 'is_llm_generated': True, 'model_used': settings.GEMINI_MODEL, 'latency_ms': elapsed_ms, 'tools_invoked': [], 'evidence': {}})}\n\n"
                return
            except Exception as stream_err:
                logger.warning("Streaming error: %s. Falling back to local generation.", stream_err)

        # For security investigations or fallback: run full pipeline and emit chunked text
        res = await run_conversational_assistant_async(
            message=payload.message,
            email_content=payload.email_content,
            raw_headers=payload.raw_headers,
            conversation_history=history_context,
            language=lang
        )

        reply_str = res.get("reply", "")
        # Emit reply in smooth word chunks
        words = reply_str.split(" ")
        for i in range(0, len(words), 4):
            chunk = " ".join(words[i:i+4]) + " "
            yield f"data: {json.dumps({'type': 'chunk', 'text': chunk})}\n\n"
            await asyncio.sleep(0.01)

        # Persist response
        async with AsyncSessionLocal() as save_db:
            now = now_utc()
            save_msg = ChatMessageRecord(
                session_id=session_id,
                role="assistant",
                content=reply_str,
                tool_calls={
                    "tools": res.get("tools_invoked", []),
                    "evidence": res.get("evidence", {}),
                    "mode": res.get("mode"),
                    "model_used": res.get("model_used"),
                    "latency_ms": res.get("latency_ms")
                },
                created_at=now
            )
            save_db.add(save_msg)
            sess = await save_db.get(ChatSessionRecord, session_id)
            if sess:
                sess.updated_at = now
            await save_db.commit()

        yield f"data: {json.dumps({'type': 'complete', 'session_id': session_id, 'reply': reply_str, 'mode': res.get('mode'), 'is_llm_generated': res.get('is_llm_generated', False), 'operational_status': res.get('operational_status', 'nominal'), 'disclaimer': res.get('disclaimer'), 'model_used': res.get('model_used'), 'latency_ms': res.get('latency_ms'), 'tools_invoked': res.get('tools_invoked', []), 'evidence': res.get('evidence', {})})}\n\n"

    return StreamingResponse(sse_event_stream(), media_type="text/event-stream")


@router.get("/sessions", response_model=List[ChatSessionSummary], status_code=status.HTTP_200_OK)
async def list_chat_sessions(
    limit: int = 20,
    offset: int = 0,
    current_analyst: AuthenticatedAnalyst = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db)
):
    """Lists past conversation sessions owned by the authenticated analyst."""
    stmt = (
        select(ChatSessionRecord)
        .options(selectinload(ChatSessionRecord.messages))
        .where(ChatSessionRecord.analyst_id == current_analyst.id)
        .order_by(desc(ChatSessionRecord.updated_at))
        .offset(offset)
        .limit(limit)
    )
    res = await db.execute(stmt)
    records = res.scalars().all()

    summaries = []
    for r in records:
        summaries.append(ChatSessionSummary(
            id=r.id,
            title=r.title,
            analyst_id=r.analyst_id,
            created_at=r.created_at,
            updated_at=r.updated_at,
            associated_scan_id=r.associated_scan_id,
            message_count=len(r.messages) if r.messages else 0
        ))
    return summaries


@router.get("/sessions/{session_id}", response_model=ChatSessionDetail, status_code=status.HTTP_200_OK)
async def get_chat_session(
    session_id: str,
    current_analyst: AuthenticatedAnalyst = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db)
):
    """Retrieves full conversation history for a specific session with ownership validation."""
    stmt = (
        select(ChatSessionRecord)
        .options(selectinload(ChatSessionRecord.messages))
        .where(ChatSessionRecord.id == session_id)
    )
    res = await db.execute(stmt)
    session = res.scalar_one_or_none()
    if not session:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Chat session not found.")

    if session.analyst_id != current_analyst.id:
        logger.warning(
            "Access denied: Analyst %s attempted to inspect session %s owned by %s",
            current_analyst.id, session_id, session.analyst_id
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Access denied to this conversation session."
        )

    return ChatSessionDetail(
        id=session.id,
        title=session.title,
        analyst_id=session.analyst_id,
        created_at=session.created_at,
        updated_at=session.updated_at,
        associated_scan_id=session.associated_scan_id,
        messages=[
            ChatMessageDetail(
                id=m.id,
                role=m.role,
                content=m.content,
                tool_calls=m.tool_calls,
                created_at=m.created_at
            )
            for m in session.messages
        ]
    )


@router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_chat_session(
    session_id: str,
    current_analyst: AuthenticatedAnalyst = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db)
):
    """Deletes a chat session and cascades to all its messages with ownership validation."""
    stmt = select(ChatSessionRecord).where(ChatSessionRecord.id == session_id)
    res = await db.execute(stmt)
    session = res.scalar_one_or_none()
    if not session:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Chat session not found.")

    if session.analyst_id != current_analyst.id:
        logger.warning(
            "Access denied: Analyst %s attempted to delete session %s owned by %s",
            current_analyst.id, session_id, session.analyst_id
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Cannot delete conversation owned by another analyst."
        )

    await db.delete(session)
    await db.commit()
    logger.info("Deleted chat session %s and its associated messages.", session_id)
    return None
