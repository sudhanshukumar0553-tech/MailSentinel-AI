"""
MailSentinel AI - Enterprise Audit Logging & Security Monitoring Endpoints
"""

from typing import Optional
from datetime import datetime
from fastapi import APIRouter, Depends, Query, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.db.session import get_db
from backend.app.core.auth import (
    AuthenticatedUser,
    require_admin,
    require_soc_analyst,
    ROLE_ADMIN,
    ROLE_SOC_ANALYST
)
from backend.app.services.audit_service import AuditService
from backend.app.schemas.audit import (
    AuditEventResponse,
    AuditLogsPaginationResponse,
    AuditMetricsResponse,
    AuditEventCreate
)

router = APIRouter(prefix="/audit", tags=["Security Audit & Monitoring"])


@router.get("/logs", response_model=AuditLogsPaginationResponse)
async def get_audit_logs(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    severity: Optional[str] = Query(None, description="Filter by severity: INFO, LOW, MEDIUM, HIGH, CRITICAL"),
    category: Optional[str] = Query(None, description="Filter by category: AUTH, AUTHZ, ADMIN, SCAN, THREAT, SECURITY"),
    event_type: Optional[str] = Query(None, description="Filter by exact event type"),
    outcome: Optional[str] = Query(None, description="Filter by outcome: SUCCESS, FAILURE, BLOCKED"),
    search: Optional[str] = Query(None, description="Search term for actor ID, email, endpoint, or IP"),
    start_date: Optional[datetime] = Query(None, description="Start date filter (UTC)"),
    end_date: Optional[datetime] = Query(None, description="End date filter (UTC)"),
    current_user: AuthenticatedUser = Depends(require_soc_analyst),
    db: AsyncSession = Depends(get_db)
) -> AuditLogsPaginationResponse:
    """
    Retrieves paginated audit events with multi-criteria filtering and RBAC scoping.
    - Admin: Full visibility across all system and administrative audit records.
    - SOC Analyst: Scoped to operational and threat events (SCAN, THREAT, AUTHZ, SECURITY).
    - Customer: Strictly forbidden (HTTP 403).
    """
    items, total = await AuditService.get_audit_logs(
        db=db,
        page=page,
        page_size=page_size,
        severity=severity,
        category=category,
        event_type=event_type,
        outcome=outcome,
        search=search,
        start_date=start_date,
        end_date=end_date,
        caller_role=current_user.role
    )

    total_pages = (total + page_size - 1) // page_size if total > 0 else 1

    return AuditLogsPaginationResponse(
        items=[AuditEventResponse(**item.to_dict()) for item in items],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages
    )


@router.get("/metrics", response_model=AuditMetricsResponse)
async def get_audit_metrics(
    current_user: AuthenticatedUser = Depends(require_soc_analyst),
    db: AsyncSession = Depends(get_db)
) -> AuditMetricsResponse:
    """
    Returns aggregated security metrics, threat counter KPIs, and recent event timeline.
    Accessible by Admin and SOC Analyst.
    """
    metrics = await AuditService.get_metrics(
        db=db,
        caller_role=current_user.role
    )

    return AuditMetricsResponse(
        total_events=metrics["total_events"],
        critical_alerts=metrics["critical_alerts"],
        high_alerts=metrics["high_alerts"],
        auth_failures=metrics["auth_failures"],
        unauthorized_attempts=metrics["unauthorized_attempts"],
        threats_detected=metrics["threats_detected"],
        severity_breakdown=metrics["severity_breakdown"],
        category_breakdown=metrics["category_breakdown"],
        recent_timeline=[AuditEventResponse(**t) for t in metrics["recent_timeline"]]
    )


@router.get("/export/csv")
async def export_audit_logs_csv(
    severity: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    admin: AuthenticatedUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
) -> Response:
    """
    Exports audit events matching criteria as a CSV file.
    STRICTLY RESTRICTED TO ADMIN ROLE ONLY.
    SOC Analyst and Customer requests are rejected with HTTP 403 Forbidden.
    """
    csv_content = await AuditService.export_csv(
        db=db,
        severity=severity,
        category=category,
        search=search,
        start_date=start_date,
        end_date=end_date
    )

    # Log the administrative export event
    await AuditService.log_event(
        db=db,
        event_type="ADMIN_AUDIT_LOGS_EXPORTED",
        event_category="ADMIN",
        severity="MEDIUM",
        outcome="SUCCESS",
        actor_id=admin.id,
        actor_email=admin.email,
        actor_role=admin.role,
        endpoint="/api/v1/audit/export/csv",
        http_method="GET",
        http_status=status.HTTP_200_OK,
        details={"search": search, "severity": severity, "category": category}
    )

    filename = f"mailsentinel_audit_export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"

    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-cache"
        }
    )


@router.post("/events", response_model=AuditEventResponse, status_code=status.HTTP_201_CREATED)
async def create_custom_audit_event(
    event: AuditEventCreate,
    current_user: AuthenticatedUser = Depends(require_soc_analyst),
    db: AsyncSession = Depends(get_db)
) -> AuditEventResponse:
    """
    Enables authorized security modules and analysts to record structured audit events.
    """
    record = await AuditService.log_event(
        db=db,
        event_type=event.event_type,
        event_category=event.event_category,
        severity=event.severity,
        outcome=event.outcome,
        actor_id=event.actor_id if event.actor_id != "anonymous" else current_user.id,
        actor_email=event.actor_email or current_user.email,
        actor_role=event.actor_role if event.actor_role != "Anonymous" else current_user.role,
        ip_address=event.ip_address,
        user_agent=event.user_agent,
        endpoint=event.endpoint,
        http_method=event.http_method,
        http_status=event.http_status,
        request_correlation_id=event.request_correlation_id,
        details=event.details
    )

    return AuditEventResponse(**record.to_dict())
