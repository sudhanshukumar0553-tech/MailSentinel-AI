"""
MailSentinel AI - Enterprise Authentication & Session Telemetry Endpoints
"""

from typing import Dict, Any, List
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from backend.app.core.auth import (
    AuthenticatedUser,
    get_current_user,
    require_admin,
    require_soc_analyst,
    require_customer,
    ROLE_ADMIN,
    ROLE_SOC_ANALYST,
    ROLE_CUSTOMER
)


router = APIRouter(prefix="/auth", tags=["Enterprise Authentication & RBAC"])


class UserProfileResponse(BaseModel):
    id: str
    email: str | None = None
    role: str
    provider: str
    is_authenticated: bool = True
    permissions: List[str]


@router.get("/me", response_model=UserProfileResponse)
async def get_current_user_profile(
    current_user: AuthenticatedUser = Depends(get_current_user)
) -> UserProfileResponse:
    """
    Returns the verified profile and security context of the authenticated user.
    """
    permissions = ["read:scans", "read:threat_matrix"]
    if current_user.role in [ROLE_ADMIN, ROLE_SOC_ANALYST]:
        permissions.extend(["execute:deep_investigation", "execute:quarantine", "write:copilot_notes"])
    if current_user.role == ROLE_ADMIN:
        permissions.extend(["admin:manage_users", "admin:configure_models", "admin:view_audit_logs"])

    return UserProfileResponse(
        id=current_user.id,
        email=current_user.email,
        role=current_user.role,
        provider=current_user.provider,
        is_authenticated=True,
        permissions=permissions
    )


@router.get("/admin-check")
async def verify_admin_access(
    admin: AuthenticatedUser = Depends(require_admin)
) -> Dict[str, Any]:
    """Protected endpoint requiring Admin role authorization."""
    return {
        "status": "authorized",
        "role": admin.role,
        "message": f"Welcome, Admin {admin.id}. Full administrative access granted."
    }


@router.get("/soc-check")
async def verify_soc_access(
    analyst: AuthenticatedUser = Depends(require_soc_analyst)
) -> Dict[str, Any]:
    """Protected endpoint requiring SOC Analyst or Admin role."""
    return {
        "status": "authorized",
        "role": analyst.role,
        "message": f"SOC operational access verified for {analyst.id} ({analyst.role})."
    }


@router.get("/customer-check")
async def verify_customer_access(
    customer: AuthenticatedUser = Depends(require_customer)
) -> Dict[str, Any]:
    """Protected endpoint open to authenticated Customers, Analysts and Admins."""
    return {
        "status": "authorized",
        "role": customer.role,
        "message": f"Standard customer access verified for {customer.id}."
    }
