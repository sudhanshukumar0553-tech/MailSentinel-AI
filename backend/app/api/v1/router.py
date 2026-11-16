"""
MailSentinel AI - API v1 Master Router

Aggregates all version 1 endpoints into a unified router.
"""

from fastapi import APIRouter
from backend.app.api.v1.endpoints import (
    health,
    scan,
    agent,
    chat,
    analytics,
    models,
    history,
    url_intel,
    auth,
    audit
)

api_v1_router = APIRouter()

# Register all endpoint routers
api_v1_router.include_router(health.router)
api_v1_router.include_router(scan.router)
api_v1_router.include_router(agent.router)
api_v1_router.include_router(chat.router)
api_v1_router.include_router(analytics.router)
api_v1_router.include_router(models.router)
api_v1_router.include_router(history.router)
api_v1_router.include_router(url_intel.router)
api_v1_router.include_router(auth.router)
api_v1_router.include_router(audit.router)
