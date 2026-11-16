"""
MailSentinel AI - Custom Domain Exceptions & Global Handlers

Provides structured error responses for API clients without leaking internal stack traces.
"""

from typing import Any, Dict, Optional
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from backend.app.core.logging import logger


class MailSentinelException(Exception):
    """Base exception class for MailSentinel AI."""
    def __init__(self, message: str, status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.details = details or {}


class DatasetLoadingError(MailSentinelException):
    """Raised when downloading or preprocessing Hugging Face datasets fails."""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message=message, status_code=status.HTTP_502_BAD_GATEWAY, details=details)


class ModelInferenceError(MailSentinelException):
    """Raised when machine learning or AI inference fails."""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message=message, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, details=details)


class EmailParsingError(MailSentinelException):
    """Raised when email content cannot be decoded or parsed."""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message=message, status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, details=details)


def register_exception_handlers(app: FastAPI) -> None:
    """Registers global exception handlers on the FastAPI application."""

    @app.exception_handler(MailSentinelException)
    async def mailsentinel_exception_handler(request: Request, exc: MailSentinelException) -> JSONResponse:
        logger.error("Handled MailSentinelException at %s: %s (Details: %s)", request.url.path, exc.message, exc.details)
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "status": "error",
                "error_type": exc.__class__.__name__,
                "message": exc.message,
                "details": exc.details
            }
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled server exception at %s: %s", request.url.path, str(exc))
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "status": "error",
                "error_type": "InternalServerError",
                "message": "An internal security platform error occurred. Please contact the administrator.",
                "details": {}
            }
        )

