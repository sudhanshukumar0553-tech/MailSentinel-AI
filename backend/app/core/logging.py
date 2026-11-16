"""
MailSentinel AI - Structured Logging Setup

Configures clean, informative console logging for the application.
"""

import logging
import sys
from backend.app.core.config import settings


def setup_logging() -> logging.Logger:
    """Configures application-wide logging with timestamps and level labels."""
    log_level = logging.DEBUG if settings.DEBUG else logging.INFO
    log_format = "%(asctime)s | %(levelname)-8s | %(name)s:%(funcName)s:%(lineno)d - %(message)s"

    logging.basicConfig(
        level=log_level,
        format=log_format,
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )

    # Reduce verbosity of noisy third-party libraries
    logging.getLogger("aiosqlite").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)

    logger = logging.getLogger("mailsentinel")
    logger.info("Logging initialized for %s (%s)", settings.PROJECT_NAME, settings.ENVIRONMENT)
    return logger


logger = setup_logging()

