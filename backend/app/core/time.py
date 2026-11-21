"""
MailSentinel AI - Centralized Date, Timezone & Timestamp Standardizer
Phase 3.8 Global Standard:
- Storage: Always UTC (timezone-aware)
- Wire/API: ISO 8601 UTC with trailing 'Z' (e.g. 2026-11-16T08:59:15.123456Z)
- User Display: Asia/Kolkata (IST - UTC+05:30)
- Display Format: DD MMM YYYY, hh:mm:ss AM/PM IST
"""

from datetime import datetime, timezone, tzinfo
from zoneinfo import ZoneInfo
from typing import Any, Optional, Union
from sqlalchemy import TypeDecorator, DateTime


# Centralized Timezone Constants
TIMEZONE_NAME = "Asia/Kolkata"
TIMEZONE_LABEL = "IST (UTC+05:30)"
TIMEZONE_ABBR = "IST"

try:
    IST_TZ: tzinfo = ZoneInfo(TIMEZONE_NAME)
except Exception:
    # Fallback to standard +05:30 fixed offset if zoneinfo database unavailable
    from datetime import timedelta
    IST_TZ = timezone(timedelta(hours=5, minutes=30), name="IST")


def now_utc() -> datetime:
    """Returns the current instant as a timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def now_ist() -> datetime:
    """Returns the current instant in Indian Standard Time (Asia/Kolkata)."""
    return datetime.now(IST_TZ)


def ensure_utc(dt: Optional[Union[datetime, str, int, float]]) -> Optional[datetime]:
    """
    Guarantees that a datetime object is timezone-aware in UTC.
    - If string, parses ISO format (treating naive strings as UTC).
    - If epoch timestamp (int/float), converts from UTC epoch.
    - If naive datetime, attaches timezone.utc (since DB stores UTC).
    - If aware datetime, converts via astimezone(timezone.utc).
    """
    if dt is None:
        return None

    if isinstance(dt, (int, float)):
        return datetime.fromtimestamp(dt, tz=timezone.utc)

    if isinstance(dt, str):
        cleaned = dt.strip()
        if not cleaned:
            return None
        # Handle trailing 'Z'
        if cleaned.endswith("Z"):
            cleaned = cleaned[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(cleaned)
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except ValueError:
            # Try alternate space-separated format from SQLite: 'YYYY-MM-DD HH:MM:SS.ffffff'
            try:
                parsed = datetime.strptime(cleaned.split("+")[0].strip(), "%Y-%m-%d %H:%M:%S.%f")
                return parsed.replace(tzinfo=timezone.utc)
            except ValueError:
                try:
                    parsed = datetime.strptime(cleaned.split("+")[0].strip(), "%Y-%m-%d %H:%M:%S")
                    return parsed.replace(tzinfo=timezone.utc)
                except ValueError:
                    return None

    if isinstance(dt, datetime):
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    return None


def to_iso_utc(dt: Optional[Union[datetime, str, int, float]]) -> Optional[str]:
    """
    Converts any datetime or timestamp to standard ISO 8601 UTC with 'Z' suffix.
    Example: 2026-11-16T08:59:15.661673Z
    """
    aware = ensure_utc(dt)
    if aware is None:
        return None
    iso = aware.isoformat()
    if iso.endswith("+00:00"):
        return iso[:-6] + "Z"
    if not iso.endswith("Z"):
        return iso + "Z"
    return iso


def to_ist(dt: Optional[Union[datetime, str, int, float]]) -> Optional[datetime]:
    """Converts a timestamp or datetime to Asia/Kolkata (IST)."""
    aware_utc = ensure_utc(dt)
    if aware_utc is None:
        return None
    return aware_utc.astimezone(IST_TZ)


def format_ist(
    dt: Optional[Union[datetime, str, int, float]],
    include_seconds: bool = True,
    include_tz: bool = True
) -> str:
    """
    Formats a timestamp for user display in Indian Standard Time.
    Standard display format: DD MMM YYYY, hh:mm:ss AM/PM IST
    Example: 16 Nov 2026, 02:29:15 PM IST
    """
    ist_dt = to_ist(dt)
    if ist_dt is None:
        return "N/A"

    time_fmt = "%I:%M:%S %p" if include_seconds else "%I:%M %p"
    formatted = ist_dt.strftime(f"%d %b %Y, {time_fmt}")

    if include_tz:
        formatted = f"{formatted} {TIMEZONE_ABBR}"

    return formatted


class UTCDateTime(TypeDecorator):
    """
    SQLAlchemy TypeDecorator that guarantees timezone-aware UTC datetime
    both when persisting to and retrieving from SQLite/PostgreSQL.
    - Prevents SQLite naive datetime returns by re-attaching timezone.utc.
    - Converts any input timezone to UTC before binding parameters.
    """
    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        dt = ensure_utc(value)
        if dt is None:
            return None
        if dialect and dialect.name == "postgresql":
            # asyncpg requires offset-naive datetime when binding to TIMESTAMP WITHOUT TIME ZONE
            return dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return ensure_utc(value)

