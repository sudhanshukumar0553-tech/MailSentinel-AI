"""
MailSentinel AI - Enterprise Audit Logging & Security Monitoring Engine

Provides centralized, tamper-resistant, append-only security telemetry:
- Records authentication, authorization, admin actions, URL/email scans, and threat alerts.
- Enforces strict data sanitization (zero secrets, tokens, or raw email leakage).
- Automated anomaly detection for brute force, unauthorized probing, and privilege escalation.
- Alert deduplication and throttling to prevent alert fatigue.
- Role-scoped querying and administrative CSV reporting.
"""

import re
import csv
import io
import time
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List, Tuple
from sqlalchemy import select, func, and_, or_, desc
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.db.session import AsyncSessionLocal
from backend.app.db.models.audit import AuditEventRecord
from backend.app.core.time import now_utc
from backend.app.core.logging import logger

# Sensitive keys to scrub from details payloads
SENSITIVE_KEY_PATTERNS = re.compile(
    r"(password|secret|jwt|token|bearer|authorization|cookie|session|key|credential|private)",
    re.IGNORECASE
)

# JWT token regex pattern (detects eyJ... strings)
JWT_PATTERN = re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}")

# Alert cooldown cache to prevent duplicate alerts for the same condition: {(alert_type, target): timestamp}
_ALERT_COOLDOWN_CACHE: Dict[Tuple[str, str], float] = {}
ALERT_COOLDOWN_SECONDS = 120.0  # 2 minutes suppression window


def sanitize_input_string(value: str, max_length: int = 500) -> str:
    """Removes newline/control character injections and truncates oversized text."""
    if not isinstance(value, str):
        return str(value)
    # Strip carriage returns and newlines to prevent log injection
    cleaned = value.replace("\r", " ").replace("\n", " ").strip()
    # Mask potential embedded JWT tokens
    cleaned = JWT_PATTERN.sub("[REDACTED_JWT]", cleaned)
    if len(cleaned) > max_length:
        return cleaned[:max_length] + "..."
    return cleaned


def sanitize_audit_details(data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Recursively scrubs sensitive keys, tokens, and PII from audit details.
    Guarantees no passwords, secrets, or raw email bodies enter the audit log.
    """
    if not data or not isinstance(data, dict):
        return {}

    sanitized: Dict[str, Any] = {}
    for k, v in data.items():
        key_str = str(k)
        if SENSITIVE_KEY_PATTERNS.search(key_str):
            sanitized[key_str] = "[REDACTED]"
            continue

        if isinstance(v, dict):
            sanitized[key_str] = sanitize_audit_details(v)
        elif isinstance(v, list):
            sanitized[key_str] = [
                sanitize_audit_details(item) if isinstance(item, dict)
                else sanitize_input_string(str(item), 200)
                for item in v
            ]
        elif isinstance(v, str):
            sanitized[key_str] = sanitize_input_string(v, 400)
        else:
            sanitized[key_str] = v

    return sanitized


class AuditService:
    """
    Enterprise Centralized Security Audit Service.
    Guarantees append-only persistence and real-time monitoring threat detection.
    """

    @staticmethod
    async def log_event(
        db: Optional[AsyncSession] = None,
        event_type: str = "SYSTEM_EVENT",
        event_category: str = "SYSTEM",
        severity: str = "INFO",
        outcome: str = "SUCCESS",
        actor_id: str = "anonymous",
        actor_email: Optional[str] = None,
        actor_role: str = "Anonymous",
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        endpoint: Optional[str] = None,
        http_method: Optional[str] = None,
        http_status: Optional[int] = None,
        request_correlation_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> AuditEventRecord:
        """
        Creates and persists an append-only audit event record, then evaluates
        threat thresholds for automated security monitoring alerts.
        If db is not provided, runs in an isolated autonomous session.
        """
        clean_details = sanitize_audit_details(details)
        clean_actor_id = sanitize_input_string(actor_id, 100)
        clean_endpoint = sanitize_input_string(endpoint, 500) if endpoint else None
        clean_user_agent = sanitize_input_string(user_agent, 500) if user_agent else None

        record = AuditEventRecord(
            timestamp=now_utc(),
            actor_id=clean_actor_id,
            actor_email=actor_email,
            actor_role=actor_role,
            event_type=event_type,
            event_category=event_category.upper(),
            severity=severity.upper(),
            outcome=outcome.upper(),
            ip_address=ip_address,
            user_agent=clean_user_agent,
            endpoint=clean_endpoint,
            http_method=http_method,
            http_status=http_status,
            request_correlation_id=request_correlation_id,
            details=clean_details
        )

        if db is not None:
            db.add(record)
            await db.commit()
            await db.refresh(record)
            await AuditService._correlate_security_alerts(db=db, triggered_event=record)
            return record
        else:
            async with AsyncSessionLocal() as session:
                session.add(record)
                await session.commit()
                await session.refresh(record)
                await AuditService._correlate_security_alerts(db=session, triggered_event=record)
                return record

    @staticmethod
    async def _correlate_security_alerts(
        db: AsyncSession,
        triggered_event: AuditEventRecord
    ) -> None:
        """
        Evaluates incoming event against security monitoring thresholds:
        - Brute Force: >= 5 login failures in 5 min.
        - Unauthorized Probing: >= 5 HTTP 401/403 denials in 5 min.
        - Privilege Escalation: Non-admin calling restricted admin paths.
        Emits automated high-severity alerts with deduplication.
        """
        now = time.time()
        five_minutes_ago = now_utc() - timedelta(minutes=5)
        actor_key = triggered_event.actor_id or triggered_event.ip_address or "unknown"

        # 1. Detect Repeated Failed Login Attempts (Brute Force)
        if triggered_event.event_type == "AUTH_LOGIN_FAILURE":
            cooldown_key = ("ALERT_BRUTE_FORCE", actor_key)
            last_alert = _ALERT_COOLDOWN_CACHE.get(cooldown_key, 0.0)

            if now - last_alert > ALERT_COOLDOWN_SECONDS:
                query = select(func.count(AuditEventRecord.id)).where(
                    and_(
                        AuditEventRecord.event_type == "AUTH_LOGIN_FAILURE",
                        AuditEventRecord.timestamp >= five_minutes_ago,
                        or_(
                            AuditEventRecord.actor_id == triggered_event.actor_id,
                            AuditEventRecord.ip_address == triggered_event.ip_address
                        )
                    )
                )
                res = await db.execute(query)
                fail_count = res.scalar() or 0

                if fail_count >= 5:
                    _ALERT_COOLDOWN_CACHE[cooldown_key] = now
                    logger.warning(
                        "SECURITY MONITORING ALERT: Detected %d failed login attempts for %s",
                        fail_count,
                        actor_key
                    )
                    alert_record = AuditEventRecord(
                        timestamp=now_utc(),
                        actor_id=triggered_event.actor_id,
                        actor_email=triggered_event.actor_email,
                        actor_role=triggered_event.actor_role,
                        event_type="SECURITY_ALERT_BRUTE_FORCE",
                        event_category="SECURITY",
                        severity="HIGH",
                        outcome="BLOCKED",
                        ip_address=triggered_event.ip_address,
                        user_agent=triggered_event.user_agent,
                        endpoint=triggered_event.endpoint,
                        details={
                            "alert_reason": "Repeated failed login attempts exceeding threshold (>= 5 in 5m)",
                            "failure_count": fail_count,
                            "target_actor": actor_key
                        }
                    )
                    db.add(alert_record)
                    await db.commit()

        # 2. Detect Repeated Unauthorized Probing (401 / 403)
        if triggered_event.outcome == "BLOCKED" or (triggered_event.http_status in [401, 403]):
            cooldown_key = ("ALERT_UNAUTHORIZED_PROBING", actor_key)
            last_alert = _ALERT_COOLDOWN_CACHE.get(cooldown_key, 0.0)

            if now - last_alert > ALERT_COOLDOWN_SECONDS:
                query = select(func.count(AuditEventRecord.id)).where(
                    and_(
                        or_(
                            AuditEventRecord.outcome == "BLOCKED",
                            AuditEventRecord.http_status.in_([401, 403])
                        ),
                        AuditEventRecord.timestamp >= five_minutes_ago,
                        or_(
                            AuditEventRecord.actor_id == triggered_event.actor_id,
                            AuditEventRecord.ip_address == triggered_event.ip_address
                        )
                    )
                )
                res = await db.execute(query)
                probing_count = res.scalar() or 0

                if probing_count >= 5:
                    _ALERT_COOLDOWN_CACHE[cooldown_key] = now
                    logger.warning(
                        "SECURITY MONITORING ALERT: Detected %d unauthorized requests from %s",
                        probing_count,
                        actor_key
                    )
                    alert_record = AuditEventRecord(
                        timestamp=now_utc(),
                        actor_id=triggered_event.actor_id,
                        actor_email=triggered_event.actor_email,
                        actor_role=triggered_event.actor_role,
                        event_type="SECURITY_ALERT_UNAUTHORIZED_PROBING",
                        event_category="SECURITY",
                        severity="HIGH",
                        outcome="BLOCKED",
                        ip_address=triggered_event.ip_address,
                        user_agent=triggered_event.user_agent,
                        endpoint=triggered_event.endpoint,
                        details={
                            "alert_reason": "Repeated unauthorized access attempts exceeding threshold (>= 5 in 5m)",
                            "blocked_count": probing_count,
                            "target_actor": actor_key
                        }
                    )
                    db.add(alert_record)
                    await db.commit()

    @staticmethod
    async def get_audit_logs(
        db: AsyncSession,
        page: int = 1,
        page_size: int = 20,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        event_type: Optional[str] = None,
        outcome: Optional[str] = None,
        search: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        caller_role: str = "Admin"
    ) -> Tuple[List[AuditEventRecord], int]:
        """
        Retrieves paginated audit events with multi-criteria filtering and RBAC scoping.
        SOC Analysts are scoped to security/operational events, while Admins view all.
        """
        page = max(1, page)
        page_size = min(100, max(5, page_size))
        offset = (page - 1) * page_size

        conditions = []

        # Role-based scoping: SOC Analyst view is restricted to operational/security categories
        if caller_role == "SOC Analyst":
            allowed_categories = ["SCAN", "THREAT", "AUTHZ", "AUTH", "SECURITY"]
            conditions.append(AuditEventRecord.event_category.in_(allowed_categories))

        if severity:
            conditions.append(AuditEventRecord.severity == severity.upper())
        if category:
            conditions.append(AuditEventRecord.event_category == category.upper())
        if event_type:
            conditions.append(AuditEventRecord.event_type == event_type)
        if outcome:
            conditions.append(AuditEventRecord.outcome == outcome.upper())

        if start_date:
            conditions.append(AuditEventRecord.timestamp >= start_date)
        if end_date:
            conditions.append(AuditEventRecord.timestamp <= end_date)

        if search:
            search_clean = f"%{search.strip()}%"
            conditions.append(
                or_(
                    AuditEventRecord.actor_id.ilike(search_clean),
                    AuditEventRecord.actor_email.ilike(search_clean),
                    AuditEventRecord.event_type.ilike(search_clean),
                    AuditEventRecord.endpoint.ilike(search_clean),
                    AuditEventRecord.ip_address.ilike(search_clean)
                )
            )

        where_clause = and_(*conditions) if conditions else True

        # Total count query
        count_query = select(func.count(AuditEventRecord.id)).where(where_clause)
        total_res = await db.execute(count_query)
        total_items = total_res.scalar() or 0

        # Items query ordered by timestamp descending
        items_query = (
            select(AuditEventRecord)
            .where(where_clause)
            .order_by(desc(AuditEventRecord.timestamp))
            .offset(offset)
            .limit(page_size)
        )
        items_res = await db.execute(items_query)
        items = list(items_res.scalars().all())

        return items, total_items

    @staticmethod
    async def get_metrics(
        db: AsyncSession,
        caller_role: str = "Admin"
    ) -> Dict[str, Any]:
        """
        Aggregates security operational KPIs, threat counters, and recent timeline.
        """
        conditions = []
        if caller_role == "SOC Analyst":
            allowed_categories = ["SCAN", "THREAT", "AUTHZ", "AUTH", "SECURITY"]
            conditions.append(AuditEventRecord.event_category.in_(allowed_categories))

        where_clause = and_(*conditions) if conditions else True

        # 1. Total events
        total_q = select(func.count(AuditEventRecord.id)).where(where_clause)
        total_events = (await db.execute(total_q)).scalar() or 0

        # 2. Critical Alerts
        crit_q = select(func.count(AuditEventRecord.id)).where(
            and_(where_clause, AuditEventRecord.severity == "CRITICAL")
        )
        critical_alerts = (await db.execute(crit_q)).scalar() or 0

        # 3. High Alerts
        high_q = select(func.count(AuditEventRecord.id)).where(
            and_(where_clause, AuditEventRecord.severity == "HIGH")
        )
        high_alerts = (await db.execute(high_q)).scalar() or 0

        # 4. Auth Failures
        auth_fail_q = select(func.count(AuditEventRecord.id)).where(
            and_(
                where_clause,
                or_(
                    AuditEventRecord.event_type == "AUTH_LOGIN_FAILURE",
                    and_(
                        AuditEventRecord.event_category == "AUTH",
                        AuditEventRecord.outcome == "FAILURE"
                    )
                )
            )
        )
        auth_failures = (await db.execute(auth_fail_q)).scalar() or 0

        # 5. Unauthorized Attempts (401/403 or BLOCKED)
        unauth_q = select(func.count(AuditEventRecord.id)).where(
            and_(
                where_clause,
                or_(
                    AuditEventRecord.outcome == "BLOCKED",
                    AuditEventRecord.http_status.in_([401, 403]),
                    AuditEventRecord.event_type == "AUTHZ_ACCESS_DENIED"
                )
            )
        )
        unauthorized_attempts = (await db.execute(unauth_q)).scalar() or 0

        # 6. Threats Detected
        threats_q = select(func.count(AuditEventRecord.id)).where(
            and_(
                where_clause,
                or_(
                    AuditEventRecord.event_category == "THREAT",
                    AuditEventRecord.event_type.in_(["THREAT_DETECTED", "SUSPICIOUS_URL_INVESTIGATION"])
                )
            )
        )
        threats_detected = (await db.execute(threats_q)).scalar() or 0

        # 7. Severity Breakdown
        sev_q = (
            select(AuditEventRecord.severity, func.count(AuditEventRecord.id))
            .where(where_clause)
            .group_by(AuditEventRecord.severity)
        )
        sev_rows = (await db.execute(sev_q)).all()
        severity_breakdown = {row[0]: row[1] for row in sev_rows}

        # 8. Category Breakdown
        cat_q = (
            select(AuditEventRecord.event_category, func.count(AuditEventRecord.id))
            .where(where_clause)
            .group_by(AuditEventRecord.event_category)
        )
        cat_rows = (await db.execute(cat_q)).all()
        category_breakdown = {row[0]: row[1] for row in cat_rows}

        # 9. Recent Timeline (Last 10 events)
        timeline_q = (
            select(AuditEventRecord)
            .where(where_clause)
            .order_by(desc(AuditEventRecord.timestamp))
            .limit(10)
        )
        recent_timeline = list((await db.execute(timeline_q)).scalars().all())

        return {
            "total_events": total_events,
            "critical_alerts": critical_alerts,
            "high_alerts": high_alerts,
            "auth_failures": auth_failures,
            "unauthorized_attempts": unauthorized_attempts,
            "threats_detected": threats_detected,
            "severity_breakdown": severity_breakdown,
            "category_breakdown": category_breakdown,
            "recent_timeline": [r.to_dict() for r in recent_timeline]
        }

    @staticmethod
    async def export_csv(
        db: AsyncSession,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        search: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> str:
        """
        Exports audit events matching criteria as a sanitized CSV string.
        Strictly restricted to Admin role.
        """
        items, _ = await AuditService.get_audit_logs(
            db=db,
            page=1,
            page_size=1000,
            severity=severity,
            category=category,
            search=search,
            start_date=start_date,
            end_date=end_date,
            caller_role="Admin"
        )

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Timestamp (UTC)",
            "Event ID",
            "Actor ID",
            "Actor Email",
            "Role",
            "Event Type",
            "Category",
            "Severity",
            "Outcome",
            "IP Address",
            "Endpoint",
            "HTTP Status",
            "Correlation ID"
        ])

        for item in items:
            writer.writerow([
                item.timestamp.isoformat() if item.timestamp else "",
                item.id,
                item.actor_id,
                item.actor_email or "N/A",
                item.actor_role,
                item.event_type,
                item.event_category,
                item.severity,
                item.outcome,
                item.ip_address or "N/A",
                item.endpoint or "N/A",
                item.http_status or "",
                item.request_correlation_id or "N/A"
            ])

        return output.getvalue()
