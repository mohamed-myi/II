"""Security events logged as JSON to stdout for GCP Cloud Logging ingestion"""
import json
import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from uuid import UUID

logger = logging.getLogger("audit")


class AuditEvent(str, Enum):
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    LOGOUT = "logout"
    LOGOUT_ALL = "logout_all"
    SESSION_CREATED = "session_created"
    SESSION_REVOKED = "session_revoked"
    SESSION_EVICTED = "session_evicted"
    SESSION_DEVIATION = "session_deviation"
    SESSION_KILLED = "session_killed"
    ACCOUNT_LINKED = "account_linked"
    RATE_LIMITED = "rate_limited"
    SEARCH = "search"
    SEARCH_INTERACTION = "search_interaction"


def log_audit_event(
    event: AuditEvent,
    user_id: Optional[UUID] = None,
    session_id: Optional[UUID] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    provider: Optional[str] = None,
    metadata: Optional[dict] = None,
) -> None:
    """Truncates user_agent to 256 chars"""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event.value,
        "user_id": str(user_id) if user_id else None,
        "session_id": str(session_id) if session_id else None,
        "ip_address": ip_address,
        "user_agent": user_agent[:256] if user_agent else None,
        "provider": provider,
    }
    
    if metadata:
        entry.update(metadata)
    
    entry = {k: v for k, v in entry.items() if v is not None}
    
    logger.info(json.dumps(entry))
