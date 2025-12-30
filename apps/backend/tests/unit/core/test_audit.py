"""
Audit Logging Unit Tests

Tests the structured JSON audit logging for security events.
Verifies log format, field filtering, and all event types.
"""
import json
import logging
from datetime import datetime, timezone
from uuid import uuid4
from io import StringIO


from src.core.audit import log_audit_event, AuditEvent


class LogCapture:
    """Helper class to capture log output."""
    
    def __init__(self, logger_name: str):
        self.logger_name = logger_name
        self.buffer = StringIO()
        self.handler = logging.StreamHandler(self.buffer)
        self.handler.setLevel(logging.DEBUG)
        self.handler.setFormatter(logging.Formatter("%(message)s"))
        self.logger = logging.getLogger(logger_name)
        self._original_level = self.logger.level
        
    def __enter__(self):
        self.logger.addHandler(self.handler)
        self.logger.setLevel(logging.DEBUG)
        return self
    
    def __exit__(self, *args):
        self.logger.removeHandler(self.handler)
        self.logger.setLevel(self._original_level)
        self.buffer.close()
    
    def get_json(self) -> dict:
        """Get captured log output and parse as JSON."""
        self.buffer.seek(0)
        lines = [line.strip() for line in self.buffer.readlines() if line.strip()]
        if not lines:
            raise ValueError("No log output captured")
        # Return the last log entry
        return json.loads(lines[-1])



# NOTE: AuditEvent enum values are self-documenting; import failures catch changes



class TestLogAuditEvent:
    """Tests for the log_audit_event function."""
    
    def test_emits_valid_json(self):
        """Log output should be valid JSON."""
        with LogCapture("audit") as cap:
            log_audit_event(AuditEvent.LOGIN_SUCCESS)
            data = cap.get_json()
        
        assert "event" in data
        assert data["event"] == "login_success"
    
    def test_includes_timestamp(self):
        """Log should include ISO format timestamp."""
        with LogCapture("audit") as cap:
            log_audit_event(AuditEvent.LOGOUT)
            data = cap.get_json()
        
        assert "timestamp" in data
        # Should be parseable as ISO datetime
        ts = datetime.fromisoformat(data["timestamp"])
        assert ts.tzinfo == timezone.utc
    
    def test_includes_user_id_when_provided(self):
        """User ID should be included and stringified."""
        user_id = uuid4()
        
        with LogCapture("audit") as cap:
            log_audit_event(AuditEvent.LOGIN_SUCCESS, user_id=user_id)
            data = cap.get_json()
        
        assert data["user_id"] == str(user_id)
    
    def test_includes_session_id_when_provided(self):
        """Session ID should be included and stringified."""
        session_id = uuid4()
        
        with LogCapture("audit") as cap:
            log_audit_event(AuditEvent.SESSION_REVOKED, session_id=session_id)
            data = cap.get_json()
        
        assert data["session_id"] == str(session_id)
    
    def test_includes_ip_address(self):
        """IP address should be included when provided."""
        with LogCapture("audit") as cap:
            log_audit_event(AuditEvent.RATE_LIMITED, ip_address="203.0.113.50")
            data = cap.get_json()
        
        assert data["ip_address"] == "203.0.113.50"
    
    def test_truncates_long_user_agent(self):
        """User agent should be truncated to 256 characters."""
        long_ua = "A" * 500
        
        with LogCapture("audit") as cap:
            log_audit_event(AuditEvent.LOGIN_SUCCESS, user_agent=long_ua)
            data = cap.get_json()
        
        assert len(data["user_agent"]) == 256
        assert data["user_agent"] == "A" * 256
    
    def test_includes_provider(self):
        """Provider should be included for OAuth events."""
        with LogCapture("audit") as cap:
            log_audit_event(AuditEvent.ACCOUNT_LINKED, provider="github")
            data = cap.get_json()
        
        assert data["provider"] == "github"
    
    def test_includes_metadata(self):
        """Custom metadata should be merged into log entry."""
        with LogCapture("audit") as cap:
            log_audit_event(
                AuditEvent.LOGIN_FAILED,
                metadata={"reason": "email_not_verified", "attempts": 3}
            )
            data = cap.get_json()
        
        assert data["reason"] == "email_not_verified"
        assert data["attempts"] == 3
    
    def test_filters_none_values(self):
        """None values should be excluded from log output."""
        with LogCapture("audit") as cap:
            log_audit_event(
                AuditEvent.LOGOUT,
                user_id=None,
                session_id=None,
                ip_address=None,
                user_agent=None,
                provider=None,
            )
            data = cap.get_json()
        
        # Only timestamp and event should be present
        assert set(data.keys()) == {"timestamp", "event"}
    
    def test_complete_event_with_all_fields(self):
        """Test a complete event with all fields populated."""
        user_id = uuid4()
        session_id = uuid4()
        
        with LogCapture("audit") as cap:
            log_audit_event(
                AuditEvent.LOGIN_SUCCESS,
                user_id=user_id,
                session_id=session_id,
                ip_address="192.168.1.1",
                user_agent="Mozilla/5.0",
                provider="google",
                metadata={"remember_me": True},
            )
            data = cap.get_json()
        
        assert data["event"] == "login_success"
        assert data["user_id"] == str(user_id)
        assert data["session_id"] == str(session_id)
        assert data["ip_address"] == "192.168.1.1"
        assert data["user_agent"] == "Mozilla/5.0"
        assert data["provider"] == "google"
        assert data["remember_me"] is True
        assert "timestamp" in data
