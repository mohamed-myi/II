"""
Cookie Security Tests - Attribute Policing

Tests use real FastAPI Response objects and inspect actual header values.
No mocking of the cookie-setting logic - we verify the actual output.

Focus areas:
- HttpOnly, Secure, SameSite enforcement (exact matches)
- Production vs Development flag switching
- Max-Age / Expires consistency
- Login flow cookie TTL
"""
import os
from datetime import datetime, timezone, timedelta
from unittest.mock import patch

from fastapi import Response

from src.core.cookies import (
    create_session_cookie,
    clear_session_cookie,
    create_login_flow_cookie,
    SESSION_COOKIE_NAME,
    LOGIN_FLOW_COOKIE_NAME,
)


def parse_set_cookie(response: Response, cookie_name: str) -> dict:
    """
    Parse Set-Cookie header into attributes dict.
    Returns exact attribute values for policing.
    
    Manual parsing because SimpleCookie doesn't handle boolean flags well.
    Note: FastAPI puts each cookie in a separate header, not comma-separated.
    """
    # FastAPI Response stores raw_headers as list of tuples
    raw = ""
    for key, value in response.raw_headers:
        if key.decode().lower() == "set-cookie" and value.decode().startswith(f"{cookie_name}="):
            raw = value.decode()
            break
    
    if not raw:
        return {}
    
    parts = raw.split("; ")
    value = parts[0].split("=", 1)[1].strip('"')
    
    result = {
        "value": value,
        "httponly": False,
        "secure": False,
        "samesite": "",
        "path": "",
        "max-age": "",
        "expires": "",
    }
    
    for part in parts[1:]:
        lower = part.lower()
        if lower == "httponly":
            result["httponly"] = True
        elif lower == "secure":
            result["secure"] = True
        elif lower.startswith("samesite="):
            result["samesite"] = part.split("=", 1)[1]
        elif lower.startswith("path="):
            result["path"] = part.split("=", 1)[1]
        elif lower.startswith("max-age="):
            result["max-age"] = part.split("=", 1)[1]
        elif lower.startswith("expires="):
            result["expires"] = part.split("=", 1)[1]
    
    return result


class TestSessionCookieSecurityAttributes:
    """
    SECURITY: Verify exact cookie attributes.
    HttpOnly and SameSite=Lax are REQUIRED in all environments.
    Secure is REQUIRED in production.
    """
    
    def test_httponly_always_set(self):
        """HttpOnly prevents XSS cookie theft - must ALWAYS be True."""
        with patch.dict(os.environ, {"ENVIRONMENT": "development"}):
            from src.core.config import get_settings
            get_settings.cache_clear()
            
            response = Response()
            create_session_cookie(response, "test-session-id")
            
            attrs = parse_set_cookie(response, SESSION_COOKIE_NAME)
            
            # EXACT MATCH - not contains, not truthy
            assert attrs["httponly"] is True, "HttpOnly MUST be True to prevent XSS"
            get_settings.cache_clear()
    
    def test_samesite_lax_enforced(self):
        """SameSite=Lax prevents CSRF - must be exactly 'lax' or 'Lax'."""
        with patch.dict(os.environ, {"ENVIRONMENT": "development"}):
            from src.core.config import get_settings
            get_settings.cache_clear()
            
            response = Response()
            create_session_cookie(response, "test-session-id")
            
            attrs = parse_set_cookie(response, SESSION_COOKIE_NAME)
            
            # Case-insensitive but must be lax (never None or Strict for OAuth flows)
            assert attrs["samesite"].lower() == "lax", \
                f"SameSite must be 'lax', got '{attrs['samesite']}'"
            get_settings.cache_clear()
    
    def test_secure_true_in_production(self):
        """Secure=True in production prevents cookie over HTTP."""
        with patch.dict(os.environ, {"ENVIRONMENT": "production"}):
            from src.core.config import get_settings
            get_settings.cache_clear()
            
            response = Response()
            create_session_cookie(response, "test-session-id")
            
            attrs = parse_set_cookie(response, SESSION_COOKIE_NAME)
            
            assert attrs["secure"] is True, \
                "Secure MUST be True in production to prevent HTTP leakage"
            get_settings.cache_clear()
    
    def test_secure_false_in_development(self):
        """Secure=False in development allows localhost testing."""
        with patch.dict(os.environ, {"ENVIRONMENT": "development"}):
            from src.core.config import get_settings
            get_settings.cache_clear()
            
            response = Response()
            create_session_cookie(response, "test-session-id")
            
            attrs = parse_set_cookie(response, SESSION_COOKIE_NAME)
            
            # In dev, Secure should be False or empty string
            assert attrs["secure"] in (False, ""), \
                "Secure should be False in development for localhost testing"
            get_settings.cache_clear()
    
    def test_path_is_root(self):
        """Path=/ ensures cookie sent on all routes."""
        with patch.dict(os.environ, {"ENVIRONMENT": "development"}):
            from src.core.config import get_settings
            get_settings.cache_clear()
            
            response = Response()
            create_session_cookie(response, "test-session-id")
            
            attrs = parse_set_cookie(response, SESSION_COOKIE_NAME)
            
            assert attrs["path"] == "/", "Path must be '/' for site-wide access"
            get_settings.cache_clear()


class TestSessionCookieExpiration:
    """
    Expiration handling - Max-Age vs Expires consistency.
    """
    
    def test_expires_set_when_provided(self):
        """When expires_at is provided, cookie expires at that timestamp."""
        with patch.dict(os.environ, {"ENVIRONMENT": "development"}):
            from src.core.config import get_settings
            get_settings.cache_clear()
            
            response = Response()
            expires_at = datetime.now(timezone.utc) + timedelta(days=7)
            create_session_cookie(response, "test-session-id", expires_at=expires_at)
            
            attrs = parse_set_cookie(response, SESSION_COOKIE_NAME)
            
            # Should have expires set (format varies by browser)
            assert attrs["expires"], "expires should be set when expires_at provided"
            get_settings.cache_clear()
    
    def test_session_cookie_when_no_expires(self):
        """No expires_at = session cookie (dies when browser closes)."""
        with patch.dict(os.environ, {"ENVIRONMENT": "development"}):
            from src.core.config import get_settings
            get_settings.cache_clear()
            
            response = Response()
            create_session_cookie(response, "test-session-id", expires_at=None)
            
            attrs = parse_set_cookie(response, SESSION_COOKIE_NAME)
            
            # Neither max-age nor expires should be set
            assert not attrs["expires"], "Session cookie should not have expires"
            assert not attrs["max-age"], "Session cookie should not have max-age"
            get_settings.cache_clear()


class TestClearSessionCookie:
    """Verify cookie deletion uses same security attributes."""
    
    def test_clear_uses_same_security_attributes(self):
        """Deletion must use matching attributes or cookie won't be cleared."""
        with patch.dict(os.environ, {"ENVIRONMENT": "production"}):
            from src.core.config import get_settings
            get_settings.cache_clear()
            
            response = Response()
            clear_session_cookie(response)
            
            attrs = parse_set_cookie(response, SESSION_COOKIE_NAME)
            
            # Must match creation attributes
            assert attrs["httponly"] is True
            assert attrs["samesite"].lower() == "lax"
            assert attrs["secure"] is True
            assert attrs["path"] == "/"
            get_settings.cache_clear()


class TestLoginFlowCookie:
    """Rate limiting flow ID cookie tests."""
    
    def test_max_age_is_300_seconds(self):
        """Login flow cookie expires in 5 minutes - prevents stale flows."""
        with patch.dict(os.environ, {"ENVIRONMENT": "development"}):
            from src.core.config import get_settings
            get_settings.cache_clear()
            
            response = Response()
            create_login_flow_cookie(response, "flow-123")
            
            attrs = parse_set_cookie(response, LOGIN_FLOW_COOKIE_NAME)
            
            # Exact match for max-age
            assert attrs["max-age"] == "300", \
                f"max-age must be exactly 300, got {attrs['max-age']}"
            get_settings.cache_clear()
    
    def test_httponly_protects_flow_id(self):
        """Flow ID is security-sensitive - must be HttpOnly."""
        with patch.dict(os.environ, {"ENVIRONMENT": "development"}):
            from src.core.config import get_settings
            get_settings.cache_clear()
            
            response = Response()
            create_login_flow_cookie(response, "flow-123")
            
            attrs = parse_set_cookie(response, LOGIN_FLOW_COOKIE_NAME)
            
            assert attrs["httponly"] is True
            get_settings.cache_clear()
    

    # NOTE: Constant value is self-documenting in code
