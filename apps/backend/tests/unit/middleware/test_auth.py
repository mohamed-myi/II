"""
Auth Middleware Tests - Security-Critical Tests Only

This module tests the core authentication and session management logic:
- Device fingerprint enforcement (anti-hijacking)
- Session validation
- Cookie synchronization for rolling window sessions

Tests are condensed using parametrization to avoid redundancy.
"""
import pytest
from datetime import datetime, timedelta, timezone
from uuid import uuid4
from unittest.mock import MagicMock, patch, AsyncMock
import os


@pytest.fixture(autouse=True)
def mock_settings():
    """Mock environment variables for all tests."""
    with patch.dict(os.environ, {
        "FINGERPRINT_SECRET": "test-fingerprint-secret-key-for-testing",
        "JWT_SECRET_KEY": "test-jwt-secret-key",
        "SESSION_REMEMBER_ME_DAYS": "7",
        "SESSION_DEFAULT_HOURS": "24",
    }):
        from src.core.config import get_settings
        get_settings.cache_clear()
        yield
        get_settings.cache_clear()


@pytest.fixture
def mock_request():
    """Creates a mock FastAPI Request."""
    request = MagicMock()
    request.headers = {}
    request.cookies = {}
    request.client = MagicMock()
    request.client.host = "127.0.0.1"
    request.state = MagicMock()
    return request


@pytest.fixture
def valid_ctx():
    """Creates a valid RequestContext with fingerprint."""
    from src.middleware.context import RequestContext
    return RequestContext(
        fingerprint_raw="test-fingerprint",
        fingerprint_hash="a" * 64,
        ip_address="127.0.0.1",
        user_agent="Test Browser",
        login_flow_id=None,
    )


@pytest.fixture
def mock_db():
    """Creates a mock AsyncSession."""
    db = AsyncMock()
    db.get = AsyncMock()
    return db


class TestFingerprintGating:
    """
    Tests for require_fingerprint dependency.
    
    Security: Enforces JavaScript requirement to prevent headless/bot attacks.
    """
    
    @pytest.mark.parametrize("fingerprint_hash,expected_status", [
        (None, 400),           # Missing fingerprint
        ("", 400),             # Falsy empty string (context sets hash to None)
        ("a" * 64, "PASS"),    # Valid hash
    ])
    def test_fingerprint_requirements(self, fingerprint_hash, expected_status):
        """Validates fingerprint gating with various inputs."""
        from src.middleware.auth import require_fingerprint
        from src.middleware.context import RequestContext
        from fastapi import HTTPException
        
        ctx = RequestContext(
            fingerprint_raw="raw-value" if fingerprint_hash else None,
            fingerprint_hash=fingerprint_hash if fingerprint_hash else None,
            ip_address="127.0.0.1",
            user_agent="Test",
            login_flow_id=None,
        )
        
        if expected_status == "PASS":
            result = require_fingerprint(ctx)
            assert result == fingerprint_hash
        else:
            with pytest.raises(HTTPException) as exc:
                require_fingerprint(ctx)
            assert exc.value.status_code == expected_status


class TestSessionValidation:
    """
    Core session validation tests.
    
    Security: Validates session exists and belongs to the same device.
    """
    
    async def test_returns_401_if_cookie_missing(self, mock_request, valid_ctx, mock_db):
        """No session cookie = not authenticated."""
        from src.middleware.auth import get_current_session
        from fastapi import HTTPException
        
        mock_request.cookies = {}
        
        with pytest.raises(HTTPException) as exc:
            await get_current_session(mock_request, valid_ctx, mock_db)
        
        assert exc.value.status_code == 401

    async def test_returns_401_if_session_not_found(self, mock_request, valid_ctx, mock_db):
        """Session ID not in database = invalid session."""
        from src.middleware.auth import get_current_session
        from src.core.cookies import SESSION_COOKIE_NAME
        from fastapi import HTTPException
        
        mock_request.cookies = {SESSION_COOKIE_NAME: str(uuid4())}
        
        with patch("src.middleware.auth.get_session_by_id", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = None
            
            with pytest.raises(HTTPException) as exc:
                await get_current_session(mock_request, valid_ctx, mock_db)
            
            assert exc.value.status_code == 401

    async def test_returns_session_on_valid_credentials(self, mock_request, valid_ctx, mock_db):
        """Valid session + matching fingerprint = success."""
        from src.middleware.auth import get_current_session
        from src.core.cookies import SESSION_COOKIE_NAME
        
        session_id = uuid4()
        mock_request.cookies = {SESSION_COOKIE_NAME: str(session_id)}
        
        mock_session = MagicMock()
        mock_session.id = session_id
        mock_session.fingerprint = valid_ctx.fingerprint_hash
        
        with patch("src.middleware.auth.get_session_by_id", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_session
            
            result = await get_current_session(mock_request, valid_ctx, mock_db)
            
            assert result == mock_session


class TestAntiHijacking:
    """
    CRITICAL: Session hijacking prevention tests.
    
    These tests prove that a session cookie stolen from one device
    cannot be used on another device (fingerprint mismatch).
    """
    
    async def test_returns_401_on_fingerprint_mismatch(self, mock_request, valid_ctx, mock_db):
        """
        ANTI-HIJACKING: Attacker steals cookie but has different fingerprint.
        Must return 401 to prevent unauthorized access.
        """
        from src.middleware.auth import get_current_session
        from src.core.cookies import SESSION_COOKIE_NAME
        from fastapi import HTTPException
        
        session_id = uuid4()
        mock_request.cookies = {SESSION_COOKIE_NAME: str(session_id)}
        
        mock_session = MagicMock()
        mock_session.id = session_id
        mock_session.fingerprint = "attacker_different_fingerprint"  # Mismatch!
        
        with patch("src.middleware.auth.get_session_by_id", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_session
            
            with pytest.raises(HTTPException) as exc:
                await get_current_session(mock_request, valid_ctx, mock_db)
            
            assert exc.value.status_code == 401
            assert "device" in exc.value.detail.lower()

    async def test_returns_401_when_request_missing_fingerprint(self, mock_request, mock_db):
        """
        Session has fingerprint but request doesn't provide one.
        Could indicate replay attack from different context.
        """
        from src.middleware.auth import get_current_session
        from src.middleware.context import RequestContext
        from src.core.cookies import SESSION_COOKIE_NAME
        from fastapi import HTTPException
        
        ctx_no_fingerprint = RequestContext(
            fingerprint_raw=None,
            fingerprint_hash=None,
            ip_address="127.0.0.1",
            user_agent="Test",
            login_flow_id=None,
        )
        
        session_id = uuid4()
        mock_request.cookies = {SESSION_COOKIE_NAME: str(session_id)}
        
        mock_session = MagicMock()
        mock_session.id = session_id
        mock_session.fingerprint = "stored_fingerprint"
        
        with patch("src.middleware.auth.get_session_by_id", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_session
            
            with pytest.raises(HTTPException) as exc:
                await get_current_session(mock_request, ctx_no_fingerprint, mock_db)
            
            assert exc.value.status_code == 401


class TestMaliciousInput:
    """
    Malformed/malicious cookie input handling.
    
    Proves that SQL injection, path traversal, and buffer overflow
    attempts in the cookie header are safely rejected.
    """
    
    @pytest.mark.parametrize("malicious_cookie", [
        "not-a-uuid",
        "../../etc/passwd",
        "' OR '1'='1",
        "a" * 10000,
        "\x00\x00\x00\x00",
        "<script>alert(1)</script>",
        "12345678-1234-1234-1234-1234567890ab; DROP TABLE sessions;--",
    ])
    async def test_malformed_input_returns_401(self, mock_request, valid_ctx, mock_db, malicious_cookie):
        """All malicious cookie values should safely return 401 before DB query."""
        from src.middleware.auth import get_current_session
        from src.core.cookies import SESSION_COOKIE_NAME
        from fastapi import HTTPException
        
        mock_request.cookies = {SESSION_COOKIE_NAME: malicious_cookie}
        
        with pytest.raises(HTTPException) as exc:
            await get_current_session(mock_request, valid_ctx, mock_db)
        
        assert exc.value.status_code == 401


class TestCookieSyncMiddleware:
    """
    Cookie synchronization middleware tests.
    
    Ensures the 7-day rolling window is maintained by updating
    the browser cookie when the session is refreshed.
    """
    
    async def test_injects_cookie_on_success_response(self):
        """Cookie injected when session refreshed and response is success."""
        from src.middleware.auth import session_cookie_sync_middleware
        
        mock_request = MagicMock()
        mock_request.state = MagicMock()
        mock_request.state.session_expires_at = datetime.now(timezone.utc) + timedelta(days=7)
        mock_request.state.session_id = str(uuid4())
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_call_next = AsyncMock(return_value=mock_response)
        
        with patch("src.middleware.auth.create_session_cookie") as mock_cookie:
            await session_cookie_sync_middleware(mock_request, mock_call_next)
            
            mock_cookie.assert_called_once()

    @pytest.mark.parametrize("status_code", [301, 302, 303, 307, 308])
    async def test_injects_cookie_on_redirect_responses(self, status_code):
        """
        CRITICAL FOR OAUTH: Cookie must be injected on redirect responses.
        After OAuth callback, user is redirected to dashboard with new session.
        """
        from src.middleware.auth import session_cookie_sync_middleware
        
        mock_request = MagicMock()
        mock_request.state = MagicMock()
        mock_request.state.session_expires_at = datetime.now(timezone.utc) + timedelta(days=7)
        mock_request.state.session_id = str(uuid4())
        
        mock_response = MagicMock()
        mock_response.status_code = status_code
        mock_call_next = AsyncMock(return_value=mock_response)
        
        with patch("src.middleware.auth.create_session_cookie") as mock_cookie:
            await session_cookie_sync_middleware(mock_request, mock_call_next)
            
            mock_cookie.assert_called_once()

    async def test_does_not_inject_cookie_on_error_response(self):
        """No cookie injection on error (prevents session fixation on failure)."""
        from src.middleware.auth import session_cookie_sync_middleware
        
        mock_request = MagicMock()
        mock_request.state = MagicMock()
        mock_request.state.session_expires_at = datetime.now(timezone.utc) + timedelta(days=7)
        mock_request.state.session_id = str(uuid4())
        
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_call_next = AsyncMock(return_value=mock_response)
        
        with patch("src.middleware.auth.create_session_cookie") as mock_cookie:
            await session_cookie_sync_middleware(mock_request, mock_call_next)
            
            mock_cookie.assert_not_called()
