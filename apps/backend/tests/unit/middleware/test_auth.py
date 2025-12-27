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
def mock_ctx():
    """Creates a mock RequestContext."""
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


class TestRequireFingerprint:
    """Tests for require_fingerprint dependency."""
    
    def test_returns_400_if_fingerprint_missing(self):
        """Verify 400 error when fingerprint is missing (JS disabled)."""
        from src.middleware.auth import require_fingerprint
        from src.middleware.context import RequestContext
        from fastapi import HTTPException
        
        ctx = RequestContext(
            fingerprint_raw=None,
            fingerprint_hash=None,
            ip_address="127.0.0.1",
            user_agent="Test",
            login_flow_id=None,
        )
        
        with pytest.raises(HTTPException) as exc:
            require_fingerprint(ctx)
        
        assert exc.value.status_code == 400
        assert "JavaScript" in exc.value.detail

    def test_returns_hash_if_fingerprint_present(self):
        """Verify fingerprint hash is returned when present."""
        from src.middleware.auth import require_fingerprint
        from src.middleware.context import RequestContext
        
        ctx = RequestContext(
            fingerprint_raw="test-raw",
            fingerprint_hash="abc123def456",
            ip_address="127.0.0.1",
            user_agent="Test",
            login_flow_id=None,
        )
        
        result = require_fingerprint(ctx)
        
        assert result == "abc123def456"


class TestGetCurrentSession:
    """Tests for get_current_session dependency."""
    
    async def test_returns_401_if_cookie_missing(self, mock_request, mock_ctx, mock_db):
        """Verify 401 when session cookie is missing."""
        from src.middleware.auth import get_current_session
        from fastapi import HTTPException
        
        mock_request.cookies = {}
        
        with pytest.raises(HTTPException) as exc:
            await get_current_session(mock_request, mock_ctx, mock_db)
        
        assert exc.value.status_code == 401
        assert "authenticated" in exc.value.detail.lower()

    async def test_returns_401_if_cookie_invalid_uuid(self, mock_request, mock_ctx, mock_db):
        """Verify 401 when session cookie is not a valid UUID."""
        from src.middleware.auth import get_current_session
        from src.core.cookies import SESSION_COOKIE_NAME
        from fastapi import HTTPException
        
        mock_request.cookies = {SESSION_COOKIE_NAME: "not-a-valid-uuid"}
        
        with pytest.raises(HTTPException) as exc:
            await get_current_session(mock_request, mock_ctx, mock_db)
        
        assert exc.value.status_code == 401
        assert "invalid" in exc.value.detail.lower()

    async def test_returns_401_if_session_not_found(self, mock_request, mock_ctx, mock_db):
        """Verify 401 when session ID doesn't exist in database."""
        from src.middleware.auth import get_current_session
        from src.core.cookies import SESSION_COOKIE_NAME
        from fastapi import HTTPException
        
        session_id = str(uuid4())
        mock_request.cookies = {SESSION_COOKIE_NAME: session_id}
        
        with patch("src.middleware.auth.get_session_by_id", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = None
            
            with pytest.raises(HTTPException) as exc:
                await get_current_session(mock_request, mock_ctx, mock_db)
            
            assert exc.value.status_code == 401

    async def test_returns_session_on_valid_cookie(self, mock_request, mock_ctx, mock_db):
        """Verify session is returned when cookie is valid."""
        from src.middleware.auth import get_current_session
        from src.core.cookies import SESSION_COOKIE_NAME
        
        session_id = uuid4()
        mock_request.cookies = {SESSION_COOKIE_NAME: str(session_id)}
        
        mock_session = MagicMock()
        mock_session.id = session_id
        mock_session.fingerprint = mock_ctx.fingerprint_hash
        mock_session.expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        
        with patch("src.middleware.auth.get_session_by_id", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_session
            
            result = await get_current_session(mock_request, mock_ctx, mock_db)
            
            assert result == mock_session

    async def test_flags_fingerprint_changed_when_mismatch(self, mock_request, mock_ctx, mock_db):
        """Verify fingerprint change is flagged but session is still returned."""
        from src.middleware.auth import get_current_session
        from src.core.cookies import SESSION_COOKIE_NAME
        
        session_id = uuid4()
        mock_request.cookies = {SESSION_COOKIE_NAME: str(session_id)}
        
        mock_session = MagicMock()
        mock_session.id = session_id
        mock_session.fingerprint = "different_fingerprint_hash"  # Different from ctx
        mock_session.expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        
        with patch("src.middleware.auth.get_session_by_id", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_session
            
            result = await get_current_session(mock_request, mock_ctx, mock_db)
            
            # Session is returned
            assert result == mock_session
            # Fingerprint change is flagged
            assert mock_request.state.fingerprint_changed is True

    async def test_does_not_flag_when_fingerprint_matches(self, mock_request, mock_ctx, mock_db):
        """Verify no flag when fingerprints match."""
        from src.middleware.auth import get_current_session
        from src.core.cookies import SESSION_COOKIE_NAME
        
        session_id = uuid4()
        mock_request.cookies = {SESSION_COOKIE_NAME: str(session_id)}
        
        mock_session = MagicMock()
        mock_session.id = session_id
        mock_session.fingerprint = mock_ctx.fingerprint_hash  # Same as ctx
        
        with patch("src.middleware.auth.get_session_by_id", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_session
            
            await get_current_session(mock_request, mock_ctx, mock_db)
            
            assert mock_request.state.fingerprint_changed is False

    async def test_does_not_flag_when_no_fingerprint_provided(self, mock_request, mock_db):
        """Verify no flag when request has no fingerprint (graceful degradation)."""
        from src.middleware.auth import get_current_session
        from src.middleware.context import RequestContext
        from src.core.cookies import SESSION_COOKIE_NAME
        
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
            
            await get_current_session(mock_request, ctx_no_fingerprint, mock_db)
            
            # No flag because we can't compare (None != stored_hash is False)
            assert mock_request.state.fingerprint_changed is False


class TestSessionCookieSyncMiddleware:
    """Tests for session_cookie_sync_middleware."""
    
    async def test_injects_cookie_when_expires_at_in_state(self):
        """Verify cookie is injected when session was refreshed."""
        from src.middleware.auth import session_cookie_sync_middleware
        
        mock_request = MagicMock()
        mock_request.state = MagicMock()
        mock_request.state.session_expires_at = datetime.now(timezone.utc) + timedelta(days=7)
        mock_request.state.session_id = str(uuid4())
        
        mock_response = MagicMock()
        mock_call_next = AsyncMock(return_value=mock_response)
        
        with patch("src.middleware.auth.create_session_cookie") as mock_cookie:
            result = await session_cookie_sync_middleware(mock_request, mock_call_next)
            
            mock_cookie.assert_called_once()
            assert result == mock_response

    async def test_does_not_modify_response_when_no_state(self):
        """Verify response is unchanged when no session refresh occurred."""
        from src.middleware.auth import session_cookie_sync_middleware
        
        mock_request = MagicMock()
        mock_request.state = MagicMock(spec=[])  # Empty spec = no attributes
        
        mock_response = MagicMock()
        mock_call_next = AsyncMock(return_value=mock_response)
        
        with patch("src.middleware.auth.create_session_cookie") as mock_cookie:
            result = await session_cookie_sync_middleware(mock_request, mock_call_next)
            
            mock_cookie.assert_not_called()
            assert result == mock_response
