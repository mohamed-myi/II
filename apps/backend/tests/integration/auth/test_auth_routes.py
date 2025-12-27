import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from urllib.parse import urlparse, parse_qs

from fastapi.testclient import TestClient
from httpx import AsyncClient

from src.main import app
from src.api.routes.auth import STATE_COOKIE_NAME
from src.core.oauth import OAuthProvider, UserProfile, OAuthToken


@pytest.fixture
def client():
    """Sync test client for redirect tests."""
    return TestClient(app, follow_redirects=False)


class TestLoginEndpoint:
    """Tests for GET /auth/login/{provider}"""

    def test_github_login_redirects_to_github(self, client):
        """Verify /auth/login/github redirects to GitHub authorize URL."""
        response = client.get("/auth/login/github")
        
        assert response.status_code == 302
        location = response.headers["location"]
        assert "github.com/login/oauth/authorize" in location
        assert "client_id=" in location
        assert "state=" in location

    def test_google_login_redirects_to_google(self, client):
        """Verify /auth/login/google redirects to Google authorize URL."""
        response = client.get("/auth/login/google")
        
        assert response.status_code == 302
        location = response.headers["location"]
        assert "accounts.google.com/o/oauth2/v2/auth" in location
        assert "client_id=" in location
        assert "state=" in location

    def test_login_sets_state_cookie(self, client):
        """Verify state cookie is set with HttpOnly flag."""
        response = client.get("/auth/login/github")
        
        assert STATE_COOKIE_NAME in response.cookies
        cookie = response.cookies[STATE_COOKIE_NAME]
        assert len(cookie) > 32  # state:remember_me format

    def test_login_with_remember_me(self, client):
        """Verify remember_me flag is encoded in state cookie."""
        response = client.get("/auth/login/github?remember_me=true")
        
        cookie_value = response.cookies[STATE_COOKIE_NAME]
        assert cookie_value.endswith(":1")

    def test_login_without_remember_me(self, client):
        """Verify remember_me=false is encoded in state cookie."""
        response = client.get("/auth/login/github?remember_me=false")
        
        cookie_value = response.cookies[STATE_COOKIE_NAME]
        assert cookie_value.endswith(":0")

    def test_invalid_provider_redirects_with_error(self, client):
        """Verify invalid provider redirects to login with error."""
        response = client.get("/auth/login/invalid_provider")
        
        assert response.status_code == 302
        location = response.headers["location"]
        assert "error=invalid_provider" in location


class TestCallbackEndpoint:
    """Tests for GET /auth/callback/{provider}"""

    def test_callback_rejects_missing_fingerprint(self, client):
        """Verify 400 when X-Device-Fingerprint header missing."""
        # Set required cookies
        client.cookies.set(STATE_COOKIE_NAME, "validstate123456789012345678901234:0")
        
        response = client.get(
            "/auth/callback/github",
            params={"code": "test_code", "state": "validstate123456789012345678901234"}
        )
        
        assert response.status_code == 400
        assert "JavaScript" in response.json().get("detail", "")

    def test_callback_rejects_missing_state(self, client):
        """Verify redirect with csrf_failed when state missing."""
        response = client.get(
            "/auth/callback/github",
            params={"code": "test_code"},
            headers={"X-Device-Fingerprint": "test_fingerprint"},
        )
        
        assert response.status_code == 302
        location = response.headers["location"]
        assert "error=csrf_failed" in location

    def test_callback_rejects_mismatched_state(self, client):
        """Verify redirect with csrf_failed when state mismatches cookie."""
        client.cookies.set(STATE_COOKIE_NAME, "stored_state_123456789012345678:0")
        
        response = client.get(
            "/auth/callback/github",
            params={"code": "test_code", "state": "different_state_901234567890123"},
            headers={"X-Device-Fingerprint": "test_fingerprint"},
        )
        
        assert response.status_code == 302
        location = response.headers["location"]
        assert "error=csrf_failed" in location

    def test_callback_handles_consent_denied(self, client):
        """Verify redirect when user denies OAuth consent."""
        response = client.get(
            "/auth/callback/github",
            params={"error": "access_denied"},
            headers={"X-Device-Fingerprint": "test_fingerprint"},
        )
        
        assert response.status_code == 302
        location = response.headers["location"]
        assert "error=consent_denied" in location

    def test_callback_rejects_invalid_provider(self, client):
        """Verify redirect with invalid_provider error."""
        response = client.get(
            "/auth/callback/invalid",
            params={"code": "test_code", "state": "test_state"},
            headers={"X-Device-Fingerprint": "test_fingerprint"},
        )
        
        assert response.status_code == 302
        location = response.headers["location"]
        assert "error=invalid_provider" in location


class TestCallbackSuccessFlow:
    """Tests for successful OAuth callback with mocked dependencies."""

    @pytest.fixture
    def mock_oauth_flow(self):
        """Mock all OAuth dependencies for success flow."""
        with patch("src.api.routes.auth.exchange_code_for_token") as mock_exchange, \
             patch("src.api.routes.auth.fetch_user_profile") as mock_profile, \
             patch("src.api.routes.auth.upsert_user") as mock_upsert, \
             patch("src.api.routes.auth.create_session") as mock_session, \
             patch("src.api.routes.auth.get_db") as mock_db, \
             patch("src.api.routes.auth.get_http_client") as mock_client:
            
            # Configure mock returns
            mock_exchange.return_value = OAuthToken(
                access_token="test_token",
                token_type="bearer",
            )
            mock_profile.return_value = UserProfile(
                email="test@example.com",
                provider_id="node_123",
                avatar_url="https://example.com/avatar.png",
                is_verified=True,
                username="testuser",
            )
            
            mock_user = MagicMock()
            mock_user.id = "00000000-0000-0000-0000-000000000001"
            mock_upsert.return_value = mock_user
            
            mock_session_obj = MagicMock()
            mock_session_obj.id = "00000000-0000-0000-0000-000000000002"
            from datetime import datetime, timezone, timedelta
            mock_expires = datetime.now(timezone.utc) + timedelta(days=7)
            mock_session.return_value = (mock_session_obj, mock_expires)
            
            # Mock async generators
            async def mock_db_gen():
                yield MagicMock()
            async def mock_client_gen():
                yield MagicMock()
            
            mock_db.return_value = mock_db_gen()
            mock_client.return_value = mock_client_gen()
            
            yield {
                "exchange": mock_exchange,
                "profile": mock_profile,
                "upsert": mock_upsert,
                "session": mock_session,
            }

    def test_callback_success_redirects_to_dashboard(self, client, mock_oauth_flow):
        """Verify successful callback redirects to /dashboard."""
        state = "validstate123456789012345678901234"
        client.cookies.set(STATE_COOKIE_NAME, f"{state}:0")
        
        response = client.get(
            "/auth/callback/github",
            params={"code": "valid_code", "state": state},
            headers={"X-Device-Fingerprint": "test_fingerprint"},
        )
        
        assert response.status_code == 302
        location = response.headers["location"]
        assert "/dashboard" in location

    def test_callback_success_sets_session_cookie(self, client, mock_oauth_flow):
        """Verify session cookie is set after successful auth."""
        state = "validstate123456789012345678901234"
        client.cookies.set(STATE_COOKIE_NAME, f"{state}:1")
        
        response = client.get(
            "/auth/callback/github",
            params={"code": "valid_code", "state": state},
            headers={"X-Device-Fingerprint": "test_fingerprint"},
        )
        
        assert "session_id" in response.cookies
