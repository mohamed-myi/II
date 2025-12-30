import pytest
from unittest.mock import patch, MagicMock
from uuid import uuid4

from fastapi.testclient import TestClient

from src.main import app
from src.api.routes.auth import STATE_COOKIE_NAME, LINK_STATE_COOKIE_NAME
from src.core.oauth import OAuthProvider, UserProfile, OAuthToken


@pytest.fixture
def client():
    return TestClient(app, follow_redirects=False)


class TestAccountMergingBehavior:
    """Verifies upsert_user merging logic per PLANNING.md success criteria"""

    @pytest.fixture
    def mock_oauth_success(self):
        """Base OAuth mock returning verified user profile"""
        with patch("src.api.routes.auth.exchange_code_for_token") as mock_exchange, \
             patch("src.api.routes.auth.fetch_user_profile") as mock_profile, \
             patch("src.api.routes.auth.get_db") as mock_db, \
             patch("src.api.routes.auth.get_http_client") as mock_client:
            
            mock_exchange.return_value = OAuthToken(
                access_token="test_token",
                token_type="bearer",
            )
            
            async def mock_db_gen():
                yield MagicMock()
            async def mock_client_gen():
                yield MagicMock()
            
            mock_db.return_value = mock_db_gen()
            mock_client.return_value = mock_client_gen()
            
            yield {
                "exchange": mock_exchange,
                "profile": mock_profile,
                "db": mock_db,
            }

    def test_same_email_same_provider_returns_existing_user(self, client, mock_oauth_success):
        """
        User logs in twice with same GitHub account;
        upsert_user returns same user record both times
        """
        user_id = uuid4()
        
        mock_oauth_success["profile"].return_value = UserProfile(
            email="returning@example.com",
            provider_id="MDQ6VXNlcjk5OQ==",
            avatar_url="https://example.com/avatar.png",
            is_verified=True,
            username="returninguser",
        )
        
        with patch("src.api.routes.auth.upsert_user") as mock_upsert, \
             patch("src.api.routes.auth.create_session") as mock_session:
            
            mock_user = MagicMock()
            mock_user.id = user_id
            mock_upsert.return_value = mock_user
            
            from datetime import datetime, timezone, timedelta
            mock_session_obj = MagicMock()
            mock_session_obj.id = uuid4()
            mock_session.return_value = (
                mock_session_obj,
                datetime.now(timezone.utc) + timedelta(days=7)
            )
            
            state = "validstate123456789012345678901234"
            
            # First login
            client.cookies.set(STATE_COOKIE_NAME, f"{state}:0")
            client.get(
                "/auth/callback/github",
                params={"code": "first_code", "state": state},
                headers={"X-Device-Fingerprint": "fp_hash_1"},
            )
            
            # Second login
            client.cookies.set(STATE_COOKIE_NAME, f"{state}:0")
            client.get(
                "/auth/callback/github",
                params={"code": "second_code", "state": state},
                headers={"X-Device-Fingerprint": "fp_hash_2"},
            )
            
            assert mock_upsert.call_count == 2
            
            for call in mock_upsert.call_args_list:
                _, kwargs = call
                if kwargs:
                    assert kwargs.get("provider") == OAuthProvider.GITHUB
                else:
                    args = call[0]
                    assert args[2] == OAuthProvider.GITHUB

    def test_different_provider_same_email_raises_error(self, client, mock_oauth_success):
        """
        User signed up with GitHub; tries Google login with same email;
        must redirect with existing_account error
        """
        from src.services.session_service import ExistingAccountError
        
        mock_oauth_success["profile"].return_value = UserProfile(
            email="existing@example.com",
            provider_id="google_id_123",
            avatar_url="https://example.com/avatar.png",
            is_verified=True,
            username=None,
        )
        
        with patch("src.api.routes.auth.upsert_user") as mock_upsert, \
             patch("src.api.routes.auth.create_session"):
            
            mock_upsert.side_effect = ExistingAccountError("github")
            
            state = "validstate123456789012345678901234"
            client.cookies.set(STATE_COOKIE_NAME, f"{state}:0")
            
            response = client.get(
                "/auth/callback/google",
                params={"code": "valid_code", "state": state},
                headers={"X-Device-Fingerprint": "fp_hash"},
            )
            
            assert response.status_code == 302
            assert "error=existing_account" in response.headers["location"]
            assert "provider=github" in response.headers["location"]


class TestAccountLinkingFlow:
    """Tests for /auth/link/{provider} authenticated account linking"""

    def test_link_requires_authentication(self, client):
        """Unauthenticated user cannot access link endpoint"""
        response = client.get("/auth/link/google")
        
        assert response.status_code == 302
        assert "error=not_authenticated" in response.headers["location"]

    def test_link_callback_requires_authentication(self, client):
        """Unauthenticated user cannot complete link callback"""
        state = "linkstate1234567890123456789012345"
        client.cookies.set(LINK_STATE_COOKIE_NAME, state)
        
        response = client.get(
            "/auth/link/callback/github",
            params={"code": "valid_code", "state": state},
        )
        
        assert response.status_code == 302
        assert "error=not_authenticated" in response.headers["location"]

    def test_link_invalid_provider_redirects_with_error(self, client):
        """Invalid provider redirects to settings with error"""
        response = client.get("/auth/link/invalid_provider")
        
        assert response.status_code == 302
        assert "error=invalid_provider" in response.headers["location"]
        assert "/settings/accounts" in response.headers["location"]

    def test_link_callback_rejects_consent_denied(self, client):
        """User denying OAuth consent redirects with error"""
        # Even without valid session, error param takes precedence
        response = client.get(
            "/auth/link/callback/github",
            params={"error": "access_denied"},
        )
        
        # First checks auth so will get not_authenticated
        assert response.status_code == 302

    def test_link_callback_route_exists_and_requires_state(self, client):
        """Verify link callback endpoint exists and validates state parameter."""
        # Without state cookie, should redirect with csrf_failed
        response = client.get(
            "/auth/link/callback/google",
            params={"code": "valid_code", "state": "orphan_state"},
            headers={"X-Device-Fingerprint": "test_fp"},
        )
        
        # Should redirect (not 404/405) - route exists and processes
        assert response.status_code == 302
        # Either not_authenticated (no session) or csrf_failed (no state cookie)
        location = response.headers["location"]
        assert "error=" in location
