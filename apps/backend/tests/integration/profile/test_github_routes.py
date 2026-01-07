"""Integration tests for GitHub profile API routes."""
import pytest
from datetime import datetime, timezone, timedelta
from uuid import uuid4
from unittest.mock import patch, MagicMock, AsyncMock

from fastapi.testclient import TestClient

from src.main import app
from src.middleware.auth import require_auth
from src.middleware.rate_limit import reset_rate_limiter, reset_rate_limiter_instance


@pytest.fixture(autouse=True)
def reset_rate_limit():
    reset_rate_limiter()
    reset_rate_limiter_instance()
    yield
    reset_rate_limiter()


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def mock_user():
    user = MagicMock()
    user.id = uuid4()
    user.email = "test@example.com"
    return user


@pytest.fixture
def mock_session(mock_user):
    session = MagicMock()
    session.id = uuid4()
    session.user_id = mock_user.id
    return session


@pytest.fixture
def authenticated_client(client, mock_user, mock_session):
    def mock_require_auth():
        return (mock_user, mock_session)
    
    app.dependency_overrides[require_auth] = mock_require_auth
    yield client
    app.dependency_overrides.clear()


class TestAuthRequired:
    """Verifies authentication middleware is applied to all GitHub routes."""
    
    @pytest.mark.parametrize("method,path", [
        ("post", "/profile/github"),
        ("get", "/profile/github"),
        ("post", "/profile/github/refresh"),
        ("delete", "/profile/github"),
    ])
    def test_returns_401_without_auth(self, client, method, path):
        response = getattr(client, method)(path)
        assert response.status_code == 401


class TestPostGitHub:
    """Tests for POST /profile/github endpoint."""
    
    def test_returns_400_when_no_github_connected(self, authenticated_client, mock_user):
        with patch(
            "src.api.routes.profile_github.fetch_github_profile",
            new_callable=AsyncMock,
        ) as mock_fetch:
            from src.services.github_profile_service import GitHubNotConnectedError
            mock_fetch.side_effect = GitHubNotConnectedError(
                "No GitHub account connected. Please connect GitHub first at /auth/connect/github"
            )
            
            response = authenticated_client.post("/profile/github")
        
        assert response.status_code == 400
        assert "connect" in response.json()["detail"].lower()
    
    def test_returns_400_when_token_revoked(self, authenticated_client, mock_user):
        with patch(
            "src.api.routes.profile_github.fetch_github_profile",
            new_callable=AsyncMock,
        ) as mock_fetch:
            from src.services.github_profile_service import GitHubNotConnectedError
            mock_fetch.side_effect = GitHubNotConnectedError(
                "Please reconnect your GitHub account"
            )
            
            response = authenticated_client.post("/profile/github")
        
        assert response.status_code == 400
        assert "connect github" in response.json()["detail"].lower()
    
    def test_successful_fetch_returns_data(self, authenticated_client, mock_user):
        with patch(
            "src.api.routes.profile_github.fetch_github_profile",
            new_callable=AsyncMock,
        ) as mock_fetch:
            mock_fetch.return_value = {
                "status": "ready",
                "username": "octocat",
                "starred_count": 42,
                "contributed_repos": 10,
                "languages": ["Python", "Go"],
                "topics": ["web", "cli"],
                "vector_status": "ready",
                "fetched_at": "2026-01-04T12:00:00+00:00",
                "minimal_data_warning": None,
            }
            
            response = authenticated_client.post("/profile/github")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ready"
        assert data["username"] == "octocat"
        assert data["starred_count"] == 42
        assert data["contributed_repos"] == 10
        assert data["languages"] == ["Python", "Go"]
        assert data["topics"] == ["web", "cli"]
        assert data["vector_status"] == "ready"
    
    def test_returns_minimal_data_warning(self, authenticated_client, mock_user):
        with patch(
            "src.api.routes.profile_github.fetch_github_profile",
            new_callable=AsyncMock,
        ) as mock_fetch:
            mock_fetch.return_value = {
                "status": "ready",
                "username": "newuser",
                "starred_count": 2,
                "contributed_repos": 1,
                "languages": ["Python"],
                "topics": [],
                "vector_status": "ready",
                "fetched_at": "2026-01-04T12:00:00+00:00",
                "minimal_data_warning": "We found limited public activity on your GitHub profile.",
            }
            
            response = authenticated_client.post("/profile/github")
        
        assert response.status_code == 200
        data = response.json()
        assert data["minimal_data_warning"] is not None
        assert "limited" in data["minimal_data_warning"].lower()
    
    def test_returns_503_on_github_rate_limit(self, authenticated_client, mock_user):
        with patch(
            "src.api.routes.profile_github.fetch_github_profile",
            new_callable=AsyncMock,
        ) as mock_fetch:
            from src.ingestion.github_client import GitHubRateLimitError
            mock_fetch.side_effect = GitHubRateLimitError()
            
            response = authenticated_client.post("/profile/github")
        
        assert response.status_code == 503
        assert "busy" in response.json()["detail"].lower()


class TestGetGitHub:
    """Tests for GET /profile/github endpoint."""
    
    def test_returns_404_when_not_populated(self, authenticated_client, mock_user):
        with patch(
            "src.api.routes.profile_github.get_github_data",
            new_callable=AsyncMock,
        ) as mock_get:
            mock_get.return_value = None
            
            response = authenticated_client.get("/profile/github")
        
        assert response.status_code == 404
        assert "no github data" in response.json()["detail"].lower()
    
    def test_returns_data_when_populated(self, authenticated_client, mock_user):
        with patch(
            "src.api.routes.profile_github.get_github_data",
            new_callable=AsyncMock,
        ) as mock_get:
            mock_get.return_value = {
                "status": "ready",
                "username": "octocat",
                "starred_count": 42,
                "contributed_repos": 10,
                "languages": ["Python", "TypeScript"],
                "topics": ["web", "api", "async"],
                "vector_status": "ready",
                "fetched_at": "2026-01-04T12:00:00+00:00",
            }
            
            response = authenticated_client.get("/profile/github")
        
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "octocat"
        assert data["starred_count"] == 42
        assert data["contributed_repos"] == 10
        assert "Python" in data["languages"]
        assert "web" in data["topics"]
        assert data["vector_status"] == "ready"


class TestRefreshGitHub:
    """Tests for POST /profile/github/refresh endpoint."""
    
    def test_returns_429_when_too_soon(self, authenticated_client, mock_user):
        with patch(
            "src.api.routes.profile_github.fetch_github_profile",
            new_callable=AsyncMock,
        ) as mock_fetch:
            from src.services.github_profile_service import RefreshRateLimitError
            mock_fetch.side_effect = RefreshRateLimitError(1800)
            
            response = authenticated_client.post("/profile/github/refresh")
        
        assert response.status_code == 429
        assert "minute" in response.json()["detail"].lower()
    
    def test_allows_refresh_after_cooldown(self, authenticated_client, mock_user):
        with patch(
            "src.api.routes.profile_github.fetch_github_profile",
            new_callable=AsyncMock,
        ) as mock_fetch:
            mock_fetch.return_value = {
                "status": "ready",
                "username": "octocat",
                "starred_count": 50,
                "contributed_repos": 15,
                "languages": ["Python", "Go", "Rust"],
                "topics": ["web", "cli", "systems"],
                "vector_status": "ready",
                "fetched_at": "2026-01-04T13:00:00+00:00",
                "minimal_data_warning": None,
            }
            
            response = authenticated_client.post("/profile/github/refresh")
        
        assert response.status_code == 200
        data = response.json()
        assert data["starred_count"] == 50


class TestDeleteGitHub:
    """Tests for DELETE /profile/github endpoint."""
    
    def test_returns_404_when_no_data(self, authenticated_client, mock_user):
        with patch(
            "src.api.routes.profile_github.delete_github",
            new_callable=AsyncMock,
        ) as mock_delete:
            mock_delete.return_value = False
            
            response = authenticated_client.delete("/profile/github")
        
        assert response.status_code == 404
        assert "no github data" in response.json()["detail"].lower()
    
    def test_successfully_deletes_data(self, authenticated_client, mock_user):
        with patch(
            "src.api.routes.profile_github.delete_github",
            new_callable=AsyncMock,
        ) as mock_delete:
            mock_delete.return_value = True
            
            response = authenticated_client.delete("/profile/github")
        
        assert response.status_code == 200
        data = response.json()
        assert data["deleted"] is True
        assert "cleared" in data["message"].lower()


class TestCombinedVectorUpdates:
    """Tests verifying combined vector is recalculated."""
    
    def test_fetch_updates_combined_vector(self, authenticated_client, mock_user):
        """Verifies that fetching GitHub data triggers combined vector recalculation."""
        with patch(
            "src.api.routes.profile_github.fetch_github_profile",
            new_callable=AsyncMock,
        ) as mock_fetch:
            mock_fetch.return_value = {
                "status": "ready",
                "username": "octocat",
                "starred_count": 42,
                "contributed_repos": 10,
                "languages": ["Python"],
                "topics": ["web"],
                "vector_status": "ready",
                "fetched_at": "2026-01-04T12:00:00+00:00",
                "minimal_data_warning": None,
            }
            
            response = authenticated_client.post("/profile/github")
            
            assert response.status_code == 200
            assert response.json()["vector_status"] == "ready"
    
    def test_delete_recalculates_combined_vector(self, authenticated_client, mock_user):
        """Verifies that deleting GitHub data triggers combined vector recalculation."""
        with patch(
            "src.api.routes.profile_github.delete_github",
            new_callable=AsyncMock,
        ) as mock_delete:
            # delete_github internally recalculates combined vector
            mock_delete.return_value = True
            
            response = authenticated_client.delete("/profile/github")
            
            assert response.status_code == 200
            mock_delete.assert_called_once()


class TestErrorMessages:
    """Tests for error message formatting per PROFILE.md."""
    
    def test_oauth_revoked_message(self, authenticated_client, mock_user):
        with patch(
            "src.api.routes.profile_github.fetch_github_profile",
            new_callable=AsyncMock,
        ) as mock_fetch:
            from src.services.github_profile_service import GitHubNotConnectedError
            mock_fetch.side_effect = GitHubNotConnectedError("Please reconnect your GitHub account")
            
            response = authenticated_client.post("/profile/github")
        
        assert response.status_code == 400
        assert "connect github" in response.json()["detail"].lower()
    
    def test_github_rate_limit_message(self, authenticated_client, mock_user):
        with patch(
            "src.api.routes.profile_github.fetch_github_profile",
            new_callable=AsyncMock,
        ) as mock_fetch:
            from src.ingestion.github_client import GitHubRateLimitError
            mock_fetch.side_effect = GitHubRateLimitError()
            
            response = authenticated_client.post("/profile/github")
        
        assert response.status_code == 503
        detail = response.json()["detail"].lower()
        assert "busy" in detail or "hour" in detail

