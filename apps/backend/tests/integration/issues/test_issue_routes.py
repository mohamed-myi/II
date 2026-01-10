"""Integration tests for issue routes."""
import pytest
from datetime import datetime, timezone
from uuid import uuid4
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi.testclient import TestClient

from src.main import app
from src.middleware.auth import require_auth


@pytest.fixture
def client():
    """Create test client."""
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def mock_user():
    """Create mock user."""
    user = MagicMock()
    user.id = uuid4()
    user.email = "test@example.com"
    return user


@pytest.fixture
def mock_session(mock_user):
    """Create mock session."""
    session = MagicMock()
    session.id = uuid4()
    session.user_id = mock_user.id
    return session


@pytest.fixture
def authenticated_client(client, mock_user, mock_session):
    """Client with mocked authentication using dependency override."""
    def mock_require_auth():
        return (mock_user, mock_session)

    app.dependency_overrides[require_auth] = mock_require_auth
    yield client
    app.dependency_overrides.clear()


class TestAuthRequired:
    """Verifies authentication middleware is applied to issue routes."""

    @pytest.mark.parametrize("method,path", [
        ("get", "/issues/I_123"),
        ("get", "/issues/I_123/similar"),
    ])
    def test_returns_401_without_auth(self, client, method, path):
        response = getattr(client, method)(path)
        assert response.status_code == 401


class TestGetIssueDetail:
    """Tests for GET /issues/{node_id} endpoint."""

    def test_returns_issue_when_found(self, authenticated_client):
        """Should return full issue detail."""
        mock_issue = MagicMock()
        mock_issue.node_id = "I_abc123"
        mock_issue.title = "Fix memory leak"
        mock_issue.body = "Full body content"
        mock_issue.labels = ["bug", "memory"]
        mock_issue.q_score = 0.85
        mock_issue.repo_name = "facebook/react"
        mock_issue.repo_url = "https://github.com/facebook/react"
        mock_issue.github_url = "https://github.com/facebook/react/issues/123"
        mock_issue.primary_language = "JavaScript"
        mock_issue.github_created_at = datetime(2026, 1, 5, 10, 0, 0, tzinfo=timezone.utc)
        mock_issue.state = "open"
        
        with patch("src.api.routes.issues.get_issue_by_node_id", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_issue
            
            response = authenticated_client.get("/issues/I_abc123")
            
            assert response.status_code == 200
            data = response.json()
            assert data["node_id"] == "I_abc123"
            assert data["title"] == "Fix memory leak"
            assert data["labels"] == ["bug", "memory"]

    def test_returns_404_when_not_found(self, authenticated_client):
        """Should return 404 when issue doesn't exist."""
        with patch("src.api.routes.issues.get_issue_by_node_id", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = None
            
            response = authenticated_client.get("/issues/I_nonexistent")
            
            assert response.status_code == 404
            assert "Issue not found" in response.json()["detail"]


class TestGetSimilarIssues:
    """Tests for GET /issues/{node_id}/similar endpoint."""

    def test_returns_similar_issues(self, authenticated_client):
        """Should return list of similar issues."""
        similar1 = MagicMock()
        similar1.node_id = "I_similar1"
        similar1.title = "Related Issue"
        similar1.repo_name = "org/repo"
        similar1.similarity_score = 0.95
        
        with patch("src.api.routes.issues.get_similar_issues", new_callable=AsyncMock) as mock_similar:
            mock_similar.return_value = [similar1]
            
            response = authenticated_client.get("/issues/I_source/similar")
            
            assert response.status_code == 200
            data = response.json()
            assert len(data["issues"]) == 1
            assert data["issues"][0]["node_id"] == "I_similar1"
            assert data["issues"][0]["similarity_score"] == 0.95

    def test_returns_empty_list_when_no_embedding(self, authenticated_client):
        """Should return empty list when source has no embedding."""
        with patch("src.api.routes.issues.get_similar_issues", new_callable=AsyncMock) as mock_similar:
            mock_similar.return_value = []
            
            response = authenticated_client.get("/issues/I_noembedding/similar")
            
            assert response.status_code == 200
            assert response.json()["issues"] == []

    def test_returns_404_when_source_not_found(self, authenticated_client):
        """Should return 404 when source issue doesn't exist."""
        with patch("src.api.routes.issues.get_similar_issues", new_callable=AsyncMock) as mock_similar:
            mock_similar.return_value = None
            
            response = authenticated_client.get("/issues/I_nonexistent/similar")
            
            assert response.status_code == 404

    def test_respects_limit_parameter(self, authenticated_client):
        """Should pass limit parameter to service."""
        with patch("src.api.routes.issues.get_similar_issues", new_callable=AsyncMock) as mock_similar:
            mock_similar.return_value = []
            
            authenticated_client.get("/issues/I_source/similar?limit=3")
            
            mock_similar.assert_called_once()
            call_kwargs = mock_similar.call_args[1]
            assert call_kwargs["limit"] == 3

    def test_validates_limit_max(self, authenticated_client):
        """Should reject limit above max."""
        with patch("src.api.routes.issues.get_similar_issues", new_callable=AsyncMock) as mock_similar:
            mock_similar.return_value = []
            
            response = authenticated_client.get("/issues/I_source/similar?limit=100")
            
            assert response.status_code == 422
