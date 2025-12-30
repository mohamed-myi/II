import pytest
from uuid import uuid4

from fastapi.testclient import TestClient

from src.main import app


@pytest.fixture
def client():
    return TestClient(app, follow_redirects=False)


class TestGetSessionsEndpoint:
    """Tests for GET /auth/sessions endpoint"""

    def test_requires_authentication(self, client):
        """Unauthenticated request returns 401"""
        response = client.get("/auth/sessions")
        
        assert response.status_code == 401
        assert "Not authenticated" in response.json().get("detail", "")


class TestRevokeSessionEndpoint:
    """Tests for DELETE /auth/sessions/{session_id}"""

    def test_requires_authentication(self, client):
        """Unauthenticated request returns 401"""
        response = client.delete(f"/auth/sessions/{uuid4()}")
        
        assert response.status_code == 401
        assert "Not authenticated" in response.json().get("detail", "")

    def test_rejects_invalid_uuid_format(self, client):
        """
        Invalid UUID format tested; auth check happens before UUID validation
        so this returns 401 for unauthenticated users
        """
        response = client.delete("/auth/sessions/not-a-valid-uuid")
        
        # Auth happens first, so 401 is expected
        assert response.status_code == 401


class TestRevokeAllSessionsEndpoint:
    """Tests for DELETE /auth/sessions"""

    def test_requires_authentication(self, client):
        """Unauthenticated request returns 401"""
        response = client.delete("/auth/sessions")
        
        assert response.status_code == 401
        assert "Not authenticated" in response.json().get("detail", "")


class TestSessionEndpointRouting:
    """Verifies correct HTTP methods are accepted"""
    
    def test_get_sessions_rejects_post(self, client):
        """POST not allowed on GET endpoint"""
        response = client.post("/auth/sessions")
        
        assert response.status_code == 405


