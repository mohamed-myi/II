
from fastapi.testclient import TestClient

from src.main import app


class TestLogout:
    def test_logout_returns_success_with_no_cookie(self):
        """Logout should succeed even without a session cookie"""
        with TestClient(app) as client:
            response = client.post("/auth/logout")
            
            assert response.status_code == 200
            assert response.json() == {"logged_out": True}
    
    def test_logout_returns_success_with_invalid_uuid(self):
        """Logout should succeed even with malformed session ID"""
        with TestClient(app, cookies={"session_id": "not-a-valid-uuid"}) as client:
            response = client.post("/auth/logout")
            
            assert response.status_code == 200
            assert response.json() == {"logged_out": True}


class TestLogoutAll:
    def test_logout_all_requires_authentication(self):
        """Logout all should return 401 without authentication"""
        with TestClient(app) as client:
            response = client.post("/auth/logout/all")
            
            assert response.status_code == 401
