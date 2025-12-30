"""
Rate Limiting Integration Tests

Tests the rate limiting behavior through the full HTTP request cycle.
"""
import pytest

from fastapi.testclient import TestClient

from src.main import app
from src.middleware.rate_limit import (
    reset_rate_limiter,
    reset_rate_limiter_instance,
)


@pytest.fixture(autouse=True)
def reset_limiter():
    """Reset rate limiter before each test."""
    reset_rate_limiter()
    reset_rate_limiter_instance()
    yield
    reset_rate_limiter()
    reset_rate_limiter_instance()


class TestRateLimitIntegration:
    """End-to-end tests for rate limiting on auth endpoints."""
    
    def test_rate_limit_triggers_on_11th_request(self):
        """Rate limit should trigger after 10 requests."""
        reset_rate_limiter()
        
        with TestClient(app) as client:
            for i in range(10):
                response = client.get(
                    "/auth/login/github",
                    headers={"X-Device-Fingerprint": "test_fp"},
                    follow_redirects=False,
                )
                assert response.status_code in [302, 307], f"Request {i+1} failed with {response.status_code}"
            
            # 11th request should be blocked
            response = client.get(
                "/auth/login/github",
                headers={"X-Device-Fingerprint": "test_fp"},
                follow_redirects=False,
            )
            
            assert response.status_code == 429
    
    def test_rate_limit_returns_retry_after_header(self):
        """429 response should include Retry-After header."""
        reset_rate_limiter()
        
        with TestClient(app) as client:
            for _ in range(10):
                client.get(
                    "/auth/login/github",
                    headers={"X-Device-Fingerprint": "test_fp"},
                    follow_redirects=False,
                )
            
            response = client.get(
                "/auth/login/github",
                headers={"X-Device-Fingerprint": "test_fp"},
                follow_redirects=False,
            )
            
            assert response.status_code == 429
            assert "retry-after" in response.headers
            assert int(response.headers["retry-after"]) > 0
    
    def test_different_flow_ids_are_isolated(self):
        """Different login flow IDs should have separate rate limits."""
        reset_rate_limiter()
        
        with TestClient(app, cookies={"login_flow_id": "flow_a"}) as client_a:
            # Exhaust limit for flow_a
            for _ in range(10):
                client_a.get(
                    "/auth/login/github",
                    headers={"X-Device-Fingerprint": "test_fp"},
                    follow_redirects=False,
                )
            
            # flow_a should be blocked
            response_a = client_a.get(
                "/auth/login/github",
                headers={"X-Device-Fingerprint": "test_fp"},
                follow_redirects=False,
            )
            assert response_a.status_code == 429
            
        # flow_b should still be allowed since compound key differs
        with TestClient(app, cookies={"login_flow_id": "flow_b"}) as client_b:
            response_b = client_b.get(
                "/auth/login/github",
                headers={"X-Device-Fingerprint": "test_fp"},
                follow_redirects=False,
            )
            assert response_b.status_code in [302, 307]


class TestInitLoginFlow:
    """Tests for the /auth/init endpoint."""
    
    def test_init_returns_204(self):
        """Init endpoint should return 204 No Content."""
        with TestClient(app) as client:
            response = client.get("/auth/init")
            assert response.status_code == 204
    
    def test_init_sets_login_flow_cookie(self):
        """Init endpoint should set login_flow_id cookie."""
        with TestClient(app) as client:
            response = client.get("/auth/init")
            
            assert "login_flow_id" in response.cookies
            assert len(response.cookies["login_flow_id"]) > 0
