import pytest
from unittest.mock import MagicMock, patch
import os


@pytest.fixture(autouse=True)
def mock_settings():
    """Mock environment variables for all tests."""
    with patch.dict(os.environ, {
        "FINGERPRINT_SECRET": "test-fingerprint-secret-key-for-testing",
        "JWT_SECRET_KEY": "test-jwt-secret-key",
    }):
        from src.core.config import get_settings
        get_settings.cache_clear()
        yield
        get_settings.cache_clear()


class TestRequestContextExtraction:
    """Tests for RequestContext dataclass and get_request_context dependency."""
    
    async def test_extracts_fingerprint_header(self):
        """Verify fingerprint is extracted from X-Device-Fingerprint header."""
        from src.middleware.context import get_request_context
        
        request = MagicMock()
        request.headers = {"X-Device-Fingerprint": "test-fingerprint-value"}
        request.cookies = {}
        request.client = MagicMock()
        request.client.host = "127.0.0.1"
        
        ctx = await get_request_context(request)
        
        assert ctx.fingerprint_raw == "test-fingerprint-value"
        assert ctx.fingerprint_hash is not None
        assert len(ctx.fingerprint_hash) == 64  # SHA256 hex length

    async def test_extracts_user_agent(self):
        """Verify User-Agent header is extracted."""
        from src.middleware.context import get_request_context
        
        request = MagicMock()
        request.headers = {"User-Agent": "Mozilla/5.0 Test Browser"}
        request.cookies = {}
        request.client = MagicMock()
        request.client.host = "127.0.0.1"
        
        ctx = await get_request_context(request)
        
        assert ctx.user_agent == "Mozilla/5.0 Test Browser"

    async def test_extracts_login_flow_id_cookie(self):
        """Verify X-Login-Flow-ID cookie is extracted."""
        from src.middleware.context import get_request_context
        
        request = MagicMock()
        request.headers = {}
        request.cookies = {"X-Login-Flow-ID": "flow-123-abc"}
        request.client = MagicMock()
        request.client.host = "127.0.0.1"
        
        ctx = await get_request_context(request)
        
        assert ctx.login_flow_id == "flow-123-abc"

    async def test_handles_missing_all_optional_headers(self):
        """Verify graceful handling when all optional headers are missing."""
        from src.middleware.context import get_request_context
        
        request = MagicMock()
        request.headers = {}
        request.cookies = {}
        request.client = MagicMock()
        request.client.host = "127.0.0.1"
        
        ctx = await get_request_context(request)
        
        assert ctx.fingerprint_raw is None
        assert ctx.fingerprint_hash is None
        assert ctx.ip_address == "127.0.0.1"
        assert ctx.user_agent is None
        assert ctx.login_flow_id is None


class TestFingerprintIntegrity:
    """HMAC integrity tests for fingerprint hashing."""
    
    async def test_hashes_fingerprint_correctly(self):
        """Verify fingerprint is hashed using HMAC-SHA256."""
        from src.middleware.context import get_request_context
        from src.core.security import hash_fingerprint
        
        fingerprint_value = "unique-browser-fingerprint"
        expected_hash = hash_fingerprint(fingerprint_value)
        
        request = MagicMock()
        request.headers = {"X-Device-Fingerprint": fingerprint_value}
        request.cookies = {}
        request.client = MagicMock()
        request.client.host = "127.0.0.1"
        
        ctx = await get_request_context(request)
        
        assert ctx.fingerprint_hash == expected_hash

    async def test_fingerprint_hash_changes_with_different_secret(self):
        """Verify different secret produces different hash (salt verification)."""
        from src.middleware.context import get_request_context
        from src.core.config import get_settings
        
        fingerprint = "same-fingerprint"
        
        request = MagicMock()
        request.headers = {"X-Device-Fingerprint": fingerprint}
        request.cookies = {}
        request.client = MagicMock()
        request.client.host = "127.0.0.1"
        
        ctx1 = await get_request_context(request)
        hash1 = ctx1.fingerprint_hash
        
        with patch.dict(os.environ, {"FINGERPRINT_SECRET": "different-secret-key"}):
            get_settings.cache_clear()
            ctx2 = await get_request_context(request)
            hash2 = ctx2.fingerprint_hash
            get_settings.cache_clear()
        
        assert hash1 != hash2
        assert len(hash1) == len(hash2) == 64

    async def test_empty_string_fingerprint_treated_as_missing(self):
        """Empty string header results in no hash (falsy check)."""
        from src.middleware.context import get_request_context
        
        request = MagicMock()
        request.headers = {"X-Device-Fingerprint": ""}
        request.cookies = {}
        request.client = MagicMock()
        request.client.host = "127.0.0.1"
        
        ctx = await get_request_context(request)
        
        assert ctx.fingerprint_raw == ""
        assert ctx.fingerprint_hash is None


class TestIPExtraction:
    """
    Condensed IP extraction tests covering proxy chains, fallbacks, and IPv6.
    
    This replaces multiple individual tests with a single parametrized test
    to cover the core data flow without redundant test bloat.
    """
    
    @pytest.mark.parametrize("headers,client_host,expected_ip", [
        # Proxy chain: first IP is extracted
        ({"X-Forwarded-For": "203.0.113.1, 1.1.1.1"}, "10.0.0.1", "203.0.113.1"),
        # Single proxy
        ({"X-Forwarded-For": "203.0.113.195"}, "10.0.0.1", "203.0.113.195"),
        # Direct IP (no proxy header)
        ({}, "192.168.1.1", "192.168.1.1"),
        # Total failure fallback (no client)
        ({}, None, "0.0.0.0"),
        # IPv6 via proxy
        ({"X-Forwarded-For": "::1"}, "127.0.0.1", "::1"),
        # Full IPv6 address
        ({"X-Forwarded-For": "2001:0db8:85a3:0000:0000:8a2e:0370:7334"}, "127.0.0.1", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
        # IPv6 with zone ID
        ({"X-Forwarded-For": "fe80::1%eth0"}, "127.0.0.1", "fe80::1%eth0"),
        # Mixed IPv4 and IPv6 in chain
        ({"X-Forwarded-For": "2001:db8::1, 192.168.1.1"}, "10.0.0.1", "2001:db8::1"),
        # Empty header falls back to client.host
        ({"X-Forwarded-For": ""}, "192.168.1.1", "192.168.1.1"),
        # Whitespace-only header falls back
        ({"X-Forwarded-For": "   "}, "192.168.1.1", "192.168.1.1"),
    ])
    async def test_ip_extraction_logic(self, headers, client_host, expected_ip):
        """Parametrized test covering proxy chains, fallbacks, and IPv6."""
        from src.middleware.context import get_request_context
        
        request = MagicMock()
        request.headers = headers
        request.cookies = {}
        if client_host is None:
            request.client = None
        else:
            request.client = MagicMock()
            request.client.host = client_host
        
        ctx = await get_request_context(request)
        
        assert ctx.ip_address == expected_ip

    async def test_ipv6_from_client_host(self):
        """Verify IPv6 address from client.host is handled correctly."""
        from src.middleware.context import get_request_context
        
        request = MagicMock()
        request.headers = {}
        request.cookies = {}
        request.client = MagicMock()
        request.client.host = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        
        ctx = await get_request_context(request)
        
        assert ctx.ip_address == "2001:0db8:85a3:0000:0000:8a2e:0370:7334"


class TestCookieExtraction:
    """Cookie extraction tests for login flow ID."""
    
    async def test_login_flow_id_with_multiple_cookies(self):
        """Ensure correct cookie is extracted when multiple cookies exist."""
        from src.middleware.context import get_request_context
        
        request = MagicMock()
        request.headers = {}
        request.cookies = {
            "session_id": "abc123",
            "X-Login-Flow-ID": "correct-flow-id",
            "_ga": "GA1.2.1234567890.1234567890",
            "other_cookie": "other_value",
        }
        request.client = MagicMock()
        request.client.host = "127.0.0.1"
        
        ctx = await get_request_context(request)
        
        assert ctx.login_flow_id == "correct-flow-id"

    async def test_empty_login_flow_id_cookie(self):
        """Empty cookie value is preserved as empty string."""
        from src.middleware.context import get_request_context
        
        request = MagicMock()
        request.headers = {}
        request.cookies = {"X-Login-Flow-ID": ""}
        request.client = MagicMock()
        request.client.host = "127.0.0.1"
        
        ctx = await get_request_context(request)
        
        assert ctx.login_flow_id == ""
