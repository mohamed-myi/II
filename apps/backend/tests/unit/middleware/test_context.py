import pytest
from unittest.mock import MagicMock, patch, AsyncMock
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

    async def test_handles_missing_fingerprint_returns_none(self):
        """Verify missing fingerprint results in None values."""
        from src.middleware.context import get_request_context
        
        request = MagicMock()
        request.headers = {}
        request.cookies = {}
        request.client = MagicMock()
        request.client.host = "127.0.0.1"
        
        ctx = await get_request_context(request)
        
        assert ctx.fingerprint_raw is None
        assert ctx.fingerprint_hash is None

    async def test_extracts_real_ip_from_x_forwarded_for(self):
        """Verify IP is extracted from X-Forwarded-For header."""
        from src.middleware.context import get_request_context
        
        request = MagicMock()
        request.headers = {"X-Forwarded-For": "203.0.113.195"}
        request.cookies = {}
        request.client = MagicMock()
        request.client.host = "10.0.0.1"
        
        ctx = await get_request_context(request)
        
        assert ctx.ip_address == "203.0.113.195"

    async def test_extracts_real_ip_from_x_forwarded_for_with_multiple_ips(self):
        """Verify first IP is extracted when multiple proxies in chain."""
        from src.middleware.context import get_request_context
        
        request = MagicMock()
        request.headers = {"X-Forwarded-For": "203.0.113.195, 70.41.3.18, 150.172.238.178"}
        request.cookies = {}
        request.client = MagicMock()
        request.client.host = "10.0.0.1"
        
        ctx = await get_request_context(request)
        
        assert ctx.ip_address == "203.0.113.195"

    async def test_extracts_ip_from_client_host_when_no_proxy(self):
        """Verify IP falls back to client.host when no X-Forwarded-For."""
        from src.middleware.context import get_request_context
        
        request = MagicMock()
        request.headers = {}
        request.cookies = {}
        request.client = MagicMock()
        request.client.host = "192.168.1.100"
        
        ctx = await get_request_context(request)
        
        assert ctx.ip_address == "192.168.1.100"

    async def test_extracts_ip_fallback_when_no_client(self):
        """Verify IP defaults to 0.0.0.0 when client is None."""
        from src.middleware.context import get_request_context
        
        request = MagicMock()
        request.headers = {}
        request.cookies = {}
        request.client = None
        
        ctx = await get_request_context(request)
        
        assert ctx.ip_address == "0.0.0.0"

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

    async def test_handles_missing_all_headers(self):
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
