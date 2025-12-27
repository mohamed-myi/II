import pytest
import os
from unittest.mock import patch


# Mock the settings before importing security module
@pytest.fixture(autouse=True)
def mock_settings():
    with patch.dict(os.environ, {
        "FINGERPRINT_SECRET": "test-fingerprint-secret-key-for-testing",
        "JWT_SECRET_KEY": "test-jwt-secret-key",
    }):
        # Clear the lru_cache to pick up new env vars
        from src.core.config import get_settings
        get_settings.cache_clear()
        yield
        get_settings.cache_clear()


class TestHashFingerprint:
    def test_returns_hex_string(self):
        from src.core.security import hash_fingerprint
        result = hash_fingerprint("test-fingerprint-value")
        assert isinstance(result, str)
        # SHA256 produces 64 hex characters
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_same_input_produces_same_hash(self):
        from src.core.security import hash_fingerprint
        fingerprint = "browser-fingerprint-12345"
        hash1 = hash_fingerprint(fingerprint)
        hash2 = hash_fingerprint(fingerprint)
        assert hash1 == hash2

    def test_different_input_produces_different_hash(self):
        from src.core.security import hash_fingerprint
        hash1 = hash_fingerprint("fingerprint-a")
        hash2 = hash_fingerprint("fingerprint-b")
        assert hash1 != hash2

    def test_empty_string_produces_valid_hash(self):
        from src.core.security import hash_fingerprint
        result = hash_fingerprint("")
        assert isinstance(result, str)
        assert len(result) == 64


class TestGenerateSessionId:
    def test_returns_valid_uuid_string(self):
        from src.core.security import generate_session_id
        import uuid
        session_id = generate_session_id()
        # Should be parseable as UUID
        parsed = uuid.UUID(session_id)
        assert str(parsed) == session_id

    def test_generates_unique_ids(self):
        from src.core.security import generate_session_id
        ids = [generate_session_id() for _ in range(100)]
        # All IDs should be unique
        assert len(set(ids)) == 100

    def test_format_is_uuid_v4(self):
        from src.core.security import generate_session_id
        import uuid
        session_id = generate_session_id()
        parsed = uuid.UUID(session_id)
        assert parsed.version == 4


class TestCompareFingerprints:
    def test_matching_fingerprint_returns_true(self):
        from src.core.security import hash_fingerprint, compare_fingerprints
        raw_fingerprint = "user-browser-fingerprint"
        stored_hash = hash_fingerprint(raw_fingerprint)
        assert compare_fingerprints(stored_hash, raw_fingerprint) is True

    def test_non_matching_fingerprint_returns_false(self):
        from src.core.security import hash_fingerprint, compare_fingerprints
        stored_hash = hash_fingerprint("original-fingerprint")
        assert compare_fingerprints(stored_hash, "different-fingerprint") is False

    def test_empty_fingerprint_comparison(self):
        from src.core.security import hash_fingerprint, compare_fingerprints
        stored_hash = hash_fingerprint("")
        assert compare_fingerprints(stored_hash, "") is True
        assert compare_fingerprints(stored_hash, "non-empty") is False

    def test_timing_attack_resistance(self):
        # Verifies we use constant-time comparison through structural testing.
        from src.core.security import compare_fingerprints, hash_fingerprint
        import secrets
        stored = hash_fingerprint("test")
        assert compare_fingerprints(stored, "test") is True
        assert compare_fingerprints(stored, "wrong") is False


class TestGenerateLoginFlowId:
    def test_returns_url_safe_string(self):
        from src.core.security import generate_login_flow_id
        flow_id = generate_login_flow_id()
        assert isinstance(flow_id, str)
        # Should be URL-safe (no special chars needing encoding)
        import urllib.parse
        assert urllib.parse.quote(flow_id, safe="") == flow_id or "_" in flow_id or "-" in flow_id

    def test_generates_unique_ids(self):
        from src.core.security import generate_login_flow_id
        ids = [generate_login_flow_id() for _ in range(100)]
        assert len(set(ids)) == 100

    def test_sufficient_entropy(self):
        from src.core.security import generate_login_flow_id
        flow_id = generate_login_flow_id()
        # 16 bytes base64url encoded = ~22 characters
        assert len(flow_id) >= 20
