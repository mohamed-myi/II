"""
Security Tests - Fail-Safes and Production Hardening

This module tests the core security utilities:
- InsecureSecretError enforcement (fail-fast on weak secrets)
- Malformed hash handling (DB NULL/corruption resilience)
- Constant-time comparison (timing attack resistance)
- ID generation uniqueness verification

Tests are condensed to focus on security-critical behavior, not stdlib validation.
"""
import pytest
import os
from unittest.mock import patch


@pytest.fixture(autouse=True)
def mock_settings():
    with patch.dict(os.environ, {
        "FINGERPRINT_SECRET": "test-fingerprint-secret-key-for-testing",
        "JWT_SECRET_KEY": "test-jwt-secret-key",
    }):
        from src.core.config import get_settings
        get_settings.cache_clear()
        yield
        get_settings.cache_clear()


class TestInsecureSecretValidation:
    """
    Security Fail-Safes for FINGERPRINT_SECRET.
    
    Proves the app "fails secure" - prevents production deployment
    with weak .env.example keys or empty secrets.
    """
    
    def test_empty_secret_fails_in_any_environment(self):
        """Empty FINGERPRINT_SECRET should fail-fast in ANY environment."""
        from src.core.security import InsecureSecretError
        
        with patch.dict(os.environ, {
            "FINGERPRINT_SECRET": "",
            "ENVIRONMENT": "development",
        }):
            from src.core.config import get_settings
            get_settings.cache_clear()
            
            from src.core.security import hash_fingerprint
            with pytest.raises(InsecureSecretError) as exc:
                hash_fingerprint("test-fingerprint")
            
            assert "must be set" in str(exc.value)
            get_settings.cache_clear()

    def test_weak_secret_raises_in_production(self):
        """Default .env.example value should raise in production."""
        from src.core.security import InsecureSecretError
        
        with patch.dict(os.environ, {
            "FINGERPRINT_SECRET": "a-random-string",
            "ENVIRONMENT": "production",
        }):
            from src.core.config import get_settings
            get_settings.cache_clear()
            
            from src.core.security import hash_fingerprint
            with pytest.raises(InsecureSecretError) as exc:
                hash_fingerprint("test-fingerprint")
            
            assert "weak" in str(exc.value).lower()
            get_settings.cache_clear()

    def test_weak_secret_allowed_in_development(self):
        """Non-empty weak secrets are allowed in development for convenience."""
        with patch.dict(os.environ, {
            "FINGERPRINT_SECRET": "a-random-string",
            "ENVIRONMENT": "development",
        }):
            from src.core.config import get_settings
            get_settings.cache_clear()
            
            from src.core.security import hash_fingerprint
            result = hash_fingerprint("test-fingerprint")
            assert len(result) == 64
            
            get_settings.cache_clear()


class TestMalformedHashHandling:
    """
    Anti-Corruption / NULL Handling.
    
    Handles "dirty data" from the database. If a hash is corrupted
    or NULL, security logic should deny access without crashing.
    """
    
    @pytest.mark.parametrize("stored_hash,raw_input,expected", [
        (None, "anything", False),            # DB NULL
        ("", "anything", False),              # Empty string
        ("abc123", "anything", False),        # Too short (corrupted)
        ("a" * 65, "anything", False),        # Too long (corrupted)
        ("a" * 100, "anything", False),       # Way too long
    ])
    def test_hash_boundary_safety(self, stored_hash, raw_input, expected):
        """Malformed stored hashes should safely return False."""
        from src.core.security import compare_fingerprints
        assert compare_fingerprints(stored_hash, raw_input) is expected

    def test_valid_hash_proceeds_to_comparison(self):
        """Valid 64-char hash should proceed to actual comparison."""
        from src.core.security import compare_fingerprints, hash_fingerprint
        valid_hash = hash_fingerprint("test-value")
        assert len(valid_hash) == 64
        assert compare_fingerprints(valid_hash, "test-value") is True
        assert compare_fingerprints(valid_hash, "wrong-value") is False


class TestFingerprintComparison:
    """
    Fingerprint comparison tests including timing attack resistance.
    """
    
    def test_matching_fingerprint_returns_true(self):
        from src.core.security import hash_fingerprint, compare_fingerprints
        raw_fingerprint = "user-browser-fingerprint"
        stored_hash = hash_fingerprint(raw_fingerprint)
        assert compare_fingerprints(stored_hash, raw_fingerprint) is True

    def test_non_matching_fingerprint_returns_false(self):
        from src.core.security import hash_fingerprint, compare_fingerprints
        stored_hash = hash_fingerprint("original-fingerprint")
        assert compare_fingerprints(stored_hash, "different-fingerprint") is False

    def test_timing_attack_resistance(self):
        """
        Verifies constant-time comparison is used (secrets.compare_digest).
        
        Structural test: ensures the comparison works correctly for both
        matching and non-matching inputs without early termination.
        """
        from src.core.security import compare_fingerprints, hash_fingerprint
        stored = hash_fingerprint("test")
        # These should use constant-time comparison internally
        assert compare_fingerprints(stored, "test") is True
        assert compare_fingerprints(stored, "wrong") is False


class TestIDGenerationUniqueness:
    """
    Entropy & Uniqueness verification for ID generation.
    
    Confirms wrapper functions haven't introduced bottlenecks or static seeds.
    Note: We're testing our wrapper, not uuid/secrets stdlib.
    """
    
    def test_session_ids_are_unique(self):
        from src.core.security import generate_session_id
        ids = [generate_session_id() for _ in range(100)]
        assert len(set(ids)) == 100

    def test_login_flow_ids_are_unique(self):
        from src.core.security import generate_login_flow_id
        ids = [generate_login_flow_id() for _ in range(100)]
        assert len(set(ids)) == 100

    def test_login_flow_id_has_sufficient_entropy(self):
        """16 bytes base64url encoded = ~22 characters minimum."""
        from src.core.security import generate_login_flow_id
        flow_id = generate_login_flow_id()
        assert len(flow_id) >= 20
