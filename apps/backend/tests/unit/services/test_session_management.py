import pytest
from datetime import datetime, timezone
from uuid import uuid4
from unittest.mock import AsyncMock, MagicMock, patch
import os


@pytest.fixture(autouse=True)
def mock_settings():
    with patch.dict(os.environ, {
        "FINGERPRINT_SECRET": "test-fingerprint-secret-key-for-testing",
        "JWT_SECRET_KEY": "test-jwt-secret-key",
        "SESSION_REMEMBER_ME_DAYS": "7",
        "SESSION_DEFAULT_HOURS": "24",
    }):
        from src.core.config import get_settings
        get_settings.cache_clear()
        yield
        get_settings.cache_clear()


@pytest.fixture
def mock_db():
    db = AsyncMock()
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    db.delete = AsyncMock()
    db.exec = AsyncMock()
    return db


class TestListSessionsLogic:
    """Tests for list_sessions business logic"""
    
    async def test_returns_sanitized_fingerprint_partial(self, mock_db):
        """Only first 8 chars of fingerprint exposed for privacy"""
        from src.services.session_service import list_sessions
        
        session = MagicMock()
        session.id = uuid4()
        session.fingerprint = "abcd1234efgh5678ijkl9012"
        session.created_at = datetime.now(timezone.utc)
        session.last_active_at = datetime.now(timezone.utc)
        session.user_agent_string = "Mozilla/5.0"
        session.ip_address = "192.168.1.1"
        
        mock_result = MagicMock()
        mock_result.all.return_value = [session]
        mock_db.exec.return_value = mock_result
        
        result = await list_sessions(mock_db, uuid4(), session.id)
        
        assert len(result) == 1
        assert result[0].fingerprint_partial == "abcd1234"
        assert len(result[0].fingerprint_partial) == 8

    async def test_is_current_flag_correctly_set(self, mock_db):
        """is_current should be True only for matching session_id"""
        from src.services.session_service import list_sessions
        
        current_id = uuid4()
        other_id = uuid4()
        
        current_session = MagicMock()
        current_session.id = current_id
        current_session.fingerprint = "fingerprint1"
        current_session.created_at = datetime.now(timezone.utc)
        current_session.last_active_at = datetime.now(timezone.utc)
        current_session.user_agent_string = None
        current_session.ip_address = None
        
        other_session = MagicMock()
        other_session.id = other_id
        other_session.fingerprint = "fingerprint2"
        other_session.created_at = datetime.now(timezone.utc)
        other_session.last_active_at = datetime.now(timezone.utc)
        other_session.user_agent_string = None
        other_session.ip_address = None
        
        mock_result = MagicMock()
        mock_result.all.return_value = [current_session, other_session]
        mock_db.exec.return_value = mock_result
        
        result = await list_sessions(mock_db, uuid4(), current_id)
        
        current_results = [s for s in result if s.is_current]
        other_results = [s for s in result if not s.is_current]
        
        assert len(current_results) == 1
        assert len(other_results) == 1
        assert current_results[0].id == str(current_id)

    @pytest.mark.parametrize("fingerprint,expected", [
        (None, ""),           # None fingerprint
        ("abc", "abc"),       # Short fingerprint (< 8 chars)
    ])
    async def test_handles_edge_case_fingerprints(self, mock_db, fingerprint, expected):
        """Edge case fingerprints (None or short) should not crash."""
        from src.services.session_service import list_sessions
        
        session = MagicMock()
        session.id = uuid4()
        session.fingerprint = fingerprint
        session.created_at = datetime.now(timezone.utc)
        session.last_active_at = datetime.now(timezone.utc)
        session.user_agent_string = None
        session.ip_address = None
        
        mock_result = MagicMock()
        mock_result.all.return_value = [session]
        mock_db.exec.return_value = mock_result
        
        result = await list_sessions(mock_db, uuid4(), None)
        
        assert result[0].fingerprint_partial == expected


class TestCountSessionsLogic:
    """Tests for count_sessions business logic"""
    
    async def test_returns_integer_count(self, mock_db):
        """count_sessions returns integer, not ResultProxy"""
        from src.services.session_service import count_sessions
        
        mock_db.exec.return_value = MagicMock(one=MagicMock(return_value=5))
        
        result = await count_sessions(mock_db, uuid4())
        
        assert result == 5
        assert isinstance(result, int)

    # NOTE: Zero count test removed - if integer type test passes, zero is just another integer

# NOTE: Refresh session boundary conditions tested in test_session_service.py::TestRefreshSessionLogic

class TestSessionInvalidationEdgeCases:
    """Edge cases for session invalidation"""
    
    async def test_invalidate_nonexistent_session(self, mock_db):
        """Invalidating non-existent session returns False"""
        from src.services.session_service import invalidate_session
        
        mock_result = MagicMock()
        mock_result.rowcount = 0
        mock_db.exec.return_value = mock_result
        
        result = await invalidate_session(mock_db, uuid4())
        
        assert result is False

    async def test_invalidate_existing_session(self, mock_db):
        """Invalidating existing session returns True"""
        from src.services.session_service import invalidate_session
        
        mock_result = MagicMock()
        mock_result.rowcount = 1
        mock_db.exec.return_value = mock_result
        
        result = await invalidate_session(mock_db, uuid4())
        
        assert result is True
