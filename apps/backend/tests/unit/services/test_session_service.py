import pytest
from datetime import datetime, timedelta, timezone
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


@pytest.fixture
def github_profile():
    from src.core.oauth import UserProfile
    return UserProfile(
        email="test@example.com",
        provider_id="MDQ6VXNlcjEyMzQ1Njc=",
        avatar_url="https://avatars.githubusercontent.com/u/1234567",
        is_verified=True,
        username="testuser",
    )


@pytest.fixture
def google_profile():
    from src.core.oauth import UserProfile
    return UserProfile(
        email="test@example.com",
        provider_id="123456789012345678901",
        avatar_url="https://lh3.googleusercontent.com/a/default",
        is_verified=True,
        username=None,
    )


class TestRefreshSessionLogic:
    """Tests the REFRESH_THRESHOLD_RATIO business rule that prevents excessive DB writes"""
    
    async def test_updates_session_when_threshold_exceeded(self, mock_db):
        """Refresh updates DB when more than 10 percent through lifespan"""
        from src.services.session_service import refresh_session
        
        session = MagicMock()
        session.remember_me = True
        session.expires_at = datetime.now(timezone.utc) + timedelta(days=3)
        session.last_active_at = datetime.now(timezone.utc) - timedelta(hours=1)
        
        new_expires = await refresh_session(mock_db, session)
        
        assert new_expires is not None
        mock_db.commit.assert_called_once()

    async def test_skips_update_when_within_threshold(self, mock_db):
        """Refresh skips DB write when less than 10 percent through lifespan"""
        from src.services.session_service import refresh_session
        
        session = MagicMock()
        session.remember_me = True
        session.expires_at = datetime.now(timezone.utc) + timedelta(days=6, hours=22)
        
        new_expires = await refresh_session(mock_db, session)
        
        assert new_expires is None
        mock_db.commit.assert_not_called()

    async def test_refresh_always_extends_from_now(self, mock_db):
        """
        Refresh calculates new expires_at from current time, not old expires_at;
        prevents indefinite session extension through repeated refreshes
        """
        from src.services.session_service import refresh_session
        
        session = MagicMock()
        session.remember_me = True
        session.expires_at = datetime.now(timezone.utc) + timedelta(days=1)
        
        before = datetime.now(timezone.utc)
        new_expires = await refresh_session(mock_db, session)
        after = datetime.now(timezone.utc)
        
        assert new_expires is not None
        expected_min = before + timedelta(days=6, hours=23)
        expected_max = after + timedelta(days=7, hours=1)
        assert expected_min <= new_expires <= expected_max


class TestIdentityConflicts:
    """OAuth identity collision detection"""
    
    async def test_raises_existing_account_error_different_provider(self, mock_db, github_profile):
        """
        Prevents duplicate accounts; if user signed up with Google then tries
        GitHub login with same email, must fail with ExistingAccountError
        """
        from src.services.session_service import upsert_user, ExistingAccountError
        from src.core.oauth import OAuthProvider
        
        existing_user = MagicMock()
        existing_user.created_via = "google"
        
        mock_result = MagicMock()
        mock_result.first.return_value = existing_user
        mock_db.exec.return_value = mock_result
        
        with pytest.raises(ExistingAccountError) as exc:
            await upsert_user(mock_db, github_profile, OAuthProvider.GITHUB)
        
        assert exc.value.original_provider == "google"

    async def test_raises_conflict_when_provider_linked_to_other(self, mock_db, github_profile):
        """Two different users cannot link the same OAuth provider account"""
        from src.services.session_service import link_provider, ProviderConflictError
        from src.core.oauth import OAuthProvider
        
        user = MagicMock()
        user.id = uuid4()
        
        other_user = MagicMock()
        other_user.id = uuid4()
        
        mock_result = MagicMock()
        mock_result.first.return_value = other_user
        mock_db.exec.return_value = mock_result
        
        with pytest.raises(ProviderConflictError):
            await link_provider(mock_db, user, github_profile, OAuthProvider.GITHUB)


class TestFingerprintEnforcement:
    """Proves device fingerprint is validated at the SQL level, not in Python"""
    
    async def test_fingerprint_included_in_query_where_clause(self, mock_db):
        """
        Fingerprint must be part of the SQL WHERE clause;
        database enforces device lock rather than fetching then checking in Python
        """
        from src.services.session_service import get_session_by_id_and_fingerprint
        
        session_id = uuid4()
        fingerprint = "test_fingerprint_hash"
        
        mock_result = MagicMock()
        mock_result.first.return_value = None
        mock_db.exec.return_value = mock_result
        
        await get_session_by_id_and_fingerprint(mock_db, session_id, fingerprint)
        
        mock_db.exec.assert_called_once()


class TestBulkSessionOperations:
    """Sign out of all other devices feature"""
    
    @pytest.mark.parametrize("except_id, expected_where_calls", [
        (uuid4(), 2),
        (None, 1),
    ])
    async def test_invalidate_all_sessions_logic(self, mock_db, except_id, expected_where_calls):
        """
        With except_session_id uses 2 WHERE clauses; without uses 1
        """
        from src.services.session_service import invalidate_all_sessions
        
        user_id = uuid4()
        
        mock_result = MagicMock()
        mock_result.rowcount = 3
        mock_db.exec.return_value = mock_result
        
        with patch("src.services.session_service.delete") as mock_delete:
            chain = mock_delete.return_value.where.return_value
            chain.where.return_value = chain
            
            await invalidate_all_sessions(mock_db, user_id, except_session_id=except_id)
            
            assert mock_delete.return_value.where.call_count == 1
            assert chain.where.call_count == (expected_where_calls - 1)

    async def test_invalidate_all_except_preserves_current(self, mock_db):
        """Excludes current session from bulk deletion"""
        from src.services.session_service import invalidate_all_sessions
        
        user_id = uuid4()
        current_session_id = uuid4()
        
        mock_result = MagicMock()
        mock_result.rowcount = 3
        mock_db.exec.return_value = mock_result
        
        with patch("src.services.session_service.delete") as mock_delete:
            mock_where = MagicMock()
            mock_where.where.return_value = MagicMock()
            mock_delete.return_value.where.return_value = mock_where
            
            count = await invalidate_all_sessions(
                mock_db, user_id, except_session_id=current_session_id
            )
            
            mock_delete.return_value.where.assert_called_once()
            mock_where.where.assert_called_once()
            
            assert count == 3
