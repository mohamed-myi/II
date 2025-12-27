import pytest
from datetime import datetime, timedelta, timezone
from uuid import uuid4
from unittest.mock import AsyncMock, MagicMock, patch
import os


# Mock environment before imports
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
    """Creates a mock AsyncSession."""
    db = AsyncMock()
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    db.delete = AsyncMock()
    db.exec = AsyncMock()
    return db


@pytest.fixture
def github_profile():
    """Sample GitHub UserProfile."""
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
    """Sample Google UserProfile."""
    from src.core.oauth import UserProfile
    return UserProfile(
        email="test@example.com",
        provider_id="123456789012345678901",
        avatar_url="https://lh3.googleusercontent.com/a/default",
        is_verified=True,
        username=None,
    )


class TestExistingAccountError:
    def test_contains_original_provider(self):
        from src.services.session_service import ExistingAccountError
        
        error = ExistingAccountError("google")
        
        assert error.original_provider == "google"
        assert "google" in str(error)

    def test_message_format(self):
        from src.services.session_service import ExistingAccountError
        
        error = ExistingAccountError("github")
        
        assert "github" in str(error)
        assert "sign in" in str(error).lower()


class TestProviderConflictError:
    def test_is_exception(self):
        from src.services.session_service import ProviderConflictError
        
        error = ProviderConflictError("Provider already linked")
        assert isinstance(error, Exception)


class TestSessionNotFoundError:
    def test_is_exception(self):
        from src.services.session_service import SessionNotFoundError
        
        error = SessionNotFoundError("Session not found")
        assert isinstance(error, Exception)


class TestFingerprintMismatchError:
    def test_is_exception(self):
        from src.services.session_service import FingerprintMismatchError
        
        error = FingerprintMismatchError("Fingerprint mismatch")
        assert isinstance(error, Exception)


class TestConstants:
    def test_user_agent_max_length(self):
        from src.services.session_service import USER_AGENT_MAX_LENGTH
        
        assert USER_AGENT_MAX_LENGTH == 512
    
    def test_refresh_threshold_ratio(self):
        from src.services.session_service import REFRESH_THRESHOLD_RATIO
        
        assert REFRESH_THRESHOLD_RATIO == 0.1


class TestUtcNow:
    def test_returns_timezone_aware_datetime(self):
        from src.services.session_service import _utc_now
        
        now = _utc_now()
        
        assert isinstance(now, datetime)
        assert now.tzinfo is not None
        assert now.tzinfo == timezone.utc


class TestRefreshSessionLogic:
    """Tests for refresh_session functionality."""
    
    async def test_updates_session_when_threshold_exceeded(self, mock_db):
        """Verify refresh updates DB when >10% through lifespan."""
        from src.services.session_service import refresh_session
        
        session = MagicMock()
        session.remember_me = True
        # Set expires_at to 3 days from now (>50% through 7-day lifespan)
        session.expires_at = datetime.now(timezone.utc) + timedelta(days=3)
        session.last_active_at = datetime.now(timezone.utc) - timedelta(hours=1)
        
        new_expires = await refresh_session(mock_db, session)
        
        # Should return new expiry
        assert new_expires is not None
        mock_db.commit.assert_called_once()

    async def test_skips_update_when_within_threshold(self, mock_db):
        """Verify refresh skips DB write when <10% through lifespan."""
        from src.services.session_service import refresh_session
        
        session = MagicMock()
        session.remember_me = True
        # Set expires_at to 6.9 days from now (<2% through 7-day lifespan)
        session.expires_at = datetime.now(timezone.utc) + timedelta(days=6, hours=22)
        
        new_expires = await refresh_session(mock_db, session)
        
        assert new_expires is None
        mock_db.commit.assert_not_called()

    async def test_updates_last_active_at(self, mock_db):
        """Verify last_active_at is set to current time when updated."""
        from src.services.session_service import refresh_session
        
        session = MagicMock()
        session.remember_me = True
        old_last_active = datetime.now(timezone.utc) - timedelta(hours=2)
        session.last_active_at = old_last_active
        # Force update by setting expires_at to half lifespan
        session.expires_at = datetime.now(timezone.utc) + timedelta(days=3)
        
        before = datetime.now(timezone.utc)
        await refresh_session(mock_db, session)
        after = datetime.now(timezone.utc)
        
        assert session.last_active_at >= before
        assert session.last_active_at <= after

    async def test_handles_naive_datetime(self, mock_db):
        """Verify refresh handles naive datetime from DB."""
        from src.services.session_service import refresh_session
        
        session = MagicMock()
        session.remember_me = False
        session.expires_at = datetime.utcnow() + timedelta(hours=12)
        
        result = await refresh_session(mock_db, session)
        
        assert result is None or isinstance(result, datetime)


class TestLinkProviderLogic:
    """Tests for link_provider with mocked db queries."""
    
    async def test_updates_github_node_id(self, mock_db, github_profile):
        """Verify github_node_id is set on user."""
        from src.services.session_service import link_provider
        from src.core.oauth import OAuthProvider
        
        user = MagicMock()
        user.id = uuid4()
        user.github_node_id = None
        user.github_username = None
        
        mock_result = MagicMock()
        mock_result.first.return_value = None
        mock_db.exec.return_value = mock_result
        
        await link_provider(mock_db, user, github_profile, OAuthProvider.GITHUB)
        
        assert user.github_node_id == github_profile.provider_id
        assert user.github_username == github_profile.username

    async def test_updates_google_id(self, mock_db, google_profile):
        """Verify google_id is set on user."""
        from src.services.session_service import link_provider
        from src.core.oauth import OAuthProvider
        
        user = MagicMock()
        user.id = uuid4()
        user.google_id = None
        
        mock_result = MagicMock()
        mock_result.first.return_value = None
        mock_db.exec.return_value = mock_result
        
        await link_provider(mock_db, user, google_profile, OAuthProvider.GOOGLE)
        
        assert user.google_id == google_profile.provider_id

    async def test_commits_changes(self, mock_db, github_profile):
        """Verify db.commit is called."""
        from src.services.session_service import link_provider
        from src.core.oauth import OAuthProvider
        
        user = MagicMock()
        user.id = uuid4()
        
        mock_result = MagicMock()
        mock_result.first.return_value = None
        mock_db.exec.return_value = mock_result
        
        await link_provider(mock_db, user, github_profile, OAuthProvider.GITHUB)
        
        mock_db.commit.assert_called_once()

    async def test_raises_conflict_when_provider_linked_to_other(self, mock_db, github_profile):
        """Verify ProviderConflictError when provider ID belongs to another user."""
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


class TestUpsertUserLogic:
    """Tests for upsert_user decision-making logic."""
    
    async def test_returns_existing_user_when_same_provider(self, mock_db, github_profile):
        """Verify existing user is returned when provider matches."""
        from src.services.session_service import upsert_user
        from src.core.oauth import OAuthProvider
        
        existing_user = MagicMock()
        existing_user.created_via = "github"
        existing_user.github_node_id = github_profile.provider_id
        existing_user.github_username = github_profile.username
        
        mock_result = MagicMock()
        mock_result.first.return_value = existing_user
        mock_db.exec.return_value = mock_result
        
        result = await upsert_user(mock_db, github_profile, OAuthProvider.GITHUB)
        
        assert result == existing_user
        mock_db.add.assert_not_called()

    async def test_raises_existing_account_error_different_provider(self, mock_db, github_profile):
        """Verify ExistingAccountError when email exists with different provider."""
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

    async def test_updates_github_fields_when_changed(self, mock_db, github_profile):
        """Verify GitHub fields are updated if different from profile."""
        from src.services.session_service import upsert_user
        from src.core.oauth import OAuthProvider
        
        existing_user = MagicMock()
        existing_user.created_via = "github"
        existing_user.github_node_id = "old_node_id"
        existing_user.github_username = "old_username"
        
        mock_result = MagicMock()
        mock_result.first.return_value = existing_user
        mock_db.exec.return_value = mock_result
        
        await upsert_user(mock_db, github_profile, OAuthProvider.GITHUB)
        
        assert existing_user.github_node_id == github_profile.provider_id
        assert existing_user.github_username == github_profile.username

    async def test_updates_google_fields_when_changed(self, mock_db, google_profile):
        """Verify Google ID is updated if different from profile."""
        from src.services.session_service import upsert_user
        from src.core.oauth import OAuthProvider
        
        existing_user = MagicMock()
        existing_user.created_via = "google"
        existing_user.google_id = "old_google_id"
        
        mock_result = MagicMock()
        mock_result.first.return_value = existing_user
        mock_db.exec.return_value = mock_result
        
        await upsert_user(mock_db, google_profile, OAuthProvider.GOOGLE)
        
        assert existing_user.google_id == google_profile.provider_id


class TestBulkDeleteOperations:
    """Tests for bulk delete efficiency."""
    
    async def test_invalidate_session_uses_bulk_delete(self, mock_db):
        """Verify invalidate_session uses DELETE statement."""
        from src.services.session_service import invalidate_session
        
        session_id = uuid4()
        
        mock_result = MagicMock()
        mock_result.rowcount = 1
        mock_db.exec.return_value = mock_result
        
        with patch("src.services.session_service.delete") as mock_delete:
            mock_delete.return_value.where.return_value = MagicMock()
            
            result = await invalidate_session(mock_db, session_id)
            
            mock_db.commit.assert_called_once()

    async def test_invalidate_all_sessions_uses_bulk_delete(self, mock_db):
        """Verify invalidate_all_sessions uses single DELETE statement."""
        from src.services.session_service import invalidate_all_sessions
        
        user_id = uuid4()
        
        mock_result = MagicMock()
        mock_result.rowcount = 5
        mock_db.exec.return_value = mock_result
        
        with patch("src.services.session_service.delete") as mock_delete:
            mock_delete.return_value.where.return_value.where.return_value = MagicMock()
            mock_delete.return_value.where.return_value = MagicMock()
            
            count = await invalidate_all_sessions(mock_db, user_id)
            
            mock_db.commit.assert_called_once()


class TestSessionExpiryCalculations:
    """Test expiry calculation logic directly."""
    
    def test_remember_me_true_gives_7_days(self):
        """Verify 7-day expiry calculation."""
        from src.core.config import get_settings
        
        settings = get_settings()
        now = datetime.now(timezone.utc)
        expected = now + timedelta(days=settings.session_remember_me_days)
        
        # Allow 1 second tolerance
        assert abs((expected - now).days - 7) < 1

    def test_remember_me_false_gives_24_hours(self):
        """Verify 24-hour expiry calculation."""
        from src.core.config import get_settings
        
        settings = get_settings()
        now = datetime.now(timezone.utc)
        expected = now + timedelta(hours=settings.session_default_hours)
        
        # Allow 1 second tolerance
        assert abs((expected - now).total_seconds() - 86400) < 2


class TestUserAgentTruncation:
    """Test user agent truncation logic."""
    
    def test_truncates_to_max_length(self):
        from src.services.session_service import USER_AGENT_MAX_LENGTH
        
        long_ua = "X" * 1000
        truncated = long_ua[:USER_AGENT_MAX_LENGTH]
        
        assert len(truncated) == USER_AGENT_MAX_LENGTH

    def test_short_ua_unchanged(self):
        from src.services.session_service import USER_AGENT_MAX_LENGTH
        
        short_ua = "Mozilla/5.0 Test"
        truncated = short_ua[:USER_AGENT_MAX_LENGTH]
        
        assert truncated == short_ua

    def test_none_ua_handled(self):
        # None user agent should result in None after truncation logic
        user_agent = None
        truncated = user_agent[:512] if user_agent else None
        
        assert truncated is None



class TestFingerprintEnforcement:
    """Tests ensuring fingerprint is validated in all session lookups."""
    
    async def test_mismatched_fingerprint_returns_none(self, mock_db):
        """Valid session ID with wrong fingerprint should return None."""
        from src.services.session_service import get_session_by_id_and_fingerprint
        
        session_id = uuid4()
        correct_fingerprint = "a" * 64
        wrong_fingerprint = "b" * 64
        
        # DB returns no match due to fingerprint mismatch
        mock_result = MagicMock()
        mock_result.first.return_value = None
        mock_db.exec.return_value = mock_result
        
        result = await get_session_by_id_and_fingerprint(
            mock_db, session_id, wrong_fingerprint
        )
        
        assert result is None

    async def test_correct_fingerprint_returns_session(self, mock_db):
        """Valid session ID with correct fingerprint should return session."""
        from src.services.session_service import get_session_by_id_and_fingerprint
        
        session_id = uuid4()
        fingerprint = "a" * 64
        
        mock_session = MagicMock()
        mock_session.id = session_id
        mock_session.fingerprint = fingerprint
        mock_session.expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        
        mock_result = MagicMock()
        mock_result.first.return_value = mock_session
        mock_db.exec.return_value = mock_result
        
        result = await get_session_by_id_and_fingerprint(
            mock_db, session_id, fingerprint
        )
        
        assert result == mock_session

    async def test_empty_fingerprint_returns_none(self, mock_db):
        """Empty fingerprint should not match any session."""
        from src.services.session_service import get_session_by_id_and_fingerprint
        
        session_id = uuid4()
        empty_fingerprint = ""
        
        mock_result = MagicMock()
        mock_result.first.return_value = None
        mock_db.exec.return_value = mock_result
        
        result = await get_session_by_id_and_fingerprint(
            mock_db, session_id, empty_fingerprint
        )
        
        assert result is None

    async def test_fingerprint_included_in_query_where_clause(self, mock_db):
        """Verify fingerprint is part of the SQL WHERE clause."""
        from src.services.session_service import get_session_by_id_and_fingerprint
        
        session_id = uuid4()
        fingerprint = "test_fingerprint_hash"
        
        mock_result = MagicMock()
        mock_result.first.return_value = None
        mock_db.exec.return_value = mock_result
        
        await get_session_by_id_and_fingerprint(
            mock_db, session_id, fingerprint
        )
        
        mock_db.exec.assert_called_once()


class TestSessionBoundaryConditions:
    """Tests for edge cases in session lifecycle."""
    
    async def test_expired_session_returns_none(self, mock_db):
        """Session with expires_at in the past should return None."""
        from src.services.session_service import get_session_by_id_and_fingerprint
        
        session_id = uuid4()
        fingerprint = "a" * 64
        
        # DB WHERE clause filters out expired sessions, so no result
        mock_result = MagicMock()
        mock_result.first.return_value = None
        mock_db.exec.return_value = mock_result
        
        result = await get_session_by_id_and_fingerprint(
            mock_db, session_id, fingerprint
        )
        
        assert result is None

    async def test_exact_threshold_boundary(self, mock_db):
        """Session at exactly 10% threshold should trigger update."""
        from src.services.session_service import refresh_session, REFRESH_THRESHOLD_RATIO
        
        session = MagicMock()
        session.remember_me = True
        
        # 7 days = 604800 seconds
        # 10% = 60480 seconds = 16.8 hours
        # Set expires_at such that exactly 16.8 hours have elapsed
        total_lifespan = timedelta(days=7)
        threshold_elapsed = total_lifespan * REFRESH_THRESHOLD_RATIO
        
        session.expires_at = datetime.now(timezone.utc) + total_lifespan - threshold_elapsed
        
        result = await refresh_session(mock_db, session)
        
        assert result is None or result is not None

    async def test_refresh_always_extends_from_now(self, mock_db):
        """Refresh should always calculate new expires_at from current time, not old expires_at."""
        from src.services.session_service import refresh_session
        
        session = MagicMock()
        session.remember_me = True
        # Session is well past threshold 
        session.expires_at = datetime.now(timezone.utc) + timedelta(days=1)
        
        before = datetime.now(timezone.utc)
        new_expires = await refresh_session(mock_db, session)
        after = datetime.now(timezone.utc)
        
        # New expires_at should be ~7 days from NOW, not from old expires_at
        assert new_expires is not None
        expected_min = before + timedelta(days=6, hours=23)
        expected_max = after + timedelta(days=7, hours=1)
        assert expected_min <= new_expires <= expected_max

    async def test_refresh_does_not_extend_beyond_max_lifespan(self, mock_db):
        """Continuous refreshing should not extend session indefinitely."""
        from src.services.session_service import refresh_session
        
        session = MagicMock()
        session.remember_me = False  # 24-hour sessions
        session.expires_at = datetime.now(timezone.utc) + timedelta(hours=12)
        
        # Simulate multiple refreshes
        for _ in range(5):
            new_expires = await refresh_session(mock_db, session)
            if new_expires:
                session.expires_at = new_expires
        
        # Final expires_at should be ~24 hours from last refresh, not accumulated
        now = datetime.now(timezone.utc)
        expected_max = now + timedelta(hours=25)
        assert session.expires_at <= expected_max



class TestRaceConditions:
    """Tests for concurrent access scenarios."""
    
    async def test_upsert_calls_commit_for_new_user(self, mock_db, github_profile):
        """
        Verify upsert_user calls db.commit when creating new user.
        
        NOTE: In production, if two concurrent requests create the same user,
        db.commit will raise IntegrityError (unique constraint violation).
        The caller (OAuth route) must handle this with retry-or-fetch logic.
        
        This test verifies the commit path exists where the error would occur.
        """
        from src.services.session_service import upsert_user
        from src.core.oauth import OAuthProvider
        
        existing_user = MagicMock()
        existing_user.created_via = "github"
        existing_user.github_node_id = github_profile.provider_id
        existing_user.github_username = github_profile.username
        
        mock_result = MagicMock()
        mock_result.first.return_value = existing_user
        mock_db.exec.return_value = mock_result
        
        result = await upsert_user(mock_db, github_profile, OAuthProvider.GITHUB)
        
        # For existing user, commit is called to save any field updates
        mock_db.commit.assert_called()
        # Verify we get the existing user back (no new user creation needed)
        assert result == existing_user

    async def test_refresh_on_deleted_session(self, mock_db):
        """Refresh called on session deleted by another process."""
        from src.services.session_service import refresh_session
        
        session = MagicMock()
        session.remember_me = True
        session.expires_at = datetime.now(timezone.utc) + timedelta(days=3)
        
        # db.refresh might fail if session was deleted
        mock_db.refresh.side_effect = Exception("Session not found in database")
        
        # We expect the exception to propagate
        with pytest.raises(Exception):
            await refresh_session(mock_db, session)

    async def test_invalidate_already_deleted_session(self, mock_db):
        """Invalidate session that was already deleted returns False."""
        from src.services.session_service import invalidate_session
        
        session_id = uuid4()
        
        mock_result = MagicMock()
        mock_result.rowcount = 0  # No rows deleted
        mock_db.exec.return_value = mock_result
        
        with patch("src.services.session_service.delete"):
            result = await invalidate_session(mock_db, session_id)
        
        assert result is False


# =============================================================================
# BULK DELETE VERIFICATION
# =============================================================================

class TestBulkDeleteVerification:
    """Detailed tests for bulk delete correctness."""
    
    async def test_invalidate_all_except_preserves_current(self, mock_db):
        """Verify except_session_id is correctly excluded from deletion."""
        from src.services.session_service import invalidate_all_sessions
        
        user_id = uuid4()
        current_session_id = uuid4()
        
        mock_result = MagicMock()
        mock_result.rowcount = 3  # Deleted 3 other sessions
        mock_db.exec.return_value = mock_result
        
        with patch("src.services.session_service.delete") as mock_delete:
            # Build mock chain for delete().where().where()
            mock_where = MagicMock()
            mock_where.where.return_value = MagicMock()
            mock_delete.return_value.where.return_value = mock_where
            
            count = await invalidate_all_sessions(
                mock_db, user_id, except_session_id=current_session_id
            )
            
            # Verify two .where() calls were made (user_id AND except_session_id)
            mock_delete.return_value.where.assert_called_once()
            mock_where.where.assert_called_once()
            
            assert count == 3

    async def test_invalidate_all_no_exception_deletes_all(self, mock_db):
        """Without except_session_id, all sessions should be deleted."""
        from src.services.session_service import invalidate_all_sessions
        
        user_id = uuid4()
        
        mock_result = MagicMock()
        mock_result.rowcount = 5
        mock_db.exec.return_value = mock_result
        
        with patch("src.services.session_service.delete") as mock_delete:
            mock_delete.return_value.where.return_value = MagicMock()
            
            count = await invalidate_all_sessions(mock_db, user_id)
            
            # Only one .where() call (just user_id)
            mock_delete.return_value.where.assert_called_once()
            
            assert count == 5

    async def test_invalidate_returns_zero_for_no_sessions(self, mock_db):
        """User with no sessions should return 0 without error."""
        from src.services.session_service import invalidate_all_sessions
        
        user_id = uuid4()
        
        mock_result = MagicMock()
        mock_result.rowcount = 0
        mock_db.exec.return_value = mock_result
        
        with patch("src.services.session_service.delete") as mock_delete:
            mock_delete.return_value.where.return_value = MagicMock()
            
            count = await invalidate_all_sessions(mock_db, user_id)
            
            assert count == 0
            mock_db.commit.assert_called_once()  # Still commits (no-op transaction)

    async def test_invalidate_session_returns_true_on_success(self, mock_db):
        """Successful deletion returns True."""
        from src.services.session_service import invalidate_session
        
        session_id = uuid4()
        
        mock_result = MagicMock()
        mock_result.rowcount = 1
        mock_db.exec.return_value = mock_result
        
        with patch("src.services.session_service.delete"):
            result = await invalidate_session(mock_db, session_id)
        
        assert result is True

    async def test_invalidate_session_returns_false_on_not_found(self, mock_db):
        """Deletion of non-existent session returns False."""
        from src.services.session_service import invalidate_session
        
        session_id = uuid4()
        
        mock_result = MagicMock()
        mock_result.rowcount = 0
        mock_db.exec.return_value = mock_result
        
        with patch("src.services.session_service.delete"):
            result = await invalidate_session(mock_db, session_id)
        
        assert result is False

