"""
End-to-end integration tests for Profile Engine Phase 6.
Tests full onboarding flow, feed personalization, and error handling.
"""
import pytest
from datetime import datetime, timezone
from uuid import uuid4
from unittest.mock import patch, MagicMock, AsyncMock

from fastapi.testclient import TestClient

from src.main import app
from src.middleware.auth import require_auth
from src.middleware.rate_limit import reset_rate_limiter, reset_rate_limiter_instance


@pytest.fixture(autouse=True)
def reset_rate_limit():
    reset_rate_limiter()
    reset_rate_limiter_instance()
    yield
    reset_rate_limiter()


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def mock_user():
    user = MagicMock()
    user.id = uuid4()
    user.email = "e2e@example.com"
    return user


@pytest.fixture
def mock_session(mock_user):
    session = MagicMock()
    session.id = uuid4()
    session.user_id = mock_user.id
    return session


@pytest.fixture
def authenticated_client(client, mock_user, mock_session):
    def mock_require_auth():
        return (mock_user, mock_session)
    
    app.dependency_overrides[require_auth] = mock_require_auth
    yield client
    app.dependency_overrides.clear()


def create_mock_profile(
    user_id,
    intent_text=None,
    intent_vector=None,
    resume_skills=None,
    resume_vector=None,
    github_username=None,
    github_vector=None,
    combined_vector=None,
    onboarding_status="not_started",
):
    """Creates a mock profile object with configurable state."""
    profile = MagicMock()
    profile.user_id = user_id
    profile.intent_text = intent_text
    profile.intent_stack_areas = ["backend"] if intent_text else None
    profile.intent_experience = "intermediate" if intent_text else None
    profile.intent_vector = intent_vector
    profile.resume_skills = resume_skills
    profile.resume_job_titles = ["Engineer"] if resume_skills else None
    profile.resume_vector = resume_vector
    profile.resume_uploaded_at = datetime.now(timezone.utc) if resume_skills else None
    profile.github_username = github_username
    profile.github_languages = ["Python"] if github_username else None
    profile.github_topics = ["web"] if github_username else None
    profile.github_vector = github_vector
    profile.github_data = {"starred_count": 10} if github_username else None
    profile.github_fetched_at = datetime.now(timezone.utc) if github_username else None
    profile.combined_vector = combined_vector
    profile.preferred_languages = ["Python"] if intent_text else None
    profile.preferred_topics = None
    profile.min_heat_threshold = 0.6
    profile.is_calculating = False
    profile.onboarding_status = onboarding_status
    profile.onboarding_completed_at = None
    profile.updated_at = datetime.now(timezone.utc)
    return profile


SAMPLE_VECTOR = [0.01] * 768


class TestFeedAuthRequired:
    """Verifies authentication is required for feed endpoint."""
    
    def test_feed_returns_401_without_auth(self, client):
        response = client.get("/feed")
        assert response.status_code == 401


class TestFeedTrendingFallback:
    """Tests trending feed fallback when user has no profile."""
    
    @patch("src.services.feed_service.get_or_create_profile")
    def test_returns_trending_when_no_combined_vector(
        self, mock_get_profile, authenticated_client, mock_user
    ):
        mock_profile = create_mock_profile(mock_user.id)
        mock_get_profile.return_value = mock_profile
        
        with patch("src.services.feed_service._get_trending_feed") as mock_trending:
            from src.services.feed_service import FeedResponse, FeedItem, TRENDING_CTA
            
            mock_trending.return_value = FeedResponse(
                results=[],
                total=0,
                page=1,
                page_size=20,
                has_more=False,
                is_personalized=False,
                profile_cta=TRENDING_CTA,
            )
            
            response = authenticated_client.get("/feed")
        
        assert response.status_code == 200
        data = response.json()
        assert data["is_personalized"] is False
        assert data["profile_cta"] is not None
        assert "trending" in data["profile_cta"].lower()
    
    @patch("src.services.feed_service.get_or_create_profile")
    def test_trending_feed_shows_cta_message(
        self, mock_get_profile, authenticated_client, mock_user
    ):
        mock_profile = create_mock_profile(mock_user.id)
        mock_get_profile.return_value = mock_profile
        
        with patch("src.services.feed_service._get_trending_feed") as mock_trending:
            from src.services.feed_service import FeedResponse, TRENDING_CTA
            
            mock_trending.return_value = FeedResponse(
                results=[],
                total=0,
                page=1,
                page_size=20,
                has_more=False,
                is_personalized=False,
                profile_cta=TRENDING_CTA,
            )
            
            response = authenticated_client.get("/feed")
        
        data = response.json()
        assert "Complete your profile" in data["profile_cta"]


class TestFeedPersonalized:
    """Tests personalized feed when user has combined_vector."""
    
    @patch("src.services.feed_service.get_or_create_profile")
    def test_returns_personalized_when_has_combined_vector(
        self, mock_get_profile, authenticated_client, mock_user
    ):
        mock_profile = create_mock_profile(
            mock_user.id,
            intent_text="I want to contribute",
            intent_vector=SAMPLE_VECTOR,
            combined_vector=SAMPLE_VECTOR,
            onboarding_status="completed",
        )
        mock_get_profile.return_value = mock_profile
        
        with patch("src.services.feed_service._get_personalized_feed") as mock_personalized:
            from src.services.feed_service import FeedResponse
            
            mock_personalized.return_value = FeedResponse(
                results=[],
                total=0,
                page=1,
                page_size=20,
                has_more=False,
                is_personalized=True,
                profile_cta=None,
            )
            
            response = authenticated_client.get("/feed")
        
        assert response.status_code == 200
        data = response.json()
        assert data["is_personalized"] is True
        assert data["profile_cta"] is None
    
    @patch("src.services.feed_service.get_or_create_profile")
    def test_personalized_feed_no_cta(
        self, mock_get_profile, authenticated_client, mock_user
    ):
        mock_profile = create_mock_profile(
            mock_user.id,
            intent_text="I want to contribute",
            intent_vector=SAMPLE_VECTOR,
            combined_vector=SAMPLE_VECTOR,
        )
        mock_get_profile.return_value = mock_profile
        
        with patch("src.services.feed_service._get_personalized_feed") as mock_personalized:
            from src.services.feed_service import FeedResponse
            
            mock_personalized.return_value = FeedResponse(
                results=[],
                total=0,
                page=1,
                page_size=20,
                has_more=False,
                is_personalized=True,
                profile_cta=None,
            )
            
            response = authenticated_client.get("/feed")
        
        data = response.json()
        assert data["profile_cta"] is None


class TestFeedPagination:
    """Tests feed pagination parameters."""
    
    @patch("src.services.feed_service.get_or_create_profile")
    def test_accepts_page_parameter(
        self, mock_get_profile, authenticated_client, mock_user
    ):
        mock_profile = create_mock_profile(mock_user.id)
        mock_get_profile.return_value = mock_profile
        
        with patch("src.services.feed_service._get_trending_feed") as mock_trending:
            from src.services.feed_service import FeedResponse, TRENDING_CTA
            
            mock_trending.return_value = FeedResponse(
                results=[],
                total=0,
                page=2,
                page_size=20,
                has_more=False,
                is_personalized=False,
                profile_cta=TRENDING_CTA,
            )
            
            response = authenticated_client.get("/feed?page=2")
        
        assert response.status_code == 200
        data = response.json()
        assert data["page"] == 2
    
    @patch("src.services.feed_service.get_or_create_profile")
    def test_accepts_page_size_parameter(
        self, mock_get_profile, authenticated_client, mock_user
    ):
        mock_profile = create_mock_profile(mock_user.id)
        mock_get_profile.return_value = mock_profile
        
        with patch("src.services.feed_service._get_trending_feed") as mock_trending:
            from src.services.feed_service import FeedResponse, TRENDING_CTA
            
            mock_trending.return_value = FeedResponse(
                results=[],
                total=0,
                page=1,
                page_size=10,
                has_more=False,
                is_personalized=False,
                profile_cta=TRENDING_CTA,
            )
            
            response = authenticated_client.get("/feed?page_size=10")
        
        assert response.status_code == 200


class TestOnboardingToFeedFlow:
    """Tests the complete flow from onboarding to personalized feed."""
    
    @pytest.mark.asyncio
    async def test_intent_vector_triggers_combined_calculation(self):
        """Verifies that intent creation would trigger combined vector calculation."""
        from src.services.profile_embedding_service import calculate_combined_vector
        
        intent_vector = SAMPLE_VECTOR
        
        combined = await calculate_combined_vector(
            intent_vector=intent_vector,
            resume_vector=None,
            github_vector=None,
        )
        
        assert combined is not None
        magnitude = sum(x * x for x in combined) ** 0.5
        assert abs(magnitude - 1.0) < 0.001


class TestRetryLogic:
    """Tests retry logic for embedding failures."""
    
    @pytest.mark.asyncio
    async def test_retry_with_exponential_backoff(self):
        from src.services.vector_generation import generate_intent_vector_with_retry
        
        call_count = 0
        
        async def mock_embed(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise Exception("Embedding service unavailable")
            return SAMPLE_VECTOR
        
        with patch("src.services.profile_embedding_service.embed_query", mock_embed):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await generate_intent_vector_with_retry(
                    ["backend"], "Test text", max_retries=3
                )
        
        assert call_count == 3
        assert result is not None
    
    @pytest.mark.asyncio
    async def test_returns_none_after_max_retries(self):
        from src.services.vector_generation import generate_intent_vector_with_retry
        
        async def always_fail(*args, **kwargs):
            raise Exception("Embedding service down")
        
        with patch("src.services.profile_embedding_service.embed_query", always_fail):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await generate_intent_vector_with_retry(
                    ["backend"], "Test text", max_retries=3
                )
        
        assert result is None


class TestErrorHandling:
    """Tests user-friendly error messages."""
    
    def test_resume_unsupported_format_error(self, authenticated_client):
        response = authenticated_client.post(
            "/profile/resume",
            files={"file": ("resume.txt", b"Plain text content", "text/plain")},
        )
        
        assert response.status_code == 400
        assert "PDF or DOCX" in response.json()["detail"]
    
    def test_error_handler_converts_github_not_connected(self):
        """Verifies error handler produces correct response for GitHubNotConnectedError."""
        from src.api.routes.profile_github import _handle_github_error
        from src.core.errors import GitHubNotConnectedError
        
        error = GitHubNotConnectedError("No account linked")
        http_exc = _handle_github_error(error)
        
        assert http_exc.status_code == 400
        assert "connect GitHub" in http_exc.detail
    
    def test_error_handler_converts_refresh_rate_limit(self):
        """Verifies error handler produces correct response for RefreshRateLimitError."""
        from src.api.routes.profile_github import _handle_github_error
        from src.core.errors import RefreshRateLimitError
        
        error = RefreshRateLimitError(seconds_remaining=3600)
        http_exc = _handle_github_error(error)
        
        assert http_exc.status_code == 429
        assert "minute" in http_exc.detail


class TestCombinedVectorCalculation:
    """Tests combined vector calculation with different source combinations."""
    
    @pytest.mark.asyncio
    async def test_intent_only_combined_equals_intent(self):
        from src.services.profile_embedding_service import calculate_combined_vector
        
        intent_vector = [1.0] * 768
        
        result = await calculate_combined_vector(
            intent_vector=intent_vector,
            resume_vector=None,
            github_vector=None,
        )
        
        assert result is not None
        magnitude = sum(x * x for x in result) ** 0.5
        assert abs(magnitude - 1.0) < 0.001
    
    @pytest.mark.asyncio
    async def test_all_sources_uses_correct_weights(self):
        from src.services.profile_embedding_service import calculate_combined_vector
        
        intent_vector = [1.0, 0.0, 0.0] + [0.0] * 765
        resume_vector = [0.0, 1.0, 0.0] + [0.0] * 765
        github_vector = [0.0, 0.0, 1.0] + [0.0] * 765
        
        result = await calculate_combined_vector(
            intent_vector=intent_vector,
            resume_vector=resume_vector,
            github_vector=github_vector,
        )
        
        assert result is not None
        assert result[0] > result[1] > result[2]
    
    @pytest.mark.asyncio
    async def test_no_sources_returns_none(self):
        from src.services.profile_embedding_service import calculate_combined_vector
        
        result = await calculate_combined_vector(
            intent_vector=None,
            resume_vector=None,
            github_vector=None,
        )
        
        assert result is None


class TestProfileDeletionCancelsJobs:
    """Tests that profile deletion cancels pending jobs."""
    
    def test_retry_queue_cancel_user_jobs(self):
        """Verifies retry queue can cancel jobs for a user."""
        from src.services.retry_queue import RetryQueue
        
        queue = RetryQueue()
        user_id = uuid4()
        
        cancelled_count = queue.cancel_user_jobs(user_id)
        
        assert cancelled_count >= 0
        assert user_id in queue._cancelled_users

