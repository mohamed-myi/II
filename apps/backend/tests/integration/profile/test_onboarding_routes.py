"""Integration tests for onboarding API routes."""
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
    user.email = "test@example.com"
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


class TestAuthRequired:
    """Verifies authentication middleware is applied to onboarding routes."""
    
    @pytest.mark.parametrize("method,path", [
        ("get", "/profile/onboarding"),
        ("post", "/profile/onboarding/complete"),
        ("post", "/profile/onboarding/skip"),
        ("get", "/profile/preview-recommendations"),
    ])
    def test_returns_401_without_auth(self, client, method, path):
        response = getattr(client, method)(path)
        assert response.status_code == 401


class TestGetOnboarding:
    """Tests for GET /profile/onboarding endpoint."""
    
    def test_returns_not_started_for_new_user(self, authenticated_client):
        from src.services.onboarding_service import OnboardingState
        
        mock_state = OnboardingState(
            status="not_started",
            completed_steps=[],
            available_steps=["welcome", "intent", "github", "resume", "preferences"],
            can_complete=False,
        )
        
        with patch(
            "src.api.routes.profile_onboarding.get_onboarding_status",
            new_callable=AsyncMock,
            return_value=mock_state,
        ):
            response = authenticated_client.get("/profile/onboarding")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "not_started"
        assert data["completed_steps"] == []
        assert data["can_complete"] is False
    
    def test_returns_in_progress_with_intent(self, authenticated_client):
        from src.services.onboarding_service import OnboardingState
        
        mock_state = OnboardingState(
            status="in_progress",
            completed_steps=["welcome", "intent", "preferences"],
            available_steps=["github", "resume"],
            can_complete=True,
        )
        
        with patch(
            "src.api.routes.profile_onboarding.get_onboarding_status",
            new_callable=AsyncMock,
            return_value=mock_state,
        ):
            response = authenticated_client.get("/profile/onboarding")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "in_progress"
        assert "welcome" in data["completed_steps"]
        assert "intent" in data["completed_steps"]
        assert data["can_complete"] is True
    
    def test_returns_completed_status(self, authenticated_client):
        from src.services.onboarding_service import OnboardingState
        
        mock_state = OnboardingState(
            status="completed",
            completed_steps=["welcome", "intent", "preferences"],
            available_steps=["github", "resume"],
            can_complete=True,
        )
        
        with patch(
            "src.api.routes.profile_onboarding.get_onboarding_status",
            new_callable=AsyncMock,
            return_value=mock_state,
        ):
            response = authenticated_client.get("/profile/onboarding")
        
        assert response.status_code == 200
        assert response.json()["status"] == "completed"


class TestCompleteOnboarding:
    """Tests for POST /profile/onboarding/complete endpoint."""
    
    def test_complete_succeeds_with_source(self, authenticated_client):
        from src.services.onboarding_service import OnboardingState
        
        mock_state = OnboardingState(
            status="completed",
            completed_steps=["welcome", "intent", "preferences"],
            available_steps=["github", "resume"],
            can_complete=True,
        )
        
        with patch(
            "src.api.routes.profile_onboarding.complete_onboarding",
            new_callable=AsyncMock,
            return_value=mock_state,
        ):
            response = authenticated_client.post("/profile/onboarding/complete")
        
        assert response.status_code == 200
        assert response.json()["status"] == "completed"
    
    def test_complete_fails_without_sources(self, authenticated_client):
        from src.services.onboarding_service import CannotCompleteOnboardingError
        
        with patch(
            "src.api.routes.profile_onboarding.complete_onboarding",
            new_callable=AsyncMock,
            side_effect=CannotCompleteOnboardingError("Cannot complete without sources"),
        ):
            response = authenticated_client.post("/profile/onboarding/complete")
        
        assert response.status_code == 400
        assert "Cannot complete" in response.json()["detail"]
    
    def test_complete_returns_409_when_already_completed(self, authenticated_client):
        from src.services.onboarding_service import OnboardingAlreadyCompletedError
        
        with patch(
            "src.api.routes.profile_onboarding.complete_onboarding",
            new_callable=AsyncMock,
            side_effect=OnboardingAlreadyCompletedError("Onboarding already completed"),
        ):
            response = authenticated_client.post("/profile/onboarding/complete")
        
        assert response.status_code == 409
        assert "already" in response.json()["detail"]


class TestSkipOnboarding:
    """Tests for POST /profile/onboarding/skip endpoint."""
    
    def test_skip_succeeds_without_sources(self, authenticated_client):
        from src.services.onboarding_service import OnboardingState
        
        mock_state = OnboardingState(
            status="skipped",
            completed_steps=["welcome"],
            available_steps=["intent", "github", "resume", "preferences"],
            can_complete=False,
        )
        
        with patch(
            "src.api.routes.profile_onboarding.skip_onboarding",
            new_callable=AsyncMock,
            return_value=mock_state,
        ):
            response = authenticated_client.post("/profile/onboarding/skip")
        
        assert response.status_code == 200
        assert response.json()["status"] == "skipped"
    
    def test_skip_returns_409_when_already_skipped(self, authenticated_client):
        from src.services.onboarding_service import OnboardingAlreadyCompletedError
        
        with patch(
            "src.api.routes.profile_onboarding.skip_onboarding",
            new_callable=AsyncMock,
            side_effect=OnboardingAlreadyCompletedError("Onboarding already skipped"),
        ):
            response = authenticated_client.post("/profile/onboarding/skip")
        
        assert response.status_code == 409


class TestPreviewRecommendations:
    """Tests for GET /profile/preview-recommendations endpoint."""
    
    def test_returns_issues_with_intent_vector(self, authenticated_client):
        from src.services.recommendation_preview_service import PreviewIssue
        
        mock_issues = [
            PreviewIssue(
                node_id="MDU6SXNzdWUx",
                title="Fix async bug",
                repo_name="fastapi/fastapi",
                primary_language="Python",
                q_score=0.85,
            ),
            PreviewIssue(
                node_id="MDU6SXNzdWUy",
                title="Add TypeScript support",
                repo_name="vercel/next.js",
                primary_language="TypeScript",
                q_score=0.78,
            ),
            PreviewIssue(
                node_id="MDU6SXNzdWUz",
                title="Improve error handling",
                repo_name="rust-lang/rust",
                primary_language="Rust",
                q_score=0.72,
            ),
        ]
        
        with patch(
            "src.api.routes.profile_onboarding.get_preview_recommendations",
            new_callable=AsyncMock,
            return_value=mock_issues,
        ):
            response = authenticated_client.get(
                "/profile/preview-recommendations?source=intent"
            )
        
        assert response.status_code == 200
        data = response.json()
        assert data["source"] == "intent"
        assert len(data["issues"]) == 3
        assert data["issues"][0]["title"] == "Fix async bug"
        assert data["issues"][0]["q_score"] == 0.85
    
    def test_returns_empty_without_vector(self, authenticated_client):
        with patch(
            "src.api.routes.profile_onboarding.get_preview_recommendations",
            new_callable=AsyncMock,
            return_value=[],
        ):
            response = authenticated_client.get(
                "/profile/preview-recommendations?source=intent"
            )
        
        assert response.status_code == 200
        assert response.json()["issues"] == []
    
    def test_returns_trending_when_no_source(self, authenticated_client):
        from src.services.recommendation_preview_service import PreviewIssue
        
        mock_issues = [
            PreviewIssue(
                node_id="MDU6SXNzdWUx",
                title="Trending issue",
                repo_name="popular/repo",
                primary_language="Python",
                q_score=0.95,
            ),
        ]
        
        with patch(
            "src.api.routes.profile_onboarding.get_preview_recommendations",
            new_callable=AsyncMock,
            return_value=mock_issues,
        ):
            response = authenticated_client.get("/profile/preview-recommendations")
        
        assert response.status_code == 200
        data = response.json()
        assert data["source"] is None
        assert len(data["issues"]) == 1
    
    def test_validates_source_parameter(self, authenticated_client):
        from src.services.recommendation_preview_service import InvalidSourceError
        
        with patch(
            "src.api.routes.profile_onboarding.get_preview_recommendations",
            new_callable=AsyncMock,
            side_effect=InvalidSourceError("Invalid source: 'invalid'"),
        ):
            response = authenticated_client.get(
                "/profile/preview-recommendations?source=invalid"
            )
        
        assert response.status_code == 400
        assert "Invalid source" in response.json()["detail"]
    
    def test_accepts_resume_source(self, authenticated_client):
        with patch(
            "src.api.routes.profile_onboarding.get_preview_recommendations",
            new_callable=AsyncMock,
            return_value=[],
        ):
            response = authenticated_client.get(
                "/profile/preview-recommendations?source=resume"
            )
        
        assert response.status_code == 200
        assert response.json()["source"] == "resume"
    
    def test_accepts_github_source(self, authenticated_client):
        with patch(
            "src.api.routes.profile_onboarding.get_preview_recommendations",
            new_callable=AsyncMock,
            return_value=[],
        ):
            response = authenticated_client.get(
                "/profile/preview-recommendations?source=github"
            )
        
        assert response.status_code == 200
        assert response.json()["source"] == "github"


class TestOnboardingAfterIntentCreate:
    """Integration tests verifying onboarding updates after intent creation."""
    
    def test_creating_intent_transitions_onboarding_to_in_progress(
        self, authenticated_client
    ):
        """
        Verifies that creating intent via POST /profile/intent
        transitions onboarding status from not_started to in_progress.
        """
        from models.profiles import UserProfile
        from src.services.onboarding_service import OnboardingState
        
        mock_profile = MagicMock(spec=UserProfile)
        mock_profile.intent_text = "I want to contribute"
        mock_profile.intent_stack_areas = ["backend"]
        mock_profile.intent_experience = "intermediate"
        mock_profile.intent_vector = [0.1] * 768
        mock_profile.preferred_languages = ["Python"]
        mock_profile.updated_at = datetime.now(timezone.utc)
        mock_profile.onboarding_status = "in_progress"
        
        with patch(
            "src.api.routes.profile.create_intent_service",
            new_callable=AsyncMock,
            return_value=mock_profile,
        ):
            response = authenticated_client.post("/profile/intent", json={
                "languages": ["Python"],
                "stack_areas": ["backend"],
                "text": "I want to contribute to open source Python projects",
                "experience_level": "intermediate",
            })
        
        assert response.status_code == 201
        
        mock_state = OnboardingState(
            status="in_progress",
            completed_steps=["welcome", "intent", "preferences"],
            available_steps=["github", "resume"],
            can_complete=True,
        )
        
        with patch(
            "src.api.routes.profile_onboarding.get_onboarding_status",
            new_callable=AsyncMock,
            return_value=mock_state,
        ):
            onboarding_response = authenticated_client.get("/profile/onboarding")
        
        assert onboarding_response.status_code == 200
        data = onboarding_response.json()
        assert data["status"] == "in_progress"
        assert "intent" in data["completed_steps"]

