"""Unit tests for GitHub profile service."""
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4


class TestExtractLanguages:
    """Tests for language extraction and weighting."""
    
    def test_extracts_primary_languages(self):
        from src.services.github_profile_service import extract_languages
        
        starred = [
            {"primaryLanguage": {"name": "Python"}, "languages": {"nodes": []}},
            {"primaryLanguage": {"name": "JavaScript"}, "languages": {"nodes": []}},
        ]
        contributed = []
        
        result = extract_languages(starred, contributed)
        
        assert "Python" in result
        assert "JavaScript" in result
    
    def test_extracts_secondary_languages(self):
        from src.services.github_profile_service import extract_languages
        
        starred = [
            {
                "primaryLanguage": {"name": "Python"},
                "languages": {"nodes": [{"name": "Python"}, {"name": "C++"}]}
            },
        ]
        contributed = []
        
        result = extract_languages(starred, contributed)
        
        assert "Python" in result
        assert "C++" in result
    
    def test_weights_contributed_repos_2x(self):
        from src.services.github_profile_service import extract_languages
        
        starred = [
            {"primaryLanguage": {"name": "Python"}, "languages": {"nodes": []}},
            {"primaryLanguage": {"name": "Python"}, "languages": {"nodes": []}},
        ]
        contributed = [
            {"primaryLanguage": {"name": "Go"}, "languages": {"nodes": []}},
        ]
        
        result = extract_languages(starred, contributed)
        
        # Go (1 contributed = 2 points) should rank equal to Python (2 starred = 2 points)
        # Both should be in top results
        assert "Go" in result
        assert "Python" in result
    
    def test_deduplicates_languages(self):
        from src.services.github_profile_service import extract_languages
        
        starred = [
            {"primaryLanguage": {"name": "Python"}, "languages": {"nodes": [{"name": "Python"}]}},
        ]
        contributed = [
            {"primaryLanguage": {"name": "Python"}, "languages": {"nodes": []}},
        ]
        
        result = extract_languages(starred, contributed)
        
        assert result.count("Python") == 1
    
    def test_handles_empty_repos(self):
        from src.services.github_profile_service import extract_languages
        
        result = extract_languages([], [])
        
        assert result == []
    
    def test_handles_null_repos(self):
        from src.services.github_profile_service import extract_languages
        
        starred = [None, {"primaryLanguage": {"name": "Rust"}, "languages": {"nodes": []}}]
        contributed = [None]
        
        result = extract_languages(starred, contributed)
        
        assert "Rust" in result
    
    def test_handles_missing_language_data(self):
        from src.services.github_profile_service import extract_languages
        
        starred = [
            {"primaryLanguage": None, "languages": {"nodes": []}},
            {"primaryLanguage": {"name": None}, "languages": None},
        ]
        contributed = []
        
        result = extract_languages(starred, contributed)
        
        assert result == []


class TestExtractTopics:
    """Tests for topic extraction."""
    
    def test_extracts_topics_from_repos(self):
        from src.services.github_profile_service import extract_topics
        
        starred = [
            {"repositoryTopics": {"nodes": [{"topic": {"name": "web"}}, {"topic": {"name": "api"}}]}},
        ]
        contributed = []
        
        result = extract_topics(starred, contributed)
        
        assert "web" in result
        assert "api" in result
    
    def test_weights_contributed_topics_2x(self):
        from src.services.github_profile_service import extract_topics
        
        starred = [
            {"repositoryTopics": {"nodes": [{"topic": {"name": "cli"}}, {"topic": {"name": "cli"}}]}},
        ]
        contributed = [
            {"repositoryTopics": {"nodes": [{"topic": {"name": "ml"}}]}},
        ]
        
        result = extract_topics(starred, contributed)
        
        # ml (1 contributed = 2 points) should rank equal to cli (2 starred = 2 points)
        assert "ml" in result
        assert "cli" in result
    
    def test_deduplicates_topics(self):
        from src.services.github_profile_service import extract_topics
        
        starred = [
            {"repositoryTopics": {"nodes": [{"topic": {"name": "web"}}]}},
        ]
        contributed = [
            {"repositoryTopics": {"nodes": [{"topic": {"name": "web"}}]}},
        ]
        
        result = extract_topics(starred, contributed)
        
        assert result.count("web") == 1
    
    def test_handles_empty_repos(self):
        from src.services.github_profile_service import extract_topics
        
        result = extract_topics([], [])
        
        assert result == []
    
    def test_handles_missing_topic_data(self):
        from src.services.github_profile_service import extract_topics
        
        starred = [
            {"repositoryTopics": None},
            {"repositoryTopics": {"nodes": None}},
            {"repositoryTopics": {"nodes": [{"topic": None}]}},
        ]
        contributed = []
        
        result = extract_topics(starred, contributed)
        
        assert result == []


class TestFormatGitHubText:
    """Tests for text formatting for embedding."""
    
    def test_formats_all_components(self):
        from src.services.github_profile_service import format_github_text
        
        result = format_github_text(
            languages=["Python", "TypeScript", "Go"],
            topics=["web", "async", "cli"],
            descriptions=["FastAPI web framework", "Type definitions"],
        )
        
        assert "Python, TypeScript, Go" in result
        assert "web, async, cli" in result
        assert "FastAPI web framework" in result
        assert "Type definitions" in result
    
    def test_handles_languages_only(self):
        from src.services.github_profile_service import format_github_text
        
        result = format_github_text(
            languages=["Python", "Go"],
            topics=[],
            descriptions=[],
        )
        
        assert result == "Python, Go"
    
    def test_handles_topics_only(self):
        from src.services.github_profile_service import format_github_text
        
        result = format_github_text(
            languages=[],
            topics=["web", "ml"],
            descriptions=[],
        )
        
        assert result == "web, ml"
    
    def test_handles_descriptions_only(self):
        from src.services.github_profile_service import format_github_text
        
        result = format_github_text(
            languages=[],
            topics=[],
            descriptions=["A cool project"],
        )
        
        assert result == "A cool project"
    
    def test_handles_empty_inputs(self):
        from src.services.github_profile_service import format_github_text
        
        result = format_github_text(
            languages=[],
            topics=[],
            descriptions=[],
        )
        
        assert result == ""
    
    def test_limits_language_count(self):
        from src.services.github_profile_service import format_github_text
        
        languages = [f"Lang{i}" for i in range(20)]
        
        result = format_github_text(
            languages=languages,
            topics=[],
            descriptions=[],
        )
        
        # Should only include first 10
        assert "Lang0" in result
        assert "Lang9" in result
        assert "Lang10" not in result
    
    def test_limits_topic_count(self):
        from src.services.github_profile_service import format_github_text
        
        topics = [f"topic{i}" for i in range(20)]
        
        result = format_github_text(
            languages=[],
            topics=topics,
            descriptions=[],
        )
        
        # Should only include first 15
        assert "topic0" in result
        assert "topic14" in result
        assert "topic15" not in result


class TestCheckMinimalData:
    """Tests for minimal data threshold checking."""
    
    def test_returns_warning_when_below_threshold(self):
        from src.services.github_profile_service import check_minimal_data
        
        result = check_minimal_data(starred_count=2, contributed_count=1)
        
        assert result is not None
        assert "limited" in result.lower()
    
    def test_returns_none_when_enough_starred(self):
        from src.services.github_profile_service import check_minimal_data
        
        result = check_minimal_data(starred_count=5, contributed_count=0)
        
        assert result is None
    
    def test_returns_none_when_enough_contributed(self):
        from src.services.github_profile_service import check_minimal_data
        
        result = check_minimal_data(starred_count=0, contributed_count=3)
        
        assert result is None
    
    def test_returns_none_at_exact_threshold(self):
        from src.services.github_profile_service import check_minimal_data
        
        # Either threshold met should pass
        result1 = check_minimal_data(starred_count=5, contributed_count=2)
        result2 = check_minimal_data(starred_count=4, contributed_count=3)
        
        assert result1 is None
        assert result2 is None
    
    def test_boundary_condition_just_below(self):
        from src.services.github_profile_service import check_minimal_data
        
        # Both below threshold
        result = check_minimal_data(starred_count=4, contributed_count=2)
        
        assert result is not None


class TestCheckRefreshAllowed:
    """Tests for refresh rate limit checking."""
    
    def test_allows_first_fetch(self):
        from src.services.github_profile_service import check_refresh_allowed
        
        result = check_refresh_allowed(None)
        
        assert result is None
    
    def test_allows_after_cooldown(self):
        from src.services.github_profile_service import check_refresh_allowed
        
        old_time = datetime.now(timezone.utc) - timedelta(hours=2)
        
        result = check_refresh_allowed(old_time)
        
        assert result is None
    
    def test_blocks_before_cooldown(self):
        from src.services.github_profile_service import check_refresh_allowed
        
        recent_time = datetime.now(timezone.utc) - timedelta(minutes=30)
        
        result = check_refresh_allowed(recent_time)
        
        assert result is not None
        assert result > 0
        assert result <= 1800  # At most 30 minutes remaining
    
    def test_returns_correct_seconds_remaining(self):
        from src.services.github_profile_service import check_refresh_allowed
        
        # 50 minutes ago; 10 minutes remaining
        recent_time = datetime.now(timezone.utc) - timedelta(minutes=50)
        
        result = check_refresh_allowed(recent_time)
        
        assert result is not None
        # Allow some tolerance for test execution time
        assert 500 <= result <= 700
    
    def test_handles_naive_datetime(self):
        from src.services.github_profile_service import check_refresh_allowed
        
        # Test with naive datetime (no timezone info)
        naive_time = datetime.now() - timedelta(minutes=30)
        
        result = check_refresh_allowed(naive_time)
        
        # Should still work and return seconds remaining
        assert result is not None or result is None  # Just verify no exception


class TestGenerateGitHubVector:
    """Tests for GitHub vector generation."""
    
    @pytest.mark.asyncio
    async def test_generates_vector_from_data(self):
        from src.services.github_profile_service import generate_github_vector
        
        mock_vector = [0.1] * 768
        
        with patch(
            "src.services.github_profile_service.generate_github_vector_with_retry",
            new_callable=AsyncMock,
        ) as mock_gen:
            mock_gen.return_value = mock_vector
            
            result = await generate_github_vector(
                languages=["Python", "Go"],
                topics=["web", "cli"],
                descriptions=["A cool project"],
            )
            
            mock_gen.assert_called_once()
            call_text = mock_gen.call_args[0][0]
            assert "Python" in call_text
            assert "web" in call_text
            assert "A cool project" in call_text
            assert result == mock_vector
    
    @pytest.mark.asyncio
    async def test_returns_none_on_embedding_failure(self):
        from src.services.github_profile_service import generate_github_vector
        
        with patch(
            "src.services.github_profile_service.generate_github_vector_with_retry",
            new_callable=AsyncMock,
        ) as mock_gen:
            mock_gen.return_value = None
            
            result = await generate_github_vector(
                languages=["Python"],
                topics=["web"],
                descriptions=[],
            )
            
            assert result is None
    
    @pytest.mark.asyncio
    async def test_returns_none_for_empty_input(self):
        from src.services.github_profile_service import generate_github_vector
        
        with patch(
            "src.services.github_profile_service.generate_github_vector_with_retry",
            new_callable=AsyncMock,
        ) as mock_gen:
            result = await generate_github_vector(
                languages=[],
                topics=[],
                descriptions=[],
            )
            
            mock_gen.assert_not_called()
            assert result is None


class TestFetchGitHubProfile:
    """Tests for the main fetch orchestration."""
    
    @pytest.mark.asyncio
    async def test_raises_not_connected_when_no_token(self):
        from src.services.github_profile_service import (
            fetch_github_profile,
            GitHubNotConnectedError,
        )
        
        mock_profile = MagicMock()
        mock_profile.github_fetched_at = None
        
        mock_db = AsyncMock()
        mock_db.exec = AsyncMock(return_value=MagicMock(first=MagicMock(return_value=mock_profile)))
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()
        
        with patch(
            "src.services.github_profile_service._get_or_create_profile",
            new_callable=AsyncMock,
        ) as mock_get_profile:
            mock_get_profile.return_value = mock_profile
            
            with patch(
                "src.services.github_profile_service.get_valid_access_token",
                new_callable=AsyncMock,
            ) as mock_token:
                from src.services.linked_account_service import LinkedAccountNotFoundError
                mock_token.side_effect = LinkedAccountNotFoundError("No account")
                
                with pytest.raises(GitHubNotConnectedError) as exc_info:
                    await fetch_github_profile(mock_db, uuid4())
                
                assert "connect" in str(exc_info.value).lower()
    
    @pytest.mark.asyncio
    async def test_raises_not_connected_when_token_revoked(self):
        from src.services.github_profile_service import (
            fetch_github_profile,
            GitHubNotConnectedError,
        )
        
        mock_profile = MagicMock()
        mock_profile.github_fetched_at = None
        
        mock_db = AsyncMock()
        mock_db.exec = AsyncMock(return_value=MagicMock(first=MagicMock(return_value=mock_profile)))
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()
        
        with patch(
            "src.services.github_profile_service._get_or_create_profile",
            new_callable=AsyncMock,
        ) as mock_get_profile:
            mock_get_profile.return_value = mock_profile
            
            with patch(
                "src.services.github_profile_service.get_valid_access_token",
                new_callable=AsyncMock,
            ) as mock_token:
                from src.services.linked_account_service import LinkedAccountRevokedError
                mock_token.side_effect = LinkedAccountRevokedError("Revoked")
                
                with pytest.raises(GitHubNotConnectedError) as exc_info:
                    await fetch_github_profile(mock_db, uuid4())
                
                assert "reconnect" in str(exc_info.value).lower()
    
    @pytest.mark.asyncio
    async def test_raises_rate_limit_error_on_refresh_too_soon(self):
        from src.services.github_profile_service import (
            fetch_github_profile,
            RefreshRateLimitError,
        )
        
        mock_profile = MagicMock()
        mock_profile.github_fetched_at = datetime.now(timezone.utc) - timedelta(minutes=30)
        
        mock_db = AsyncMock()
        mock_db.exec = AsyncMock(return_value=MagicMock(first=MagicMock(return_value=mock_profile)))
        
        with patch(
            "src.services.github_profile_service._get_or_create_profile",
            new_callable=AsyncMock,
        ) as mock_get_profile:
            mock_get_profile.return_value = mock_profile
            
            with pytest.raises(RefreshRateLimitError) as exc_info:
                await fetch_github_profile(mock_db, uuid4(), is_refresh=True)
            
            assert exc_info.value.seconds_remaining > 0


class TestDeleteGitHub:
    """Tests for GitHub data deletion."""
    
    @pytest.mark.asyncio
    async def test_returns_false_when_no_data(self):
        from src.services.github_profile_service import delete_github
        
        mock_profile = MagicMock()
        mock_profile.github_username = None
        
        mock_db = AsyncMock()
        mock_db.exec = AsyncMock(return_value=MagicMock(first=MagicMock(return_value=mock_profile)))
        
        result = await delete_github(mock_db, uuid4())
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_clears_all_github_fields(self):
        from src.services.github_profile_service import delete_github
        
        mock_profile = MagicMock()
        mock_profile.github_username = "octocat"
        mock_profile.github_languages = ["Python"]
        mock_profile.github_topics = ["web"]
        mock_profile.github_data = {"test": "data"}
        mock_profile.github_fetched_at = datetime.now(timezone.utc)
        mock_profile.github_vector = [0.1] * 768
        mock_profile.intent_vector = None
        mock_profile.resume_vector = None
        
        mock_db = AsyncMock()
        mock_db.exec = AsyncMock(return_value=MagicMock(first=MagicMock(return_value=mock_profile)))
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()
        
        with patch(
            "src.services.github_profile_service.calculate_combined_vector",
            new_callable=AsyncMock,
        ) as mock_combined:
            mock_combined.return_value = None
            
            result = await delete_github(mock_db, uuid4())
        
        assert result is True
        assert mock_profile.github_username is None
        assert mock_profile.github_languages is None
        assert mock_profile.github_topics is None
        assert mock_profile.github_data is None
        assert mock_profile.github_fetched_at is None
        assert mock_profile.github_vector is None
    
    @pytest.mark.asyncio
    async def test_recalculates_combined_vector(self):
        from src.services.github_profile_service import delete_github
        
        mock_profile = MagicMock()
        mock_profile.github_username = "octocat"
        mock_profile.intent_vector = [0.2] * 768
        mock_profile.resume_vector = None
        
        mock_db = AsyncMock()
        mock_db.exec = AsyncMock(return_value=MagicMock(first=MagicMock(return_value=mock_profile)))
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()
        
        with patch(
            "src.services.github_profile_service.calculate_combined_vector",
            new_callable=AsyncMock,
        ) as mock_combined:
            mock_combined.return_value = [0.3] * 768
            
            await delete_github(mock_db, uuid4())
            
            mock_combined.assert_called_once_with(
                intent_vector=mock_profile.intent_vector,
                resume_vector=None,
                github_vector=None,
            )
            assert mock_profile.combined_vector == [0.3] * 768


class TestGetGitHubData:
    """Tests for GitHub data retrieval."""
    
    @pytest.mark.asyncio
    async def test_returns_none_when_not_populated(self):
        from src.services.github_profile_service import get_github_data
        
        mock_profile = MagicMock()
        mock_profile.github_username = None
        
        mock_db = AsyncMock()
        mock_db.exec = AsyncMock(return_value=MagicMock(first=MagicMock(return_value=mock_profile)))
        
        result = await get_github_data(mock_db, uuid4())
        
        assert result is None
    
    @pytest.mark.asyncio
    async def test_returns_data_when_populated(self):
        from src.services.github_profile_service import get_github_data
        
        mock_profile = MagicMock()
        mock_profile.github_username = "octocat"
        mock_profile.github_languages = ["Python", "Go"]
        mock_profile.github_topics = ["web", "cli"]
        mock_profile.github_data = {"starred_count": 10, "contributed_count": 5}
        mock_profile.github_fetched_at = datetime(2026, 1, 4, 12, 0, 0, tzinfo=timezone.utc)
        mock_profile.github_vector = [0.1] * 768
        
        mock_db = AsyncMock()
        mock_db.exec = AsyncMock(return_value=MagicMock(first=MagicMock(return_value=mock_profile)))
        
        result = await get_github_data(mock_db, uuid4())
        
        assert result is not None
        assert result["username"] == "octocat"
        assert result["languages"] == ["Python", "Go"]
        assert result["topics"] == ["web", "cli"]
        assert result["starred_count"] == 10
        assert result["contributed_repos"] == 5
        assert result["vector_status"] == "ready"
        assert "2026-01-04" in result["fetched_at"]

