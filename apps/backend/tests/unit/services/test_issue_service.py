"""Unit tests for issue_service."""
import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock, AsyncMock, patch

from src.services.issue_service import (
    get_issue_by_node_id,
    get_similar_issues,
    IssueDetail,
    SimilarIssue,
    MIN_SIMILARITY_THRESHOLD,
    DEFAULT_SIMILAR_LIMIT,
    MAX_SIMILAR_LIMIT,
)


class TestGetIssueByNodeId:
    """Tests for get_issue_by_node_id function."""

    @pytest.mark.asyncio
    async def test_returns_issue_detail_when_found(self):
        """Should return full issue detail when issue exists."""
        mock_db = AsyncMock()
        mock_row = MagicMock()
        mock_row.node_id = "I_abc123"
        mock_row.title = "Fix memory leak"
        mock_row.body = "Full issue body"
        mock_row.labels = ["bug", "memory"]
        mock_row.q_score = 0.85
        mock_row.repo_name = "facebook/react"
        mock_row.repo_url = "https://github.com/facebook/react"
        mock_row.github_url = "https://github.com/facebook/react/issues/123"
        mock_row.primary_language = "JavaScript"
        mock_row.github_created_at = datetime(2026, 1, 5, 10, 0, 0, tzinfo=timezone.utc)
        mock_row.state = "open"
        
        mock_result = MagicMock()
        mock_result.fetchone.return_value = mock_row
        mock_db.execute.return_value = mock_result
        
        result = await get_issue_by_node_id(mock_db, "I_abc123")
        
        assert result is not None
        assert isinstance(result, IssueDetail)
        assert result.node_id == "I_abc123"
        assert result.title == "Fix memory leak"
        assert result.labels == ["bug", "memory"]
        assert result.state == "open"

    @pytest.mark.asyncio
    async def test_returns_none_when_not_found(self):
        """Should return None when issue does not exist."""
        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.fetchone.return_value = None
        mock_db.execute.return_value = mock_result
        
        result = await get_issue_by_node_id(mock_db, "I_nonexistent")
        
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_closed_issue(self):
        """Should return issue even if closed (for detail views)."""
        mock_db = AsyncMock()
        mock_row = MagicMock()
        mock_row.node_id = "I_closed"
        mock_row.title = "Fixed bug"
        mock_row.body = "This was fixed"
        mock_row.labels = []
        mock_row.q_score = 0.7
        mock_row.repo_name = "org/repo"
        mock_row.repo_url = "https://github.com/org/repo"
        mock_row.github_url = "https://github.com/org/repo/issues/1"
        mock_row.primary_language = "Python"
        mock_row.github_created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        mock_row.state = "closed"
        
        mock_result = MagicMock()
        mock_result.fetchone.return_value = mock_row
        mock_db.execute.return_value = mock_result
        
        result = await get_issue_by_node_id(mock_db, "I_closed")
        
        assert result is not None
        assert result.state == "closed"

    @pytest.mark.asyncio
    async def test_handles_empty_labels(self):
        """Should handle issues with no labels."""
        mock_db = AsyncMock()
        mock_row = MagicMock()
        mock_row.node_id = "I_nolabels"
        mock_row.title = "No labels"
        mock_row.body = "Body"
        mock_row.labels = None
        mock_row.q_score = 0.6
        mock_row.repo_name = "org/repo"
        mock_row.repo_url = "https://github.com/org/repo"
        mock_row.github_url = "https://github.com/org/repo/issues/1"
        mock_row.primary_language = None
        mock_row.github_created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        mock_row.state = "open"
        
        mock_result = MagicMock()
        mock_result.fetchone.return_value = mock_row
        mock_db.execute.return_value = mock_result
        
        result = await get_issue_by_node_id(mock_db, "I_nolabels")
        
        assert result is not None
        assert result.labels == []
        assert result.primary_language is None


class TestGetSimilarIssues:
    """Tests for get_similar_issues function."""

    @pytest.mark.asyncio
    async def test_returns_none_when_source_not_found(self):
        """Should return None when source issue doesn't exist."""
        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.fetchone.return_value = None
        mock_db.execute.return_value = mock_result
        
        result = await get_similar_issues(mock_db, "I_nonexistent")
        
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_empty_list_when_no_embedding(self):
        """Should return empty list when source issue has no embedding."""
        mock_db = AsyncMock()
        mock_source_row = MagicMock()
        mock_source_row.node_id = "I_noembedding"
        mock_source_row.embedding = None
        
        mock_result = MagicMock()
        mock_result.fetchone.return_value = mock_source_row
        mock_db.execute.return_value = mock_result
        
        result = await get_similar_issues(mock_db, "I_noembedding")
        
        assert result == []

    @pytest.mark.asyncio
    async def test_returns_similar_issues_ordered_by_similarity(self):
        """Should return similar issues ordered by similarity score."""
        mock_db = AsyncMock()
        
        # First call: get source issue with embedding
        mock_source_row = MagicMock()
        mock_source_row.node_id = "I_source"
        mock_source_row.embedding = [0.1] * 768
        
        # Second call: get similar issues
        mock_similar_row1 = MagicMock()
        mock_similar_row1.node_id = "I_similar1"
        mock_similar_row1.title = "Similar Issue 1"
        mock_similar_row1.repo_name = "org/repo1"
        mock_similar_row1.similarity_score = 0.95
        
        mock_similar_row2 = MagicMock()
        mock_similar_row2.node_id = "I_similar2"
        mock_similar_row2.title = "Similar Issue 2"
        mock_similar_row2.repo_name = "org/repo2"
        mock_similar_row2.similarity_score = 0.85
        
        # Setup mock to return different results for different calls
        mock_result1 = MagicMock()
        mock_result1.fetchone.return_value = mock_source_row
        
        mock_result2 = MagicMock()
        mock_result2.fetchall.return_value = [mock_similar_row1, mock_similar_row2]
        
        mock_db.execute.side_effect = [mock_result1, mock_result2]
        
        result = await get_similar_issues(mock_db, "I_source")
        
        assert result is not None
        assert len(result) == 2
        assert result[0].node_id == "I_similar1"
        assert result[0].similarity_score == 0.95
        assert result[1].similarity_score == 0.85

    @pytest.mark.asyncio
    async def test_excludes_source_issue_from_results(self):
        """Should not include the source issue in similar results."""
        mock_db = AsyncMock()
        
        mock_source_row = MagicMock()
        mock_source_row.node_id = "I_source"
        mock_source_row.embedding = [0.1] * 768
        
        # Similar issues don't include source
        mock_similar = MagicMock()
        mock_similar.node_id = "I_other"
        mock_similar.title = "Other Issue"
        mock_similar.repo_name = "org/repo"
        mock_similar.similarity_score = 0.9
        
        mock_result1 = MagicMock()
        mock_result1.fetchone.return_value = mock_source_row
        
        mock_result2 = MagicMock()
        mock_result2.fetchall.return_value = [mock_similar]
        
        mock_db.execute.side_effect = [mock_result1, mock_result2]
        
        result = await get_similar_issues(mock_db, "I_source")
        
        assert result is not None
        assert len(result) == 1
        assert result[0].node_id != "I_source"

    @pytest.mark.asyncio
    async def test_returns_empty_when_all_closed(self):
        """Should return empty list when all similar issues are closed."""
        mock_db = AsyncMock()
        
        mock_source_row = MagicMock()
        mock_source_row.node_id = "I_source"
        mock_source_row.embedding = [0.1] * 768
        
        mock_result1 = MagicMock()
        mock_result1.fetchone.return_value = mock_source_row
        
        # No open similar issues found
        mock_result2 = MagicMock()
        mock_result2.fetchall.return_value = []
        
        mock_db.execute.side_effect = [mock_result1, mock_result2]
        
        result = await get_similar_issues(mock_db, "I_source")
        
        assert result == []

    @pytest.mark.asyncio
    async def test_respects_limit_parameter(self):
        """Should respect the limit parameter."""
        mock_db = AsyncMock()
        
        mock_source_row = MagicMock()
        mock_source_row.node_id = "I_source"
        mock_source_row.embedding = [0.1] * 768
        
        mock_result1 = MagicMock()
        mock_result1.fetchone.return_value = mock_source_row
        
        mock_result2 = MagicMock()
        mock_result2.fetchall.return_value = []
        
        mock_db.execute.side_effect = [mock_result1, mock_result2]
        
        await get_similar_issues(mock_db, "I_source", limit=3)
        
        # Verify the limit was passed in the query
        call_args = mock_db.execute.call_args_list[1][1]
        assert call_args["limit"] == 3

    @pytest.mark.asyncio
    async def test_clamps_limit_to_max(self):
        """Should clamp limit to MAX_SIMILAR_LIMIT."""
        mock_db = AsyncMock()
        
        mock_source_row = MagicMock()
        mock_source_row.node_id = "I_source"
        mock_source_row.embedding = [0.1] * 768
        
        mock_result1 = MagicMock()
        mock_result1.fetchone.return_value = mock_source_row
        
        mock_result2 = MagicMock()
        mock_result2.fetchall.return_value = []
        
        mock_db.execute.side_effect = [mock_result1, mock_result2]
        
        await get_similar_issues(mock_db, "I_source", limit=100)
        
        call_args = mock_db.execute.call_args_list[1][1]
        assert call_args["limit"] == MAX_SIMILAR_LIMIT

    @pytest.mark.asyncio
    async def test_uses_min_similarity_threshold(self):
        """Should filter by MIN_SIMILARITY_THRESHOLD."""
        mock_db = AsyncMock()
        
        mock_source_row = MagicMock()
        mock_source_row.node_id = "I_source"
        mock_source_row.embedding = [0.1] * 768
        
        mock_result1 = MagicMock()
        mock_result1.fetchone.return_value = mock_source_row
        
        mock_result2 = MagicMock()
        mock_result2.fetchall.return_value = []
        
        mock_db.execute.side_effect = [mock_result1, mock_result2]
        
        await get_similar_issues(mock_db, "I_source")
        
        call_args = mock_db.execute.call_args_list[1][1]
        assert call_args["min_threshold"] == MIN_SIMILARITY_THRESHOLD

    @pytest.mark.asyncio
    async def test_source_closed_finds_open_similar(self):
        """Closed source issue can still find open similar issues."""
        mock_db = AsyncMock()
        
        # Source issue is closed but still has embedding
        mock_source_row = MagicMock()
        mock_source_row.node_id = "I_closed_source"
        mock_source_row.embedding = [0.1] * 768
        
        mock_similar = MagicMock()
        mock_similar.node_id = "I_open_similar"
        mock_similar.title = "Open Similar"
        mock_similar.repo_name = "org/repo"
        mock_similar.similarity_score = 0.9
        
        mock_result1 = MagicMock()
        mock_result1.fetchone.return_value = mock_source_row
        
        mock_result2 = MagicMock()
        mock_result2.fetchall.return_value = [mock_similar]
        
        mock_db.execute.side_effect = [mock_result1, mock_result2]
        
        result = await get_similar_issues(mock_db, "I_closed_source")
        
        # Should still return similar open issues
        assert result is not None
        assert len(result) == 1
        assert result[0].node_id == "I_open_similar"


class TestConstants:
    """Tests for module constants."""

    def test_min_similarity_threshold_is_reasonable(self):
        """MIN_SIMILARITY_THRESHOLD should be between 0 and 1."""
        assert 0 < MIN_SIMILARITY_THRESHOLD < 1
        assert MIN_SIMILARITY_THRESHOLD == 0.3

    def test_default_limit(self):
        """DEFAULT_SIMILAR_LIMIT should be reasonable."""
        assert DEFAULT_SIMILAR_LIMIT == 5

    def test_max_limit(self):
        """MAX_SIMILAR_LIMIT should be reasonable."""
        assert MAX_SIMILAR_LIMIT == 10
