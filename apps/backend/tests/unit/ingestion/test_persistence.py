"""Unit tests for streaming persistence layer"""

import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

from src.ingestion.embeddings import EmbeddedIssue
from src.ingestion.gatherer import IssueData
from src.ingestion.quality_gate import QScoreComponents
from src.ingestion.scout import RepositoryData
from src.ingestion.survival_score import calculate_survival_score, days_since


@pytest.fixture
def mock_session():
    session = AsyncMock()
    session.execute = AsyncMock()
    session.commit = AsyncMock()
    return session


@pytest.fixture
def persistence(mock_session, monkeypatch):
    """Create StreamingPersistence with mocked dependencies."""
    # Mock sqlalchemy and sqlmodel before importing
    mock_sqlalchemy = MagicMock()
    mock_sqlalchemy.text = MagicMock()
    
    monkeypatch.setitem(__import__('sys').modules, "sqlalchemy", mock_sqlalchemy)
    monkeypatch.setitem(__import__('sys').modules, "sqlalchemy.text", MagicMock())
    monkeypatch.setitem(__import__('sys').modules, "sqlmodel", MagicMock())
    monkeypatch.setitem(__import__('sys').modules, "sqlmodel.ext", MagicMock())
    monkeypatch.setitem(__import__('sys').modules, "sqlmodel.ext.asyncio", MagicMock())
    monkeypatch.setitem(__import__('sys').modules, "sqlmodel.ext.asyncio.session", MagicMock())
    
    # Import here after mocks are set up
    from src.ingestion.persistence import StreamingPersistence
    return StreamingPersistence(session=mock_session)


@pytest.fixture
def sample_q_components():
    return QScoreComponents(
        has_code=True,
        has_headers=True,
        tech_weight=0.5,
        is_junk=False,
    )


@pytest.fixture
def make_embedded_issue(sample_q_components):
    def _make(node_id: str = "I_123", q_score: float = 0.75):
        issue = IssueData(
            node_id=node_id,
            repo_id="R_456",
            title="Bug report",
            body_text="Description",
            labels=["bug"],
            github_created_at=datetime.now(timezone.utc),
            q_score=q_score,
            q_components=sample_q_components,
        )
        return EmbeddedIssue(
            issue=issue,
            embedding=[0.1] * 768,
        )
    return _make


@pytest.fixture
def make_repository():
    def _make(node_id: str = "R_123", full_name: str = "owner/repo"):
        return RepositoryData(
            node_id=node_id,
            full_name=full_name,
            primary_language="Python",
            stargazer_count=1000,
            issue_count_open=50,
            topics=["python", "api"],
        )
    return _make


class TestStreamingPersistence:
    def test_batch_size_is_50(self, persistence):
        assert persistence.BATCH_SIZE == 50


class TestUpsertRepositories:
    async def test_upserts_single_repo(self, persistence, mock_session, make_repository):
        repo = make_repository()
        
        count = await persistence.upsert_repositories([repo])
        
        assert count == 1
        mock_session.execute.assert_called_once()
        mock_session.commit.assert_called_once()

    async def test_upserts_multiple_repos(self, persistence, mock_session, make_repository):
        repos = [make_repository(f"R_{i}", f"owner/repo{i}") for i in range(5)]
        
        count = await persistence.upsert_repositories(repos)
        
        assert count == 5
        mock_session.execute.assert_called_once()

    async def test_returns_zero_for_empty_list(self, persistence, mock_session):
        count = await persistence.upsert_repositories([])
        
        assert count == 0
        mock_session.execute.assert_not_called()

    async def test_passes_correct_params(self, persistence, mock_session, make_repository):
        repo = make_repository(node_id="R_test", full_name="test/repo")
        
        await persistence.upsert_repositories([repo])
        
        call_args = mock_session.execute.call_args[0][1]
        assert call_args["node_id_0"] == "R_test"
        assert call_args["full_name_0"] == "test/repo"
        assert call_args["primary_language_0"] == "Python"
        assert call_args["stargazer_count_0"] == 1000


class TestPersistStream:
    async def test_persists_single_issue(self, persistence, mock_session, make_embedded_issue):
        async def single_issue():
            yield make_embedded_issue()
        
        count = await persistence.persist_stream(single_issue())
        
        assert count == 1
        mock_session.execute.assert_called_once()
        mock_session.commit.assert_called()

    async def test_batches_at_50(self, persistence, mock_session, make_embedded_issue):
        async def issue_stream():
            for i in range(50):
                yield make_embedded_issue(node_id=f"I_{i}")
        
        count = await persistence.persist_stream(issue_stream())
        
        assert count == 50
        assert mock_session.execute.call_count == 1

    async def test_two_batches_for_75_issues(self, persistence, mock_session, make_embedded_issue):
        async def issue_stream():
            for i in range(75):
                yield make_embedded_issue(node_id=f"I_{i}")
        
        count = await persistence.persist_stream(issue_stream())
        
        assert count == 75
        assert mock_session.execute.call_count == 2

    async def test_handles_empty_stream(self, persistence, mock_session):
        async def empty_stream():
            return
            yield
        
        count = await persistence.persist_stream(empty_stream())
        
        assert count == 0
        mock_session.execute.assert_not_called()


class TestSurvivalScoreInjection:
    async def test_survival_score_calculated(self, persistence, mock_session, make_embedded_issue):
        """Verify survival_score parameter is passed to SQL"""
        async def single_issue():
            yield make_embedded_issue(q_score=0.8)
        
        await persistence.persist_stream(single_issue())
        
        call_args = mock_session.execute.call_args[0][1]
        assert "survival_score_0" in call_args
        assert call_args["survival_score_0"] > 0

    async def test_higher_q_score_means_higher_survival(self, persistence, mock_session, make_embedded_issue):
        """Verify Q-score affects survival score"""
        survival_scores = []
        
        for q in [0.3, 0.9]:
            mock_session.reset_mock()
            
            async def single_issue():
                yield make_embedded_issue(q_score=q)
            
            await persistence.persist_stream(single_issue())
            
            params = mock_session.execute.call_args[0][1]
            survival_scores.append(params["survival_score_0"])
        
        assert survival_scores[1] > survival_scores[0]  # 0.9 > 0.3


class TestQScoreComponents:
    async def test_passes_q_components_to_sql(self, persistence, mock_session, make_embedded_issue):
        """Verify Q-score components are stored as separate columns"""
        async def single_issue():
            yield make_embedded_issue()
        
        await persistence.persist_stream(single_issue())
        
        call_args = mock_session.execute.call_args[0][1]
        assert "has_code_0" in call_args
        assert "has_template_headers_0" in call_args
        assert "tech_stack_weight_0" in call_args
        assert call_args["has_code_0"] is True
        assert call_args["has_template_headers_0"] is True
        assert call_args["tech_stack_weight_0"] == 0.5


class TestEmbeddingStorage:
    async def test_embedding_passed_as_string(self, persistence, mock_session, make_embedded_issue):
        """Verify embedding is serialized for pgvector"""
        async def single_issue():
            yield make_embedded_issue()
        
        await persistence.persist_stream(single_issue())
        
        call_args = mock_session.execute.call_args[0][1]
        embedding_param = call_args["embedding_0"]
        # Should be string representation of list for ::vector cast
        assert isinstance(embedding_param, str)
        assert embedding_param.startswith("[")
