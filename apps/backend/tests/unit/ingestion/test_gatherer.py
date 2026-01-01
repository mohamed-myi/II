"""Unit tests for Gatherer streaming issue harvester"""

import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from src.ingestion.gatherer import (
    Gatherer,
    IssueData,
    BODY_TRUNCATE_LENGTH,
)
from src.ingestion.scout import RepositoryData
from src.ingestion.quality_gate import QScoreComponents


@pytest.fixture
def mock_client():
    client = AsyncMock()
    client.execute_query = AsyncMock()
    return client


@pytest.fixture
def gatherer(mock_client):
    return Gatherer(client=mock_client)


@pytest.fixture
def sample_repo():
    return RepositoryData(
        node_id="R_kgDOHDq123",
        full_name="facebook/react",
        primary_language="TypeScript",
        stargazer_count=200000,
        issue_count_open=500,
        topics=["react", "javascript"],
    )


def make_issue_node(
    node_id: str = "I_kwDOHDq123",
    title: str = "Bug report",
    body: str = "## Description\n```typescript\nthrow new TypeError()\n```",
    created_at: str = "2024-01-15T12:00:00Z",
    labels: list[str] | None = None,
):
    return {
        "id": node_id,
        "title": title,
        "bodyText": body,
        "createdAt": created_at,
        "labels": {
            "nodes": [{"name": l} for l in (labels or [])]
        },
    }


class TestParseIssue:

    def test_parses_complete_node(self, gatherer, sample_repo):
        node = make_issue_node(
            node_id="I_123",
            title="TypeError in component",
            body="## Description\n```typescript\ncode\n```",
            labels=["bug", "high-priority"],
        )

        issue = gatherer._parse_issue(node, sample_repo)

        assert issue is not None
        assert issue.node_id == "I_123"
        assert issue.repo_id == sample_repo.node_id
        assert issue.title == "TypeError in component"
        assert "bug" in issue.labels
        assert issue.q_score >= 0.0

    def test_truncates_body_at_limit(self, gatherer, sample_repo):
        long_body = "x" * 10000
        node = make_issue_node(body=long_body)

        issue = gatherer._parse_issue(node, sample_repo)

        assert issue is not None
        assert len(issue.body_text) == BODY_TRUNCATE_LENGTH

    def test_handles_empty_body(self, gatherer, sample_repo):
        node = make_issue_node(body="")

        issue = gatherer._parse_issue(node, sample_repo)

        assert issue is not None
        assert issue.body_text == ""

    def test_handles_none_body(self, gatherer, sample_repo):
        node = make_issue_node()
        node["bodyText"] = None

        issue = gatherer._parse_issue(node, sample_repo)

        assert issue is not None
        assert issue.body_text == ""

    def test_parses_created_at_with_z_suffix(self, gatherer, sample_repo):
        node = make_issue_node(created_at="2024-01-15T12:00:00Z")

        issue = gatherer._parse_issue(node, sample_repo)

        assert issue is not None
        assert issue.github_created_at.year == 2024
        assert issue.github_created_at.month == 1
        assert issue.github_created_at.day == 15

    def test_parses_labels(self, gatherer, sample_repo):
        node = make_issue_node(labels=["bug", "help wanted", "good first issue"])

        issue = gatherer._parse_issue(node, sample_repo)

        assert issue is not None
        assert len(issue.labels) == 3
        assert "bug" in issue.labels

    def test_handles_empty_labels(self, gatherer, sample_repo):
        node = make_issue_node(labels=[])

        issue = gatherer._parse_issue(node, sample_repo)

        assert issue is not None
        assert issue.labels == []

    def test_handles_missing_labels(self, gatherer, sample_repo):
        node = make_issue_node()
        del node["labels"]

        issue = gatherer._parse_issue(node, sample_repo)

        assert issue is not None
        assert issue.labels == []

    def test_returns_none_for_missing_id(self, gatherer, sample_repo):
        node = make_issue_node()
        del node["id"]

        issue = gatherer._parse_issue(node, sample_repo)
        assert issue is None

    def test_returns_none_for_missing_created_at(self, gatherer, sample_repo):
        node = make_issue_node()
        del node["createdAt"]

        issue = gatherer._parse_issue(node, sample_repo)
        assert issue is None

    def test_returns_none_for_invalid_created_at(self, gatherer, sample_repo):
        node = make_issue_node(created_at="not-a-date")

        issue = gatherer._parse_issue(node, sample_repo)
        assert issue is None

    def test_returns_none_for_empty_node(self, gatherer, sample_repo):
        issue = gatherer._parse_issue({}, sample_repo)
        assert issue is None

    def test_returns_none_for_none_node(self, gatherer, sample_repo):
        issue = gatherer._parse_issue(None, sample_repo)
        assert issue is None

    def test_calculates_q_score(self, gatherer, sample_repo):
        node = make_issue_node(
            title="TypeError in async function",
            body="## Description\n```typescript\nawait Promise.resolve()\n```",
        )

        issue = gatherer._parse_issue(node, sample_repo)

        assert issue is not None
        assert issue.q_score > 0.6
        assert isinstance(issue.q_components, QScoreComponents)


class TestFetchRepoIssues:
    async def test_fetches_single_page(self, mock_client, gatherer, sample_repo):
        mock_client.execute_query.return_value = {
            "repository": {
                "issues": {
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                    "nodes": [
                        make_issue_node(f"I_{i}", body="## Description\n```code\n```")
                        for i in range(5)
                    ],
                }
            }
        }

        issues = [i async for i in gatherer._fetch_repo_issues(sample_repo)]

        assert len(issues) >= 1
        mock_client.execute_query.assert_called_once()

    async def test_paginates_multiple_pages(self, mock_client, gatherer, sample_repo):
        page1 = {
            "repository": {
                "issues": {
                    "pageInfo": {"hasNextPage": True, "endCursor": "cursor_1"},
                    "nodes": [
                        make_issue_node(f"I_{i}", body="## Description\n```code\n```")
                        for i in range(3)
                    ],
                }
            }
        }
        page2 = {
            "repository": {
                "issues": {
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                    "nodes": [
                        make_issue_node(f"I_{i+10}", body="## Description\n```code\n```")
                        for i in range(2)
                    ],
                }
            }
        }

        mock_client.execute_query.side_effect = [page1, page2]

        issues = [i async for i in gatherer._fetch_repo_issues(sample_repo)]

        assert mock_client.execute_query.call_count == 2

    async def test_handles_missing_repository(self, mock_client, gatherer, sample_repo):
        mock_client.execute_query.return_value = {"repository": None}

        issues = [i async for i in gatherer._fetch_repo_issues(sample_repo)]

        assert len(issues) == 0

    async def test_filters_low_q_score_issues(self, mock_client, gatherer, sample_repo):
        mock_client.execute_query.return_value = {
            "repository": {
                "issues": {
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                    "nodes": [
                        make_issue_node("I_high", body="## Description\n```code\n```"),
                        make_issue_node("I_low", title="bug", body="just a bug"),
                    ],
                }
            }
        }

        issues = [i async for i in gatherer._fetch_repo_issues(sample_repo)]

        high_quality = [i for i in issues if i.node_id == "I_high"]
        low_quality = [i for i in issues if i.node_id == "I_low"]

        assert len(high_quality) == 1
        assert len(low_quality) == 0


class TestRetryLogic:

    async def test_retries_on_failure(self, mock_client, gatherer, sample_repo):
        call_count = [0]

        async def mock_execute(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] < 3:
                raise Exception("API Error")
            return {
                "repository": {
                    "issues": {
                        "pageInfo": {"hasNextPage": False, "endCursor": None},
                        "nodes": [make_issue_node("I_1", body="## Description\n```code\n```")],
                    }
                }
            }

        mock_client.execute_query.side_effect = mock_execute

        with patch("asyncio.sleep", new_callable=AsyncMock):
            issues = [i async for i in gatherer._fetch_repo_issues_with_retry(sample_repo)]

        assert call_count[0] == 3
        assert len(issues) >= 1

    async def test_raises_after_max_retries(self, mock_client, gatherer, sample_repo):
        mock_client.execute_query.side_effect = Exception("Persistent failure")

        with patch("asyncio.sleep", new_callable=AsyncMock):
            with pytest.raises(Exception, match="Persistent failure"):
                _ = [i async for i in gatherer._fetch_repo_issues_with_retry(sample_repo)]

    async def test_exponential_backoff(self, mock_client, gatherer, sample_repo):
        mock_client.execute_query.side_effect = Exception("API Error")
        sleep_calls = []

        async def capture_sleep(seconds):
            sleep_calls.append(seconds)

        with patch("asyncio.sleep", side_effect=capture_sleep):
            try:
                _ = [i async for i in gatherer._fetch_repo_issues_with_retry(sample_repo)]
            except Exception:
                pass

        assert sleep_calls == [2.0, 4.0]


class TestHarvestIssues:

    async def test_harvests_from_multiple_repos(self, mock_client, gatherer):
        repos = [
            RepositoryData(
                node_id=f"R_{i}",
                full_name=f"owner/repo{i}",
                primary_language="Python",
                stargazer_count=1000,
                issue_count_open=50,
                topics=[],
            )
            for i in range(3)
        ]

        mock_client.execute_query.return_value = {
            "repository": {
                "issues": {
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                    "nodes": [make_issue_node("I_1", body="## Description\n```code\n```")],
                }
            }
        }

        issues = [i async for i in gatherer.harvest_issues(repos)]

        assert mock_client.execute_query.call_count == 3

    async def test_continues_on_repo_failure(self, mock_client, gatherer):
        repos = [
            RepositoryData(
                node_id=f"R_{i}",
                full_name=f"owner/repo{i}",
                primary_language="Python",
                stargazer_count=1000,
                issue_count_open=50,
                topics=[],
            )
            for i in range(3)
        ]

        call_count = [0]

        async def mock_execute(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] <= 3:  # First repo fails all retries
                raise Exception("API Error")
            return {
                "repository": {
                    "issues": {
                        "pageInfo": {"hasNextPage": False, "endCursor": None},
                        "nodes": [make_issue_node("I_1", body="## Description\n```code\n```")],
                    }
                }
            }

        mock_client.execute_query.side_effect = mock_execute

        with patch("asyncio.sleep", new_callable=AsyncMock):
            issues = [i async for i in gatherer.harvest_issues(repos)]

        assert len(issues) >= 1


class TestIssueData:

    def test_dataclass_fields(self):
        components = QScoreComponents(
            has_code=True,
            has_headers=True,
            tech_weight=0.5,
            is_junk=False,
        )

        issue = IssueData(
            node_id="I_123",
            repo_id="R_456",
            title="Bug report",
            body_text="Description",
            labels=["bug"],
            github_created_at=datetime.now(timezone.utc),
            q_score=0.75,
            q_components=components,
        )

        assert issue.node_id == "I_123"
        assert issue.repo_id == "R_456"
        assert issue.q_score == 0.75
        assert issue.q_components.has_code is True


class TestBodyTruncation:
    def test_truncate_length_is_4000(self):
        assert BODY_TRUNCATE_LENGTH == 4000

