"""Unit tests for Scout repository discovery"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

from src.ingestion.scout import Scout, RepositoryData, SCOUT_LANGUAGES


@pytest.fixture
def mock_client():
    client = AsyncMock()
    client.execute_query = AsyncMock()
    return client


@pytest.fixture
def scout(mock_client):
    return Scout(client=mock_client)


class TestScoutLanguages:

    def test_scout_languages_list(self):
        assert len(SCOUT_LANGUAGES) == 10
        assert "TypeScript" in SCOUT_LANGUAGES
        assert "Python" in SCOUT_LANGUAGES
        assert "Rust" in SCOUT_LANGUAGES


class TestBuildSearchQuery:

    def test_includes_language_filter(self, scout):
        query = scout._build_search_query("Python")
        assert "language:Python" in query

    def test_includes_stars_filter(self, scout):
        query = scout._build_search_query("Python")
        assert f"stars:>{scout.MIN_STARS}" in query

    def test_includes_pushed_date_filter(self, scout):
        query = scout._build_search_query("Python")
        assert "pushed:>" in query
        expected_cutoff = (datetime.now(timezone.utc) - timedelta(days=14)).strftime("%Y-%m-%d")
        assert expected_cutoff in query

    def test_includes_sort_by_stars(self, scout):
        query = scout._build_search_query("Python")
        assert "sort:stars-desc" in query

    def test_query_format_complete(self, scout):
        query = scout._build_search_query("TypeScript")
        assert query.startswith("language:TypeScript")
        assert "stars:>1000" in query
        assert "sort:stars-desc" in query


class TestParseRepository:

    def test_parses_complete_node(self, scout):
        node = {
            "id": "R_kgDOHDq123",
            "nameWithOwner": "facebook/react",
            "primaryLanguage": {"name": "TypeScript"},
            "stargazerCount": 200000,
            "issues": {"totalCount": 500},
            "repositoryTopics": {
                "nodes": [
                    {"topic": {"name": "react"}},
                    {"topic": {"name": "javascript"}},
                ]
            },
            "pushedAt": "2024-01-01T12:00:00Z",
        }

        repo = scout._parse_repository(node, "JavaScript")

        assert repo is not None
        assert repo.node_id == "R_kgDOHDq123"
        assert repo.full_name == "facebook/react"
        assert repo.primary_language == "TypeScript"
        assert repo.stargazer_count == 200000
        assert repo.issue_count_open == 500
        assert "react" in repo.topics
        assert "javascript" in repo.topics

    def test_filters_below_velocity_threshold(self, scout):
        node = {
            "id": "R_kgDOHDq123",
            "nameWithOwner": "owner/repo",
            "primaryLanguage": {"name": "Python"},
            "stargazerCount": 5000,
            "issues": {"totalCount": 5},
            "repositoryTopics": {"nodes": []},
        }

        repo = scout._parse_repository(node, "Python")
        assert repo is None

    def test_uses_fallback_language_when_primary_missing(self, scout):
        node = {
            "id": "R_kgDOHDq123",
            "nameWithOwner": "owner/repo",
            "primaryLanguage": None,
            "stargazerCount": 5000,
            "issues": {"totalCount": 50},
            "repositoryTopics": {"nodes": []},
        }

        repo = scout._parse_repository(node, "JavaScript")

        assert repo is not None
        assert repo.primary_language == "JavaScript"

    def test_returns_none_for_missing_id(self, scout):
        node = {
            "nameWithOwner": "owner/repo",
            "primaryLanguage": {"name": "Python"},
            "issues": {"totalCount": 50},
        }

        repo = scout._parse_repository(node, "Python")
        assert repo is None

    def test_returns_none_for_missing_name(self, scout):
        node = {
            "id": "R_kgDOHDq123",
            "primaryLanguage": {"name": "Python"},
            "issues": {"totalCount": 50},
        }

        repo = scout._parse_repository(node, "Python")
        assert repo is None

    def test_returns_none_for_empty_node(self, scout):
        repo = scout._parse_repository({}, "Python")
        assert repo is None

    def test_returns_none_for_none_node(self, scout):
        repo = scout._parse_repository(None, "Python")
        assert repo is None

    def test_handles_missing_topics(self, scout):
        node = {
            "id": "R_kgDOHDq123",
            "nameWithOwner": "owner/repo",
            "primaryLanguage": {"name": "Python"},
            "stargazerCount": 5000,
            "issues": {"totalCount": 50},
        }

        repo = scout._parse_repository(node, "Python")

        assert repo is not None
        assert repo.topics == []

    def test_handles_empty_topic_nodes(self, scout):
        node = {
            "id": "R_kgDOHDq123",
            "nameWithOwner": "owner/repo",
            "primaryLanguage": {"name": "Python"},
            "stargazerCount": 5000,
            "issues": {"totalCount": 50},
            "repositoryTopics": {"nodes": [None, {}, {"topic": None}]},
        }

        repo = scout._parse_repository(node, "Python")

        assert repo is not None
        assert repo.topics == []


class TestDiscoverForLanguage:
    async def test_fetches_repos_for_language(self, mock_client, scout):
        mock_client.execute_query.return_value = {
            "search": {
                "repositoryCount": 100,
                "pageInfo": {"hasNextPage": False, "endCursor": None},
                "nodes": [
                    {
                        "id": f"R_{i}",
                        "nameWithOwner": f"owner/repo{i}",
                        "primaryLanguage": {"name": "Python"},
                        "stargazerCount": 5000,
                        "issues": {"totalCount": 50},
                        "repositoryTopics": {"nodes": []},
                    }
                    for i in range(10)
                ],
            }
        }

        repos = await scout._discover_for_language("Python")

        assert len(repos) == 10
        assert all(r.primary_language == "Python" for r in repos)
        mock_client.execute_query.assert_called_once()

    async def test_paginates_until_limit_reached(self, mock_client, scout):
        first_page = {
            "search": {
                "repositoryCount": 200,
                "pageInfo": {"hasNextPage": True, "endCursor": "cursor_1"},
                "nodes": [
                    {
                        "id": f"R_{i}",
                        "nameWithOwner": f"owner/repo{i}",
                        "primaryLanguage": {"name": "Python"},
                        "stargazerCount": 5000,
                        "issues": {"totalCount": 50},
                        "repositoryTopics": {"nodes": []},
                    }
                    for i in range(50)
                ],
            }
        }

        mock_client.execute_query.return_value = first_page

        repos = await scout._discover_for_language("Python")

        assert len(repos) == 50
        assert mock_client.execute_query.call_count == 1

    async def test_stops_when_no_more_pages(self, mock_client, scout):
        mock_client.execute_query.return_value = {
            "search": {
                "repositoryCount": 5,
                "pageInfo": {"hasNextPage": False, "endCursor": None},
                "nodes": [
                    {
                        "id": f"R_{i}",
                        "nameWithOwner": f"owner/repo{i}",
                        "primaryLanguage": {"name": "Go"},
                        "stargazerCount": 5000,
                        "issues": {"totalCount": 50},
                        "repositoryTopics": {"nodes": []},
                    }
                    for i in range(5)
                ],
            }
        }

        repos = await scout._discover_for_language("Go")

        assert len(repos) == 5
        mock_client.execute_query.assert_called_once()

    async def test_filters_low_velocity_during_pagination(self, mock_client, scout):
        mock_client.execute_query.return_value = {
            "search": {
                "repositoryCount": 20,
                "pageInfo": {"hasNextPage": False, "endCursor": None},
                "nodes": [
                    {
                        "id": f"R_{i}",
                        "nameWithOwner": f"owner/repo{i}",
                        "primaryLanguage": {"name": "Rust"},
                        "stargazerCount": 5000,
                        "issues": {"totalCount": 5 if i % 2 == 0 else 50},
                        "repositoryTopics": {"nodes": []},
                    }
                    for i in range(20)
                ],
            }
        }

        repos = await scout._discover_for_language("Rust")

        assert len(repos) == 10


class TestDiscoverRepositories:

    async def test_discovers_across_all_languages(self, mock_client, scout):
        mock_client.execute_query.return_value = {
            "search": {
                "repositoryCount": 10,
                "pageInfo": {"hasNextPage": False, "endCursor": None},
                "nodes": [
                    {
                        "id": f"R_{i}",
                        "nameWithOwner": f"owner/repo{i}",
                        "primaryLanguage": {"name": "Python"},
                        "stargazerCount": 5000,
                        "issues": {"totalCount": 50},
                        "repositoryTopics": {"nodes": []},
                    }
                    for i in range(5)
                ],
            }
        }

        repos = await scout.discover_repositories()

        assert len(repos) == 50
        assert mock_client.execute_query.call_count == 10

    async def test_continues_on_single_language_failure(self, mock_client, scout):
        call_count = [0]

        async def mock_execute(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 3:  # Fail on 3rd language
                raise Exception("API Error")
            return {
                "search": {
                    "repositoryCount": 5,
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                    "nodes": [
                        {
                            "id": f"R_{call_count[0]}_{i}",
                            "nameWithOwner": f"owner/repo{i}",
                            "primaryLanguage": {"name": "Python"},
                            "stargazerCount": 5000,
                            "issues": {"totalCount": 50},
                            "repositoryTopics": {"nodes": []},
                        }
                        for i in range(5)
                    ],
                }
            }

        mock_client.execute_query.side_effect = mock_execute

        repos = await scout.discover_repositories()

        assert len(repos) == 45
        assert call_count[0] == 10


class TestRepositoryData:

    def test_dataclass_fields(self):
        repo = RepositoryData(
            node_id="R_123",
            full_name="owner/repo",
            primary_language="Python",
            stargazer_count=1000,
            issue_count_open=50,
            topics=["python", "web"],
        )

        assert repo.node_id == "R_123"
        assert repo.full_name == "owner/repo"
        assert repo.primary_language == "Python"
        assert repo.stargazer_count == 1000
        assert repo.issue_count_open == 50
        assert repo.topics == ["python", "web"]

