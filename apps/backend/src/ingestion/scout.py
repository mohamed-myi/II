"""Repository discovery for the ingestion pipeline"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .github_client import GitHubGraphQLClient

logger = logging.getLogger(__name__)

SCOUT_QUERY_PATH = Path(__file__).parent / "queries" / "scout.graphql"

SCOUT_LANGUAGES: list[str] = [
    "TypeScript", "Python", "Java", "JavaScript", "C++",
    "C#", "Go", "Rust", "Kotlin", "SQL",
]


@dataclass
class RepositoryData:
    node_id: str
    full_name: str
    primary_language: str
    stargazer_count: int
    issue_count_open: int
    topics: list[str]


class Scout:
    """
    Discovers Top 50 repositories per language meeting velocity criteria;
    returns list of RepositoryData; approximately 500 repos total, 50KB memory
    """

    REPOS_PER_LANGUAGE: int = 50
    MIN_STARS: int = 1000
    MIN_ISSUE_VELOCITY: int = 10
    RECENCY_DAYS: int = 14
    PAGE_SIZE: int = 50

    def __init__(self, client: GitHubGraphQLClient):
        self._client = client
        self._query = self._load_query()

    def _load_query(self) -> str:
        if SCOUT_QUERY_PATH.exists():
            return SCOUT_QUERY_PATH.read_text()
        return self._inline_query()

    def _inline_query(self) -> str:
        return """
        query ScoutRepositories($searchQuery: String!, $first: Int!, $after: String) {
          search(query: $searchQuery, type: REPOSITORY, first: $first, after: $after) {
            repositoryCount
            pageInfo { hasNextPage endCursor }
            nodes {
              ... on Repository {
                id
                nameWithOwner
                primaryLanguage { name }
                stargazerCount
                issues(states: OPEN) { totalCount }
                repositoryTopics(first: 10) { nodes { topic { name } } }
                pushedAt
              }
            }
          }
          rateLimit { cost remaining resetAt nodeCount }
        }
        """

    async def discover_repositories(self) -> list[RepositoryData]:
        """Fetches top repos for all 10 languages; estimated cost 20 to 40 points"""
        repositories: list[RepositoryData] = []

        for language in SCOUT_LANGUAGES:
            try:
                repos = await self._discover_for_language(language)
                repositories.extend(repos)
                logger.info(
                    f"Scout: {language} yielded {len(repos)} repos "
                    f"(total: {len(repositories)})"
                )
            except Exception as e:
                logger.warning(f"Scout: Failed to fetch {language}: {e}")
                continue

        logger.info(f"Scout: Discovery complete; {len(repositories)} total repos")
        return repositories

    async def _discover_for_language(self, language: str) -> list[RepositoryData]:
        repos: list[RepositoryData] = []
        search_query = self._build_search_query(language)
        cursor: str | None = None

        while len(repos) < self.REPOS_PER_LANGUAGE:
            remaining_needed = self.REPOS_PER_LANGUAGE - len(repos)
            page_size = min(self.PAGE_SIZE, remaining_needed)

            data = await self._client.execute_query(
                self._query,
                variables={
                    "searchQuery": search_query,
                    "first": page_size,
                    "after": cursor,
                },
                estimated_cost=2,
            )

            search_data = data.get("search", {})
            nodes = search_data.get("nodes", [])
            page_info = search_data.get("pageInfo", {})

            for node in nodes:
                if len(repos) >= self.REPOS_PER_LANGUAGE:
                    break
                repo = self._parse_repository(node, language)
                if repo is not None:
                    repos.append(repo)

            if not page_info.get("hasNextPage"):
                break
            cursor = page_info.get("endCursor")

        return repos

    def _build_search_query(self, language: str) -> str:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=self.RECENCY_DAYS)).strftime("%Y-%m-%d")
        return f"language:{language} stars:>{self.MIN_STARS} pushed:>{cutoff} sort:stars-desc"

    def _parse_repository(self, node: dict, fallback_language: str) -> RepositoryData | None:
        """Returns None if fails velocity filter or missing required fields"""
        if not node:
            return None

        node_id = node.get("id")
        full_name = node.get("nameWithOwner")

        if not node_id or not full_name:
            return None

        primary_language_data = node.get("primaryLanguage")
        primary_language = (
            primary_language_data.get("name")
            if primary_language_data else fallback_language
        )

        issues_data = node.get("issues", {})
        issue_count = issues_data.get("totalCount", 0)

        if issue_count < self.MIN_ISSUE_VELOCITY:
            return None

        topics_data = node.get("repositoryTopics", {}).get("nodes", [])
        topics = []
        for t in topics_data:
            if t and isinstance(t, dict):
                topic_obj = t.get("topic")
                if topic_obj and isinstance(topic_obj, dict):
                    name = topic_obj.get("name")
                    if name:
                        topics.append(name)

        return RepositoryData(
            node_id=node_id,
            full_name=full_name,
            primary_language=primary_language or fallback_language,
            stargazer_count=node.get("stargazerCount", 0),
            issue_count_open=issue_count,
            topics=topics,
        )

