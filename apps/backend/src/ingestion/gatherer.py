"""Streaming issue harvester; yields AsyncIterator for constant memory"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, AsyncIterator

from .quality_gate import (
    QScoreComponents,
    extract_components,
    compute_q_score,
    passes_quality_gate,
)

if TYPE_CHECKING:
    from .github_client import GitHubGraphQLClient
    from .scout import RepositoryData

logger = logging.getLogger(__name__)

GATHERER_QUERY_PATH = Path(__file__).parent / "queries" / "gatherer.graphql"

BODY_TRUNCATE_LENGTH: int = 4000


@dataclass
class IssueData:
    node_id: str
    repo_id: str
    title: str
    body_text: str
    labels: list[str]
    github_created_at: datetime
    q_score: float
    q_components: QScoreComponents


class Gatherer:
    """Streams issues via AsyncIterator; filters by Q score >= 0,6"""

    PAGE_SIZE: int = 100
    MAX_RETRIES: int = 3
    RETRY_DELAY_SECONDS: float = 2.0
    Q_SCORE_THRESHOLD: float = 0.6

    def __init__(self, client: GitHubGraphQLClient):
        self._client = client
        self._query = self._load_query()

    def _load_query(self) -> str:
        if GATHERER_QUERY_PATH.exists():
            return GATHERER_QUERY_PATH.read_text()
        return self._inline_query()

    def _inline_query(self) -> str:
        return """
        query GathererIssues($owner: String!, $name: String!, $first: Int!, $after: String) {
          repository(owner: $owner, name: $name) {
            issues(states: OPEN, first: $first, after: $after, orderBy: {field: CREATED_AT, direction: DESC}) {
              pageInfo { hasNextPage endCursor }
              nodes {
                id title bodyText createdAt
                labels(first: 10) { nodes { name } }
              }
            }
          }
          rateLimit { cost remaining resetAt nodeCount }
        }
        """

    async def harvest_issues(
        self,
        repos: list[RepositoryData],
    ) -> AsyncIterator[IssueData]:
        """Holds at most PAGE_SIZE issues at a time"""
        for repo in repos:
            try:
                issue_count = 0
                async for issue in self._fetch_repo_issues_with_retry(repo):
                    issue_count += 1
                    yield issue

                if issue_count > 0:
                    logger.debug(
                        f"Gatherer: {repo.full_name} yielded {issue_count} issues"
                    )
            except Exception as e:
                logger.warning(
                    f"Gatherer: Skipping {repo.full_name} after retries: {e}"
                )
                continue

    async def _fetch_repo_issues_with_retry(
        self,
        repo: RepositoryData,
    ) -> AsyncIterator[IssueData]:
        last_error: Exception | None = None

        for attempt in range(self.MAX_RETRIES):
            try:
                async for issue in self._fetch_repo_issues(repo):
                    yield issue
                return  # Success; exit retry loop
            except Exception as e:
                last_error = e
                if attempt < self.MAX_RETRIES - 1:
                    delay = self.RETRY_DELAY_SECONDS * (attempt + 1)
                    logger.debug(
                        f"Gatherer: Retry {attempt + 1}/{self.MAX_RETRIES} "
                        f"for {repo.full_name} after {delay}s"
                    )
                    await asyncio.sleep(delay)

        if last_error:
            raise last_error

    async def _fetch_repo_issues(
        self,
        repo: RepositoryData,
    ) -> AsyncIterator[IssueData]:
        owner, name = repo.full_name.split("/", 1)
        cursor: str | None = None

        while True:
            data = await self._client.execute_query(
                self._query,
                variables={
                    "owner": owner,
                    "name": name,
                    "first": self.PAGE_SIZE,
                    "after": cursor,
                },
                estimated_cost=1,
            )

            repository = data.get("repository")
            if not repository:
                logger.warning(f"Gatherer: Repository not found: {repo.full_name}")
                break

            issues_data = repository.get("issues", {})
            nodes = issues_data.get("nodes", [])
            page_info = issues_data.get("pageInfo", {})

            for node in nodes:
                issue = self._parse_issue(node, repo)
                if issue and passes_quality_gate(issue.q_score, self.Q_SCORE_THRESHOLD):
                    yield issue

            if not page_info.get("hasNextPage"):
                break
            cursor = page_info.get("endCursor")

    def _parse_issue(self, node: dict, repo: RepositoryData) -> IssueData | None:
        if not node:
            return None

        node_id = node.get("id")
        title = node.get("title", "")
        created_at_str = node.get("createdAt")

        if not node_id or not created_at_str:
            return None

        body = (node.get("bodyText") or "")[:BODY_TRUNCATE_LENGTH]

        labels_data = node.get("labels", {}).get("nodes", [])
        labels = [
            label.get("name")
            for label in labels_data
            if label and label.get("name")
        ]

        try:
            github_created_at = datetime.fromisoformat(
                created_at_str.replace("Z", "+00:00")
            )
        except (ValueError, AttributeError):
            logger.warning(f"Gatherer: Invalid createdAt for issue {node_id}")
            return None

        components = extract_components(title, body, repo.primary_language)
        q_score = compute_q_score(components)

        return IssueData(
            node_id=node_id,
            repo_id=repo.node_id,
            title=title,
            body_text=body,
            labels=labels,
            github_created_at=github_created_at,
            q_score=q_score,
            q_components=components,
        )

