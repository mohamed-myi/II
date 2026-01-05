"""Streaming persistence layer for ingested issues"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING, AsyncIterator

from sqlalchemy import text
from sqlmodel.ext.asyncio.session import AsyncSession

from .survival_score import calculate_survival_score, days_since

if TYPE_CHECKING:
    from .embeddings import EmbeddedIssue
    from .scout import RepositoryData

logger = logging.getLogger(__name__)


class StreamingPersistence:
    """Consumes embedded issue stream and writes in batches via UPSERT"""

    BATCH_SIZE: int = 50

    def __init__(self, session: AsyncSession):
        self._session = session

    async def upsert_repositories(self, repos: list[RepositoryData]) -> int:
        """
        Batch UPSERT repositories before issue ingestion.
        Returns count of upserted rows.
        """
        if not repos:
            return 0

        now = datetime.now(timezone.utc)
        values_list = []
        params = {}

        for i, repo in enumerate(repos):
            values_list.append(
                f"(:node_id_{i}, :full_name_{i}, :primary_language_{i}, "
                f":issue_velocity_week_{i}, :stargazer_count_{i}, :topics_{i}, :last_scraped_at_{i})"
            )
            params[f"node_id_{i}"] = repo.node_id
            params[f"full_name_{i}"] = repo.full_name
            params[f"primary_language_{i}"] = repo.primary_language
            params[f"issue_velocity_week_{i}"] = repo.issue_count_open
            params[f"stargazer_count_{i}"] = repo.stargazer_count
            params[f"topics_{i}"] = repo.topics
            params[f"last_scraped_at_{i}"] = now

        values_sql = ", ".join(values_list)

        query = text(f"""
            INSERT INTO ingestion.repository 
                (node_id, full_name, primary_language, issue_velocity_week, 
                 stargazer_count, topics, last_scraped_at)
            VALUES {values_sql}
            ON CONFLICT (node_id) DO UPDATE SET
                full_name = EXCLUDED.full_name,
                primary_language = EXCLUDED.primary_language,
                issue_velocity_week = EXCLUDED.issue_velocity_week,
                stargazer_count = EXCLUDED.stargazer_count,
                topics = EXCLUDED.topics,
                last_scraped_at = EXCLUDED.last_scraped_at
        """)

        await self._session.execute(query, params)
        await self._session.commit()

        logger.debug(f"Upserted {len(repos)} repositories")
        return len(repos)

    async def persist_stream(
        self,
        embedded_issues: AsyncIterator[EmbeddedIssue],
    ) -> int:
        """
        Consumes stream, calculates survival_score, UPSERTs in batches.
        Returns total issues persisted.
        """
        batch: list[EmbeddedIssue] = []
        total = 0

        async for item in embedded_issues:
            batch.append(item)

            if len(batch) >= self.BATCH_SIZE:
                await self._upsert_batch(batch)
                total += len(batch)
                batch.clear()

        if batch:
            await self._upsert_batch(batch)
            total += len(batch)

        logger.info(f"Persisted {total} issues to database")
        return total

    async def _upsert_batch(self, batch: list[EmbeddedIssue]) -> None:
        """UPSERT batch with survival_score calculation"""
        if not batch:
            return

        values_list = []
        params = {}

        for i, item in enumerate(batch):
            issue = item.issue
            days_old = days_since(issue.github_created_at)
            survival = calculate_survival_score(issue.q_score, days_old)

            values_list.append(
                f"(:node_id_{i}, :repo_id_{i}, :has_code_{i}, :has_template_headers_{i}, "
                f":tech_stack_weight_{i}, :q_score_{i}, :survival_score_{i}, :title_{i}, "
                f":body_text_{i}, :labels_{i}, CAST(:embedding_{i} AS vector), :github_created_at_{i})"
            )

            params[f"node_id_{i}"] = issue.node_id
            params[f"repo_id_{i}"] = issue.repo_id
            params[f"has_code_{i}"] = issue.q_components.has_code
            params[f"has_template_headers_{i}"] = issue.q_components.has_headers
            params[f"tech_stack_weight_{i}"] = issue.q_components.tech_weight
            params[f"q_score_{i}"] = issue.q_score
            params[f"survival_score_{i}"] = survival
            params[f"title_{i}"] = issue.title
            params[f"body_text_{i}"] = issue.body_text
            params[f"labels_{i}"] = issue.labels
            params[f"embedding_{i}"] = str(item.embedding)
            params[f"github_created_at_{i}"] = issue.github_created_at

        values_sql = ", ".join(values_list)

        query = text(f"""
            INSERT INTO ingestion.issue
                (node_id, repo_id, has_code, has_template_headers, tech_stack_weight,
                 q_score, survival_score, title, body_text, labels, embedding, github_created_at)
            VALUES {values_sql}
            ON CONFLICT (node_id) DO UPDATE SET
                repo_id = EXCLUDED.repo_id,
                has_code = EXCLUDED.has_code,
                has_template_headers = EXCLUDED.has_template_headers,
                tech_stack_weight = EXCLUDED.tech_stack_weight,
                q_score = EXCLUDED.q_score,
                survival_score = EXCLUDED.survival_score,
                title = EXCLUDED.title,
                body_text = EXCLUDED.body_text,
                labels = EXCLUDED.labels,
                embedding = EXCLUDED.embedding,
                github_created_at = EXCLUDED.github_created_at
        """)

        await self._session.execute(query, params)
        await self._session.commit()

        logger.debug(f"Upserted batch of {len(batch)} issues")

