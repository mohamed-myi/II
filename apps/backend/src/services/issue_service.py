"""
Issue service for issue discovery and detail endpoints.
All queries filter open state by default for user-facing endpoints.
"""
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from sqlalchemy import text
from sqlmodel.ext.asyncio.session import AsyncSession

logger = logging.getLogger(__name__)

# Minimum cosine similarity to include in similar issues results
MIN_SIMILARITY_THRESHOLD = 0.3
DEFAULT_SIMILAR_LIMIT = 5
MAX_SIMILAR_LIMIT = 10


@dataclass
class IssueDetail:
    """Full issue detail with repository metadata."""
    node_id: str
    title: str
    body: str
    labels: list[str]
    q_score: float
    repo_name: str
    repo_url: str
    github_url: str
    primary_language: Optional[str]
    github_created_at: datetime
    state: str


@dataclass
class SimilarIssue:
    """Similar issue with similarity score."""
    node_id: str
    title: str
    repo_name: str
    similarity_score: float


async def get_issue_by_node_id(
    db: AsyncSession,
    node_id: str,
) -> Optional[IssueDetail]:
    """
    Fetches a single issue by node_id with repository metadata.
    Returns issue regardless of state (open/closed) for detail views.
    """
    sql = """
    SELECT 
        i.node_id,
        i.title,
        i.body_text AS body,
        i.labels,
        i.q_score,
        r.full_name AS repo_name,
        'https://github.com/' || r.full_name AS repo_url,
        'https://github.com/' || r.full_name || '/issues/' || 
            SUBSTRING(i.node_id FROM '[0-9]+$') AS github_url,
        r.primary_language,
        i.github_created_at,
        i.state
    FROM ingestion.issue i
    JOIN ingestion.repository r ON i.repo_id = r.node_id
    WHERE i.node_id = :node_id
    """
    
    result = await db.execute(text(sql), {"node_id": node_id})
    row = result.fetchone()
    
    if row is None:
        return None
    
    return IssueDetail(
        node_id=row.node_id,
        title=row.title,
        body=row.body,
        labels=list(row.labels) if row.labels else [],
        q_score=float(row.q_score),
        repo_name=row.repo_name,
        repo_url=row.repo_url,
        github_url=row.github_url,
        primary_language=row.primary_language,
        github_created_at=row.github_created_at,
        state=row.state,
    )


async def get_similar_issues(
    db: AsyncSession,
    node_id: str,
    limit: int = DEFAULT_SIMILAR_LIMIT,
) -> Optional[list[SimilarIssue]]:
    """
    Finds similar open issues based on vector similarity.
    
    Returns None if source issue not found.
    Returns empty list if:
    - Source issue has no embedding
    - No similar issues above MIN_SIMILARITY_THRESHOLD
    - All similar issues are closed
    
    Note: Cosine distance is used (lower = more similar).
    Similarity score = 1 - cosine_distance.
    """
    if limit < 1:
        limit = DEFAULT_SIMILAR_LIMIT
    if limit > MAX_SIMILAR_LIMIT:
        limit = MAX_SIMILAR_LIMIT
    
    # Check if issue exists and get its embedding
    embedding_sql = """
    SELECT node_id, embedding
    FROM ingestion.issue
    WHERE node_id = :node_id
    """
    
    result = await db.execute(text(embedding_sql), {"node_id": node_id})
    source_row = result.fetchone()
    
    if source_row is None:
        return None
    
    if source_row.embedding is None:
        # Issue exists but has no embedding yet
        logger.info(f"Issue {node_id} has no embedding, returning empty similar list")
        return []
    
    # Find similar open issues, excluding source issue
    # Use cosine distance operator <=> and convert to similarity
    similarity_sql = """
    SELECT 
        i.node_id,
        i.title,
        r.full_name AS repo_name,
        1 - (i.embedding <=> CAST(:source_vec AS vector)) AS similarity_score
    FROM ingestion.issue i
    JOIN ingestion.repository r ON i.repo_id = r.node_id
    WHERE i.node_id != :node_id
      AND i.embedding IS NOT NULL
      AND i.state = 'open'
      AND 1 - (i.embedding <=> CAST(:source_vec AS vector)) >= :min_threshold
    ORDER BY i.embedding <=> CAST(:source_vec AS vector)
    LIMIT :limit
    """
    
    result = await db.execute(
        text(similarity_sql),
        {
            "node_id": node_id,
            "source_vec": str(list(source_row.embedding)),
            "min_threshold": MIN_SIMILARITY_THRESHOLD,
            "limit": limit,
        },
    )
    rows = result.fetchall()
    
    return [
        SimilarIssue(
            node_id=row.node_id,
            title=row.title,
            repo_name=row.repo_name,
            similarity_score=round(float(row.similarity_score), 3),
        )
        for row in rows
    ]


__all__ = [
    "IssueDetail",
    "SimilarIssue",
    "get_issue_by_node_id",
    "get_similar_issues",
    "MIN_SIMILARITY_THRESHOLD",
    "DEFAULT_SIMILAR_LIMIT",
    "MAX_SIMILAR_LIMIT",
]
