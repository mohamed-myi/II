"""API routes for issue discovery and detail endpoints."""
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlmodel.ext.asyncio.session import AsyncSession

from src.api.dependencies import get_db
from src.middleware.auth import require_auth
from src.services.issue_service import (
    get_issue_by_node_id,
    get_similar_issues,
    DEFAULT_SIMILAR_LIMIT,
    MAX_SIMILAR_LIMIT,
)

router = APIRouter()


# Response Models

class IssueDetailResponse(BaseModel):
    """Full issue detail response."""
    node_id: str
    title: str
    body: str
    labels: list[str]
    q_score: float
    repo_name: str
    repo_url: str
    github_url: str
    primary_language: str | None
    github_created_at: str  # ISO format
    state: str


class SimilarIssueResponse(BaseModel):
    """Single similar issue."""
    node_id: str
    title: str
    repo_name: str
    similarity_score: float


class SimilarIssuesResponse(BaseModel):
    """List of similar issues."""
    issues: list[SimilarIssueResponse]


# Endpoints

@router.get("/{node_id}", response_model=IssueDetailResponse)
async def get_issue_detail(
    node_id: str,
    auth: Annotated[tuple, Depends(require_auth)],
    db: AsyncSession = Depends(get_db),
) -> IssueDetailResponse:
    """
    Returns full issue detail by node_id.
    
    Used for issue detail views, deep-linking, and bookmark cards.
    """
    issue = await get_issue_by_node_id(db, node_id)
    
    if issue is None:
        raise HTTPException(status_code=404, detail="Issue not found")
    
    return IssueDetailResponse(
        node_id=issue.node_id,
        title=issue.title,
        body=issue.body,
        labels=issue.labels,
        q_score=issue.q_score,
        repo_name=issue.repo_name,
        repo_url=issue.repo_url,
        github_url=issue.github_url,
        primary_language=issue.primary_language,
        github_created_at=issue.github_created_at.isoformat(),
        state=issue.state,
    )


@router.get("/{node_id}/similar", response_model=SimilarIssuesResponse)
async def get_similar_issues_endpoint(
    node_id: str,
    auth: Annotated[tuple, Depends(require_auth)],
    db: AsyncSession = Depends(get_db),
    limit: Annotated[int, Query(ge=1, le=MAX_SIMILAR_LIMIT)] = DEFAULT_SIMILAR_LIMIT,
) -> SimilarIssuesResponse:
    """
    Returns similar open issues based on vector similarity.
    
    Returns empty list if:
    - Source issue has no embedding yet
    - No similar issues above similarity threshold
    - All similar issues are closed
    """
    similar = await get_similar_issues(db, node_id, limit=limit)
    
    if similar is None:
        # Source issue not found
        raise HTTPException(status_code=404, detail="Issue not found")
    
    return SimilarIssuesResponse(
        issues=[
            SimilarIssueResponse(
                node_id=s.node_id,
                title=s.title,
                repo_name=s.repo_name,
                similarity_score=s.similarity_score,
            )
            for s in similar
        ]
    )
