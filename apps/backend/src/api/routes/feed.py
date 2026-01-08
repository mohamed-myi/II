"""
Feed API route for personalized issue recommendations.
Uses combined_vector for similarity; falls back to trending when no profile.
"""
from typing import Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlmodel.ext.asyncio.session import AsyncSession

from src.api.dependencies import get_db
from src.middleware.auth import require_auth
from src.services.feed_service import (
    get_feed,
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE,
)
from models.identity import User, Session


router = APIRouter()


class FeedItemOutput(BaseModel):
    """Single issue in the feed."""
    node_id: str
    title: str
    body_preview: str
    labels: list[str]
    q_score: float
    repo_name: str
    primary_language: Optional[str]
    github_created_at: str
    similarity_score: Optional[float] = Field(
        default=None,
        description="Cosine similarity to user profile; null for trending feed",
    )


class FeedResponse(BaseModel):
    """Paginated feed response with personalization metadata."""
    results: list[FeedItemOutput]
    total: int
    page: int
    page_size: int
    has_more: bool
    is_personalized: bool = Field(
        description="True if results are based on user profile; false for trending",
    )
    profile_cta: Optional[str] = Field(
        default=None,
        description="Call to action message when showing trending feed",
    )


@router.get("", response_model=FeedResponse)
async def get_feed_route(
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(
        default=DEFAULT_PAGE_SIZE,
        ge=1,
        le=MAX_PAGE_SIZE,
        description="Results per page",
    ),
    auth: tuple[User, Session] = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
) -> FeedResponse:
    """
    Returns personalized issue recommendations based on user profile.
    
    When the user has a combined_vector (from intent, resume, or GitHub data),
    issues are ranked by vector similarity with preference filters applied.
    
    When no profile data exists, returns trending issues (high quality, recent)
    with a call to action to complete the profile.
    
    Pagination:
        page: 1-indexed page number
        page_size: results per page (max 50)
    
    Response includes:
        is_personalized: true if using profile-based ranking
        profile_cta: message shown when using trending fallback
        similarity_score: cosine similarity for personalized results (null for trending)
    """
    user, _ = auth
    
    feed = await get_feed(
        db=db,
        user_id=user.id,
        page=page,
        page_size=page_size,
    )
    
    return FeedResponse(
        results=[
            FeedItemOutput(
                node_id=item.node_id,
                title=item.title,
                body_preview=item.body_preview,
                labels=item.labels,
                q_score=item.q_score,
                repo_name=item.repo_name,
                primary_language=item.primary_language,
                github_created_at=item.github_created_at.isoformat(),
                similarity_score=item.similarity_score,
            )
            for item in feed.results
        ],
        total=feed.total,
        page=feed.page,
        page_size=feed.page_size,
        has_more=feed.has_more,
        is_personalized=feed.is_personalized,
        profile_cta=feed.profile_cta,
    )

