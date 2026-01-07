"""Onboarding API routes for tracking onboarding progress."""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlmodel.ext.asyncio.session import AsyncSession

from src.api.dependencies import get_db
from src.middleware.auth import require_auth
from src.services.onboarding_service import (
    get_onboarding_status,
    complete_onboarding,
    skip_onboarding,
    CannotCompleteOnboardingError,
    OnboardingAlreadyCompletedError,
)
from src.services.recommendation_preview_service import (
    get_preview_recommendations,
    InvalidSourceError,
)
from models.identity import User, Session


router = APIRouter()


class OnboardingStatusResponse(BaseModel):
    status: str
    completed_steps: list[str]
    available_steps: list[str]
    can_complete: bool


class PreviewIssueResponse(BaseModel):
    node_id: str
    title: str
    repo_name: str
    primary_language: Optional[str]
    q_score: float


class PreviewRecommendationsResponse(BaseModel):
    source: Optional[str]
    issues: list[PreviewIssueResponse]


@router.get("/onboarding", response_model=OnboardingStatusResponse)
async def get_onboarding(
    auth: tuple[User, Session] = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
) -> OnboardingStatusResponse:
    user, _ = auth
    state = await get_onboarding_status(db, user.id)
    
    return OnboardingStatusResponse(
        status=state.status,
        completed_steps=state.completed_steps,
        available_steps=state.available_steps,
        can_complete=state.can_complete,
    )


@router.post("/onboarding/complete", response_model=OnboardingStatusResponse)
async def complete_onboarding_route(
    auth: tuple[User, Session] = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
) -> OnboardingStatusResponse:
    user, _ = auth
    
    try:
        state = await complete_onboarding(db, user.id)
    except CannotCompleteOnboardingError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except OnboardingAlreadyCompletedError as e:
        raise HTTPException(status_code=409, detail=str(e))
    
    return OnboardingStatusResponse(
        status=state.status,
        completed_steps=state.completed_steps,
        available_steps=state.available_steps,
        can_complete=state.can_complete,
    )


@router.post("/onboarding/skip", response_model=OnboardingStatusResponse)
async def skip_onboarding_route(
    auth: tuple[User, Session] = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
) -> OnboardingStatusResponse:
    user, _ = auth
    
    try:
        state = await skip_onboarding(db, user.id)
    except OnboardingAlreadyCompletedError as e:
        raise HTTPException(status_code=409, detail=str(e))
    
    return OnboardingStatusResponse(
        status=state.status,
        completed_steps=state.completed_steps,
        available_steps=state.available_steps,
        can_complete=state.can_complete,
    )


@router.get("/preview-recommendations", response_model=PreviewRecommendationsResponse)
async def get_preview_recommendations_route(
    source: Optional[str] = Query(
        default=None,
        description="Source vector to use: intent, resume, or github. If not provided, returns trending issues.",
    ),
    auth: tuple[User, Session] = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
) -> PreviewRecommendationsResponse:
    user, _ = auth
    
    try:
        issues = await get_preview_recommendations(db, user.id, source)
    except InvalidSourceError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    return PreviewRecommendationsResponse(
        source=source,
        issues=[
            PreviewIssueResponse(
                node_id=issue.node_id,
                title=issue.title,
                repo_name=issue.repo_name,
                primary_language=issue.primary_language,
                q_score=issue.q_score,
            )
            for issue in issues
        ],
    )

