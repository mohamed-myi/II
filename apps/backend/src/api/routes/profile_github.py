"""GitHub profile API routes for fetching and managing GitHub activity data."""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel.ext.asyncio.session import AsyncSession

from src.api.dependencies import get_db
from src.middleware.auth import require_auth
from src.services.github_profile_service import (
    fetch_github_profile,
    get_github_data,
    delete_github,
)
from src.ingestion.github_client import (
    GitHubAPIError,
    GitHubAuthError as ClientAuthError,
    GitHubRateLimitError as ClientRateLimitError,
)
from src.core.errors import (
    handle_profile_error,
    GitHubNotConnectedError,
    RefreshRateLimitError,
)
from models.identity import User, Session


router = APIRouter()


class GitHubInitiateResponse(BaseModel):
    """Response after initiating GitHub profile fetch."""
    status: str
    username: str
    starred_count: int
    contributed_repos: int
    languages: list[str]
    topics: list[str]
    vector_status: Optional[str]
    fetched_at: str
    minimal_data_warning: Optional[str] = None


class GitHubDataResponse(BaseModel):
    """Response containing stored GitHub profile data."""
    status: str
    username: str
    starred_count: int
    contributed_repos: int
    languages: list[str]
    topics: list[str]
    vector_status: Optional[str]
    fetched_at: Optional[str]


def _handle_github_error(e: Exception) -> HTTPException:
    """Converts GitHub-related exceptions to user-friendly HTTP responses."""
    if isinstance(e, GitHubNotConnectedError):
        return HTTPException(status_code=400, detail="Please connect GitHub first")
    if isinstance(e, RefreshRateLimitError):
        minutes = max(1, e.seconds_remaining // 60)
        return HTTPException(
            status_code=429,
            detail=f"GitHub refresh available in {minutes} minute{'s' if minutes > 1 else ''}"
        )
    if isinstance(e, ClientAuthError):
        return HTTPException(status_code=400, detail="Please reconnect your GitHub account")
    if isinstance(e, ClientRateLimitError):
        return HTTPException(status_code=503, detail="GitHub is busy. We'll try again shortly.")
    if isinstance(e, GitHubAPIError):
        return HTTPException(status_code=503, detail="Unable to reach GitHub. Please try again.")
    
    return handle_profile_error(e)


@router.post("/github", response_model=GitHubInitiateResponse)
async def initiate_github_fetch(
    auth: tuple[User, Session] = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
) -> GitHubInitiateResponse:
    """
    Initiates GitHub profile data fetch.
    
    Requires a connected GitHub account via /auth/connect/github.
    Extracts languages, topics, and starred/contributed repos.
    Generates github_vector and recalculates combined_vector.
    
    Returns:
        GitHubInitiateResponse with extracted profile data and vector status.
    
    Errors:
        400: GitHub not connected or authentication failed
        503: GitHub API unavailable or rate limited
    """
    user, _ = auth
    
    try:
        result = await fetch_github_profile(db, user.id, is_refresh=False)
    except (
        GitHubNotConnectedError,
        RefreshRateLimitError,
        ClientAuthError,
        ClientRateLimitError,
        GitHubAPIError,
    ) as e:
        raise _handle_github_error(e)
    
    return GitHubInitiateResponse(
        status=result["status"],
        username=result["username"],
        starred_count=result["starred_count"],
        contributed_repos=result["contributed_repos"],
        languages=result["languages"],
        topics=result["topics"],
        vector_status=result["vector_status"],
        fetched_at=result["fetched_at"],
        minimal_data_warning=result.get("minimal_data_warning"),
    )


@router.get("/github", response_model=GitHubDataResponse)
async def get_github(
    auth: tuple[User, Session] = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
) -> GitHubDataResponse:
    """
    Returns stored GitHub profile data.
    
    Returns:
        GitHubDataResponse with extracted languages, topics, and repo counts.
    
    Errors:
        404: No GitHub data found; use POST /profile/github first.
    """
    user, _ = auth
    
    data = await get_github_data(db, user.id)
    
    if data is None:
        raise HTTPException(
            status_code=404,
            detail="No GitHub data found. Connect GitHub first."
        )
    
    return GitHubDataResponse(
        status=data["status"],
        username=data["username"],
        starred_count=data["starred_count"],
        contributed_repos=data["contributed_repos"],
        languages=data["languages"],
        topics=data["topics"],
        vector_status=data["vector_status"],
        fetched_at=data["fetched_at"],
    )


@router.post("/github/refresh", response_model=GitHubInitiateResponse)
async def refresh_github(
    auth: tuple[User, Session] = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
) -> GitHubInitiateResponse:
    """
    Re-fetches GitHub profile data.
    
    Rate limited to 1 request per hour to avoid GitHub API limits.
    
    Returns:
        GitHubInitiateResponse with updated profile data.
    
    Errors:
        400: GitHub not connected or authentication failed
        429: Refresh rate limit exceeded; try again later
        503: GitHub API unavailable
    """
    user, _ = auth
    
    try:
        result = await fetch_github_profile(db, user.id, is_refresh=True)
    except (
        GitHubNotConnectedError,
        RefreshRateLimitError,
        ClientAuthError,
        ClientRateLimitError,
        GitHubAPIError,
    ) as e:
        raise _handle_github_error(e)
    
    return GitHubInitiateResponse(
        status=result["status"],
        username=result["username"],
        starred_count=result["starred_count"],
        contributed_repos=result["contributed_repos"],
        languages=result["languages"],
        topics=result["topics"],
        vector_status=result["vector_status"],
        fetched_at=result["fetched_at"],
        minimal_data_warning=result.get("minimal_data_warning"),
    )


@router.delete("/github")
async def delete_github_data(
    auth: tuple[User, Session] = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Clears GitHub profile data and vector.
    
    Does NOT revoke OAuth token; use DELETE /auth/connect/github for that.
    Triggers combined_vector recalculation from remaining sources.
    
    Returns:
        Confirmation of deletion.
    
    Errors:
        404: No GitHub data to delete.
    """
    user, _ = auth
    
    was_deleted = await delete_github(db, user.id)
    
    if not was_deleted:
        raise HTTPException(
            status_code=404,
            detail="No GitHub data to delete"
        )
    
    return {"deleted": True, "message": "GitHub data cleared"}
