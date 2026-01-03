"""
Search API routes with tiered rate limiting.
Unknown users: 10 req/min
Authenticated users: 60 req/min
"""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlmodel.ext.asyncio.session import AsyncSession

from src.api.dependencies import get_db
from src.middleware.context import RequestContext, get_request_context
from src.middleware.rate_limit import get_rate_limiter
from src.core.audit import log_audit_event, AuditEvent
from src.services.search_service import (
    SearchFilters,
    SearchRequest,
    hybrid_search,
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE,
)
from src.services.search_cache import (
    get_cached_search,
    cache_search_response,
)

router = APIRouter()


# Rate limit constants
ANON_SEARCH_LIMIT = 10
AUTH_SEARCH_LIMIT = 60
RATE_LIMIT_WINDOW = 60 # secs


class SearchFiltersInput(BaseModel):
    """API input model for search filters."""
    languages: list[str] = Field(default_factory=list, max_length=10)
    labels: list[str] = Field(default_factory=list, max_length=20)
    repos: list[str] = Field(default_factory=list, max_length=10)


class SearchRequestInput(BaseModel):
    """API input model for search request."""
    query: str = Field(..., min_length=1, max_length=500)
    filters: SearchFiltersInput = Field(default_factory=SearchFiltersInput)
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE)


class SearchResultOutput(BaseModel):
    """API output model for a single search result."""
    node_id: str
    title: str
    body_preview: str
    labels: list[str]
    q_score: float
    repo_name: str
    primary_language: Optional[str]
    github_created_at: str
    rrf_score: float


class SearchResponseOutput(BaseModel):
    """API output model for search response."""
    search_id: str
    results: list[SearchResultOutput]
    total: int
    page: int
    page_size: int
    has_more: bool


async def _get_optional_user_id(request: Request, db: AsyncSession) -> Optional[UUID]:
    """
    Attempts to extract user_id from session cookie.
    Returns None if not authenticated, no error raised.
    """
    from src.core.cookies import SESSION_COOKIE_NAME
    from src.services.session_service import get_session_by_id
    
    session_id_str = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_id_str:
        return None
    
    try:
        session_uuid = UUID(session_id_str)
        session = await get_session_by_id(db, session_uuid)
        if session:
            return session.user_id
    except (ValueError, Exception):
        pass
    
    return None


async def check_search_rate_limit(
    request: Request,
    ctx: RequestContext = Depends(get_request_context),
    db: AsyncSession = Depends(get_db),
) -> Optional[UUID]:
    """
    Tiered rate limiting for search:
    - Unknown: 10 req/min (keyed by IP)
    - Authenticated: 60 req/min (keyed by user_id)
    
    Returns user_id if authenticated, None otherwise.
    """
    limiter = await get_rate_limiter()
    user_id = await _get_optional_user_id(request, db)
    
    if user_id:
        key = f"search:user:{user_id}"
        max_requests = AUTH_SEARCH_LIMIT
    else:
        key = f"search:ip:{ctx.ip_address}"
        max_requests = ANON_SEARCH_LIMIT
    
    is_limited, retry_after = await limiter.is_rate_limited(
        key=key,
        max_requests=max_requests,
        window_seconds=RATE_LIMIT_WINDOW,
    )
    
    if is_limited:
        log_audit_event(
            AuditEvent.RATE_LIMITED,
            user_id=user_id,
            ip_address=ctx.ip_address,
            metadata={
                "endpoint": "search",
                "retry_after": retry_after,
                "key": key,
            },
        )
        raise HTTPException(
            status_code=429,
            detail="Too many search requests",
            headers={"Retry-After": str(retry_after)},
        )
    
    return user_id


@router.post("", response_model=SearchResponseOutput)
async def search(
    body: SearchRequestInput,
    user_id: Optional[UUID] = Depends(check_search_rate_limit),
    db: AsyncSession = Depends(get_db),
    ctx: RequestContext = Depends(get_request_context),
) -> SearchResponseOutput:
    """
    Hybrid search combining vector similarity and BM25 full-text search.
    Results are ranked using Reciprocal Rank Fusion (RRF).
    """
    # Convert input models to service models
    filters = SearchFilters(
        languages=body.filters.languages,
        labels=body.filters.labels,
        repos=body.filters.repos,
    )
    
    request = SearchRequest(
        query=body.query,
        filters=filters,
        page=body.page,
        page_size=body.page_size,
    )
    
    # Check cache first
    cached_response = await get_cached_search(request)
    if cached_response:
        response = cached_response
        cache_hit = True
    else:
        # Execute hybrid search
        response = await hybrid_search(db, request)
        # Cache the response
        await cache_search_response(request, response)
        cache_hit = False
    
    # Log search for analytics (interaction logging is separate)
    log_audit_event(
        AuditEvent.SEARCH,
        user_id=user_id,
        ip_address=ctx.ip_address,
        metadata={
            "search_id": str(response.search_id),
            "query": body.query,
            "result_count": len(response.results),
            "filters": body.filters.model_dump(),
            "cache_hit": cache_hit,
        },
    )
    
    # Convert to output model
    results = [
        SearchResultOutput(
            node_id=r.node_id,
            title=r.title,
            body_preview=r.body_text,
            labels=r.labels,
            q_score=r.q_score,
            repo_name=r.repo_name,
            primary_language=r.primary_language,
            github_created_at=r.github_created_at.isoformat(),
            rrf_score=r.rrf_score,
        )
        for r in response.results
    ]
    
    return SearchResponseOutput(
        search_id=str(response.search_id),
        results=results,
        total=response.total,
        page=response.page,
        page_size=response.page_size,
        has_more=response.has_more,
    )


class InteractionInput(BaseModel):
    """API input for logging search result interactions."""
    search_id: str = Field(..., description="UUID from search response")
    selected_node_id: str = Field(..., description="Issue node_id that was clicked")
    position: int = Field(..., ge=1, description="1-indexed position in results")


@router.post("/interact", status_code=204)
async def log_interaction(
    body: InteractionInput,
    user_id: Optional[UUID] = Depends(check_search_rate_limit),
    db: AsyncSession = Depends(get_db),
    ctx: RequestContext = Depends(get_request_context),
) -> Response:
    """
    Log a search result interaction for the golden dataset.
    Used to train and evaluate future ranking models.
    
    The search_id must be from a recent search (within cache TTL).
    """
    try:
        search_uuid = UUID(body.search_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid search_id format")
    
    # Insert interaction record into analytics.search_interactions
    sql = text("""
        INSERT INTO analytics.search_interactions 
        (search_id, user_id, query_text, filters_json, selected_node_id, position)
        VALUES (:search_id, :user_id, :query_text, :filters_json, :selected_node_id, :position)
    """)
    
    await db.execute(sql, {
        "search_id": search_uuid,
        "user_id": user_id,
        "query_text": "",  # Would need to lookup from cache or pass in request
        "filters_json": None,
        "selected_node_id": body.selected_node_id,
        "position": body.position,
    })
    await db.commit()
    
    log_audit_event(
        AuditEvent.SEARCH_INTERACTION,
        user_id=user_id,
        ip_address=ctx.ip_address,
        metadata={
            "search_id": body.search_id,
            "selected_node_id": body.selected_node_id,
            "position": body.position,
        },
    )
    
    return Response(status_code=204)

