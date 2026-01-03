"""
Redis-based caching for search results, skipped if unavailable.
Time to Live: 5 min
"""

import json
import logging
from datetime import datetime
from typing import Optional
from uuid import UUID

from src.core.redis import get_redis
from src.services.search_service import (
    SearchRequest,
    SearchResponse,
    SearchResultItem,
    SearchFilters,
)

logger = logging.getLogger(__name__)

CACHE_TTL_SECONDS = 300
CACHE_PREFIX = "search:"


def _serialize_response(response: SearchResponse) -> str:
    """Serialize SearchResponse to JSON string."""
    data = {
        "search_id": str(response.search_id),
        "results": [
            {
                "node_id": r.node_id,
                "title": r.title,
                "body_text": r.body_text,
                "labels": r.labels,
                "q_score": r.q_score,
                "repo_name": r.repo_name,
                "primary_language": r.primary_language,
                "github_created_at": r.github_created_at.isoformat(),
                "rrf_score": r.rrf_score,
            }
            for r in response.results
        ],
        "total": response.total,
        "page": response.page,
        "page_size": response.page_size,
        "has_more": response.has_more,
        "query": response.query,
        "filters": {
            "languages": response.filters.languages,
            "labels": response.filters.labels,
            "repos": response.filters.repos,
        },
    }
    return json.dumps(data)


def _deserialize_response(data: str) -> SearchResponse:
    """Deserialize JSON string to SearchResponse."""
    parsed = json.loads(data)
    
    results = [
        SearchResultItem(
            node_id=r["node_id"],
            title=r["title"],
            body_text=r["body_text"],
            labels=r["labels"],
            q_score=r["q_score"],
            repo_name=r["repo_name"],
            primary_language=r["primary_language"],
            github_created_at=datetime.fromisoformat(r["github_created_at"]),
            rrf_score=r["rrf_score"],
        )
        for r in parsed["results"]
    ]
    
    filters = SearchFilters(
        languages=parsed["filters"]["languages"],
        labels=parsed["filters"]["labels"],
        repos=parsed["filters"]["repos"],
    )
    
    return SearchResponse(
        search_id=UUID(parsed["search_id"]),
        results=results,
        total=parsed["total"],
        page=parsed["page"],
        page_size=parsed["page_size"],
        has_more=parsed["has_more"],
        query=parsed["query"],
        filters=filters,
    )


async def get_cached_search(request: SearchRequest) -> Optional[SearchResponse]:
    """
    Retrieve cached search response if available.
    Returns None if cache miss or Redis unavailable.
    """
    redis = await get_redis()
    if redis is None:
        return None
    
    cache_key = f"{CACHE_PREFIX}{request.cache_key()}"
    
    try:
        cached = await redis.get(cache_key)
        if cached:
            logger.debug(f"Cache hit: {cache_key}")
            return _deserialize_response(cached)
        logger.debug(f"Cache miss: {cache_key}")
        return None
    except Exception as e:
        logger.warning(f"Cache read error: {e}")
        return None


async def cache_search_response(
    request: SearchRequest,
    response: SearchResponse,
) -> None:
    """
    Cache search response with 5-minute TTL.
    Silently fails if Redis unavailable.
    """
    redis = await get_redis()
    if redis is None:
        return
    
    cache_key = f"{CACHE_PREFIX}{request.cache_key()}"
    
    try:
        serialized = _serialize_response(response)
        await redis.setex(cache_key, CACHE_TTL_SECONDS, serialized)
        logger.debug(f"Cached search: {cache_key}")
    except Exception as e:
        logger.warning(f"Cache write error: {e}")


async def invalidate_search_cache(pattern: str = "*") -> int:
    """
    Invalidate cached search results matching pattern.
    Uses Redis pipeline to batch deletions in a single network round trip.
    Returns count of deleted keys.
    """
    redis = await get_redis()
    if redis is None:
        return 0
    
    try:
        full_pattern = f"{CACHE_PREFIX}{pattern}"
        
        # Collect all matching keys first
        keys = [key async for key in redis.scan_iter(full_pattern)]
        
        if not keys:
            return 0
        
        # Use pipeline to delete all keys in one network round trip
        async with redis.pipeline(transaction=True) as pipe:
            for key in keys:
                pipe.delete(key)
            await pipe.execute()
        
        logger.debug(f"Invalidated {len(keys)} cache keys matching {full_pattern}")
        return len(keys)
    except Exception as e:
        logger.warning(f"Cache invalidation error: {e}")
        return 0


__all__ = [
    "CACHE_TTL_SECONDS",
    "CACHE_PREFIX",
    "get_cached_search",
    "cache_search_response",
    "invalidate_search_cache",
    "_serialize_response",
    "_deserialize_response",
]

