"""
Hybrid search service using Reciprocal Rank Fusion (RRF).
Combines ScaNN/HNSW vector similarity with BM25 full-text search.

Two-Stage Retrieval Architecture:
    Stage 1: Fetch candidate IDs from vector and BM25 paths (no filters),
             perform RRF fusion, apply filters post-fusion, return ordered
             node_ids with accurate COUNT.
    Stage 2: Hydrate current page with full metadata, preserving RRF order.

Edge Case Decisions:
    Embedding failure: Skip vector path; BM25-only fallback
    No BM25 matches: Vector-only results; RRF = 1/(60+rank) + 0
    RRF tie-breaking: q_score DESC
    Filter zero results: Strict empty (no relaxation)
    Deep pagination (>500): Empty page; total remains accurate
    Stage 2 missing IDs: Log discrepancy; return partial results
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from uuid import UUID, uuid4
import hashlib
import json
import logging

from sqlalchemy import text
from sqlmodel.ext.asyncio.session import AsyncSession

from src.services.embedding_service import embed_query
from src.core.config import get_settings

logger = logging.getLogger(__name__)

# RRF constant, standard value 
RRF_K: int = 60

# Maximum candidates from each retrieval path, increased for better recall
CANDIDATE_LIMIT: int = 500

# Default pagination
DEFAULT_PAGE_SIZE: int = 20
MAX_PAGE_SIZE: int = 50


@dataclass
class SearchFilters:
    """
    Multi-select filters for hybrid search.
    All filters use ANY semantics (OR within filter, AND across filters).
    """
    languages: list[str] = field(default_factory=list)
    labels: list[str] = field(default_factory=list)
    repos: list[str] = field(default_factory=list)
    
    def is_empty(self) -> bool:
        return not self.languages and not self.labels and not self.repos
    
    def to_cache_key(self) -> str:
        """Deterministic string for cache key generation"""
        return json.dumps({
            "languages": sorted(self.languages),
            "labels": sorted(self.labels),
            "repos": sorted(self.repos),
        }, sort_keys=True)


@dataclass
class SearchRequest:
    """Search request with query, filters, and pagination."""
    query: str
    filters: SearchFilters = field(default_factory=SearchFilters)
    page: int = 1
    page_size: int = DEFAULT_PAGE_SIZE
    user_id: Optional[UUID] = None  # For personalization cache key
    
    def __post_init__(self):
        if self.page < 1:
            self.page = 1
        if self.page_size < 1:
            self.page_size = DEFAULT_PAGE_SIZE
        if self.page_size > MAX_PAGE_SIZE:
            self.page_size = MAX_PAGE_SIZE
    
    @property
    def offset(self) -> int:
        return (self.page - 1) * self.page_size
    
    def cache_key(self, include_user: bool = False) -> str:
        """SHA256 hash for Redis cache key"""
        key_data = f"{self.query}|{self.filters.to_cache_key()}|{self.page}|{self.page_size}"
        if include_user and self.user_id:
            key_data += f"|{self.user_id}"
        return hashlib.sha256(key_data.encode()).hexdigest()


@dataclass
class SearchResultItem:
    """Single search result with issue data and scores."""
    node_id: str
    title: str
    body_text: str
    labels: list[str]
    q_score: float
    repo_name: str
    primary_language: Optional[str]
    github_created_at: datetime
    rrf_score: float


@dataclass
class SearchResponse:
    """Paginated search response."""
    search_id: UUID
    results: list[SearchResultItem]
    total: int
    page: int
    page_size: int
    has_more: bool
    query: str
    filters: SearchFilters


@dataclass
class Stage1Result:
    """Result from Stage 1: ordered IDs with scores and total count."""
    node_ids: list[str]
    rrf_scores: dict[str, float]
    total: int


async def hybrid_search(
    db: AsyncSession,
    request: SearchRequest,
) -> SearchResponse:
    """
    Executes two-stage hybrid search using RRF to combine vector and BM25 results.
    
    1: Get ordered candidate IDs and total count
    2: Hydrate current page with full metadata
    
    Args:
        db: Database session
        request: Search request with query, filters, pagination
        
    Returns:
        SearchResponse with paginated results and accurate total
    """
    search_id = uuid4()
    
    logger.info(
        f"Search request: search_id={search_id}, query={request.query!r}, "
        f"filters={request.filters}, page={request.page}"
    )
    
    # Embed the query, may return None on failure
    query_embedding = await embed_query(request.query)
    use_vector_path = query_embedding is not None
    
    if not use_vector_path:
        logger.warning(f"Embedding failed for search_id={search_id}; using BM25-only")
    
    # Stage 1
    stage1_result = await _execute_stage1(
        db=db,
        query_text=request.query,
        query_embedding=query_embedding,
        filters=request.filters,
        use_vector_path=use_vector_path,
    )
    
    # Handle empty results or deep pagination
    if stage1_result.total == 0:
        logger.info(f"Search completed: search_id={search_id}, results=0, total=0")
        return SearchResponse(
            search_id=search_id,
            results=[],
            total=0,
            page=request.page,
            page_size=request.page_size,
            has_more=False,
            query=request.query,
            filters=request.filters,
        )
    
    # Get current page IDs
    start_idx = request.offset
    end_idx = start_idx + request.page_size
    page_ids = stage1_result.node_ids[start_idx:end_idx]
    
    # Deep pagination (no IDs for this page)
    if not page_ids:
        logger.info(
            f"Search completed: search_id={search_id}, "
            f"page={request.page} beyond available results, total={stage1_result.total}"
        )
        return SearchResponse(
            search_id=search_id,
            results=[],
            total=stage1_result.total,
            page=request.page,
            page_size=request.page_size,
            has_more=False,
            query=request.query,
            filters=request.filters,
        )
    
    # Stage 2
    results = await _execute_stage2(
        db=db,
        page_ids=page_ids,
        rrf_scores=stage1_result.rrf_scores,
    )
    
    # Log discrepancy if Stage 2 returned fewer rows than expected
    if len(results) < len(page_ids):
        missing_count = len(page_ids) - len(results)
        logger.warning(
            f"Stage 2 returned {len(results)} of {len(page_ids)} expected rows "
            f"for search_id={search_id}; {missing_count} issues may have been deleted"
        )
    
    has_more = (request.offset + len(results)) < stage1_result.total
    
    logger.info(
        f"Search completed: search_id={search_id}, "
        f"results={len(results)}, total={stage1_result.total}"
    )
    
    return SearchResponse(
        search_id=search_id,
        results=results,
        total=stage1_result.total,
        page=request.page,
        page_size=request.page_size,
        has_more=has_more,
        query=request.query,
        filters=request.filters,
    )


async def _execute_stage1(
    db: AsyncSession,
    query_text: str,
    query_embedding: Optional[list[float]],
    filters: SearchFilters,
    use_vector_path: bool,
) -> Stage1Result:
    """
    Stage 1: Fetch candidate IDs from vector and BM25 paths without filters,
    perform RRF fusion, apply filters post-fusion, return ordered IDs with COUNT.
    
    Filters are applied AFTER RRF fusion to prevent recall gaps.
    """
    sql = _build_stage1_sql(filters, use_vector_path)
    settings = get_settings()
    
    params = {
        "query_text": query_text,
        "langs": filters.languages or None,
        "labels": filters.labels or None,
        "repos": filters.repos or None,
        "candidate_limit": CANDIDATE_LIMIT,
        "freshness_half_life_days": float(settings.search_freshness_half_life_days) if settings.search_freshness_half_life_days > 0 else 0.0001,
        "freshness_floor": float(settings.search_freshness_floor),
        "freshness_weight": float(settings.search_freshness_weight),
    }
    
    if use_vector_path and query_embedding:
        params["query_vec"] = str(query_embedding)
    
    result = await db.execute(text(sql), params)
    rows = result.fetchall()
    
    if not rows:
        return Stage1Result(node_ids=[], rrf_scores={}, total=0)
    
    node_ids = []
    rrf_scores = {}
    total = 0
    
    for row in rows:
        node_ids.append(row.node_id)
        rrf_scores[row.node_id] = float(row.rrf_score)
        # All rows have same total_count from window function
        total = row.total_count
    
    return Stage1Result(node_ids=node_ids, rrf_scores=rrf_scores, total=total)


async def _execute_stage2(
    db: AsyncSession,
    page_ids: list[str],
    rrf_scores: dict[str, float],
) -> list[SearchResultItem]:
    """
    Stage 2: Hydrate page IDs with full metadata.
    Uses array_position to preserve RRF ordering from Stage 1.
    """
    if not page_ids:
        return []
    
    sql = """
    SELECT 
        i.node_id,
        i.title,
        i.body_text,
        i.labels,
        i.q_score,
        i.github_created_at,
        r.full_name AS repo_name,
        r.primary_language
    FROM ingestion.issue i
    JOIN ingestion.repository r ON i.repo_id = r.node_id
    WHERE i.node_id = ANY(:ids) AND i.state = 'open'
    ORDER BY array_position(:ids, i.node_id)
    """
    
    result = await db.execute(text(sql), {"ids": page_ids})
    rows = result.fetchall()
    
    results = []
    for row in rows:
        results.append(SearchResultItem(
            node_id=row.node_id,
            title=row.title,
            body_text=row.body_text[:500] if row.body_text else "",
            labels=row.labels or [],
            q_score=row.q_score,
            repo_name=row.repo_name,
            primary_language=row.primary_language,
            github_created_at=row.github_created_at,
            rrf_score=rrf_scores.get(row.node_id, 0.0),
        ))
    
    return results


def _build_stage1_sql(filters: SearchFilters, use_vector_path: bool) -> str:
    """
    Builds Stage 1 SQL: candidate retrieval without filters in CTEs,
    RRF fusion, then post-filter application.
    
    Key design decisions:
        No filters in CTEs: Prevents recall gaps with selective filters
        Post-fusion filtering: Applied in final WHERE clause
        Tie-breaking: q_score DESC for deterministic ordering
        COUNT(*) OVER(): Accurate total without separate query
    """
    
    # Post-fusion filter conditions
    filter_conditions = []
    if filters.languages:
        filter_conditions.append("r.primary_language = ANY(:langs)")
    if filters.labels:
        filter_conditions.append("fused.labels && :labels")
    if filters.repos:
        filter_conditions.append("r.full_name = ANY(:repos)")
    
    post_filter_where = ""
    if filter_conditions:
        post_filter_where = "WHERE " + " AND ".join(filter_conditions)
    
    if use_vector_path:
        # Full hybrid: vector + BM25
        sql = f"""
        WITH vector_results AS (
            SELECT 
                i.node_id,
                i.labels,
                i.repo_id,
                i.q_score,
                i.github_created_at,
                i.ingested_at,
                ROW_NUMBER() OVER (ORDER BY i.embedding <=> CAST(:query_vec AS vector)) AS v_rank
            FROM ingestion.issue i
            WHERE i.embedding IS NOT NULL AND i.state = 'open'
            ORDER BY i.embedding <=> CAST(:query_vec AS vector)
            LIMIT :candidate_limit
        ),
        bm25_results AS (
            SELECT 
                i.node_id,
                i.labels,
                i.repo_id,
                i.q_score,
                i.github_created_at,
                i.ingested_at,
                ROW_NUMBER() OVER (
                    ORDER BY ts_rank(i.search_vector, plainto_tsquery('english', :query_text)) DESC
                ) AS b_rank
            FROM ingestion.issue i
            WHERE i.search_vector @@ plainto_tsquery('english', :query_text) AND i.state = 'open'
            ORDER BY ts_rank(i.search_vector, plainto_tsquery('english', :query_text)) DESC
            LIMIT :candidate_limit
        ),
        fused AS (
            SELECT 
                COALESCE(v.node_id, b.node_id) AS node_id,
                COALESCE(v.labels, b.labels) AS labels,
                COALESCE(v.repo_id, b.repo_id) AS repo_id,
                COALESCE(v.q_score, b.q_score) AS q_score,
                COALESCE(v.github_created_at, b.github_created_at) AS github_created_at,
                COALESCE(v.ingested_at, b.ingested_at) AS ingested_at,
                COALESCE(1.0 / ({RRF_K} + v.v_rank), 0) + 
                COALESCE(1.0 / ({RRF_K} + b.b_rank), 0) AS rrf_score
            FROM vector_results v
            FULL OUTER JOIN bm25_results b ON v.node_id = b.node_id
        ),
        filtered AS (
            SELECT 
                fused.node_id,
                fused.rrf_score,
                fused.q_score,
                GREATEST(
                    :freshness_floor,
                    POWER(
                        0.5,
                        (
                            EXTRACT(EPOCH FROM (NOW() - GREATEST(fused.ingested_at, fused.github_created_at))) / 86400.0
                        ) / NULLIF(:freshness_half_life_days, 0)
                    )
                ) AS freshness,
                (
                    fused.rrf_score +
                    (:freshness_weight * GREATEST(
                        :freshness_floor,
                        POWER(
                            0.5,
                            (
                                EXTRACT(EPOCH FROM (NOW() - GREATEST(fused.ingested_at, fused.github_created_at))) / 86400.0
                            ) / NULLIF(:freshness_half_life_days, 0)
                        )
                    ))
                ) AS final_score
            FROM fused
            JOIN ingestion.repository r ON fused.repo_id = r.node_id
            {post_filter_where}
        )
        SELECT 
            node_id,
            rrf_score,
            COUNT(*) OVER() AS total_count
        FROM filtered
        ORDER BY final_score DESC, q_score DESC, node_id ASC
        """
    else:
        # BM25-only fallback (embedding failed)
        sql = f"""
        WITH bm25_results AS (
            SELECT 
                i.node_id,
                i.labels,
                i.repo_id,
                i.q_score,
                i.github_created_at,
                i.ingested_at,
                ROW_NUMBER() OVER (
                    ORDER BY ts_rank(i.search_vector, plainto_tsquery('english', :query_text)) DESC
                ) AS b_rank
            FROM ingestion.issue i
            WHERE i.search_vector @@ plainto_tsquery('english', :query_text) AND i.state = 'open'
            ORDER BY ts_rank(i.search_vector, plainto_tsquery('english', :query_text)) DESC
            LIMIT :candidate_limit
        ),
        fused AS (
            SELECT 
                node_id,
                labels,
                repo_id,
                q_score,
                github_created_at,
                ingested_at,
                1.0 / ({RRF_K} + b_rank) AS rrf_score
            FROM bm25_results
        ),
        filtered AS (
            SELECT 
                fused.node_id,
                fused.rrf_score,
                fused.q_score,
                GREATEST(
                    :freshness_floor,
                    POWER(
                        0.5,
                        (
                            EXTRACT(EPOCH FROM (NOW() - GREATEST(fused.ingested_at, fused.github_created_at))) / 86400.0
                        ) / NULLIF(:freshness_half_life_days, 0)
                    )
                ) AS freshness,
                (
                    fused.rrf_score +
                    (:freshness_weight * GREATEST(
                        :freshness_floor,
                        POWER(
                            0.5,
                            (
                                EXTRACT(EPOCH FROM (NOW() - GREATEST(fused.ingested_at, fused.github_created_at))) / 86400.0
                            ) / NULLIF(:freshness_half_life_days, 0)
                        )
                    ))
                ) AS final_score
            FROM fused
            JOIN ingestion.repository r ON fused.repo_id = r.node_id
            {post_filter_where}
        )
        SELECT 
            node_id,
            rrf_score,
            COUNT(*) OVER() AS total_count
        FROM filtered
        ORDER BY final_score DESC, q_score DESC, node_id ASC
        """
    
    return sql


__all__ = [
    "SearchFilters",
    "SearchRequest",
    "SearchResultItem",
    "SearchResponse",
    "Stage1Result",
    "hybrid_search",
    "RRF_K",
    "CANDIDATE_LIMIT",
    "DEFAULT_PAGE_SIZE",
    "MAX_PAGE_SIZE",
    "_build_stage1_sql",
]
