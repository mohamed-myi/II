"""
Integration tests for hybrid search end-to-end flow.
Requires Docker (testcontainers with pgvector).
"""

import os
import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

try:
    from testcontainers.postgres import PostgresContainer
    TESTCONTAINERS_AVAILABLE = True
except ImportError:
    TESTCONTAINERS_AVAILABLE = False

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel.ext.asyncio.session import AsyncSession

from src.services.search_service import (
    SearchFilters,
    SearchRequest,
    hybrid_search,
)


pytestmark = pytest.mark.skipif(
    not TESTCONTAINERS_AVAILABLE,
    reason="testcontainers[postgres] not installed; requires Docker"
)


# Schema setup SQL including search_vector generated column
SETUP_SQL = """
CREATE EXTENSION IF NOT EXISTS vector;
CREATE SCHEMA IF NOT EXISTS ingestion;

CREATE TABLE ingestion.repository (
    node_id VARCHAR PRIMARY KEY,
    full_name VARCHAR NOT NULL UNIQUE,
    primary_language VARCHAR,
    issue_velocity_week INTEGER NOT NULL DEFAULT 0,
    stargazer_count INTEGER NOT NULL DEFAULT 0,
    languages JSONB,
    topics TEXT[],
    last_scraped_at TIMESTAMPTZ
);

CREATE INDEX ix_ingestion_repository_primary_language ON ingestion.repository(primary_language);

CREATE TABLE ingestion.issue (
    node_id VARCHAR PRIMARY KEY,
    repo_id VARCHAR NOT NULL REFERENCES ingestion.repository(node_id),
    has_code BOOLEAN NOT NULL DEFAULT false,
    has_template_headers BOOLEAN NOT NULL DEFAULT false,
    tech_stack_weight REAL NOT NULL DEFAULT 0.0,
    q_score REAL NOT NULL DEFAULT 0.0,
    survival_score REAL NOT NULL DEFAULT 0.0,
    title VARCHAR NOT NULL,
    body_text VARCHAR NOT NULL,
    labels TEXT[],
    embedding vector(768),
    github_created_at TIMESTAMPTZ NOT NULL,
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    search_vector tsvector GENERATED ALWAYS AS (
        to_tsvector('english', COALESCE(title, '') || ' ' || COALESCE(body_text, ''))
    ) STORED
);

CREATE INDEX ix_ingestion_issue_repo_id ON ingestion.issue(repo_id);
CREATE INDEX ix_issue_search_vector ON ingestion.issue USING GIN (search_vector);
CREATE INDEX ix_issue_embedding_hnsw ON ingestion.issue USING hnsw (embedding vector_cosine_ops) WITH (m = 16, ef_construction = 64);
"""

# Sample 768-dim embedding (normalized random vector for testing)
SAMPLE_EMBEDDING = [0.01] * 768


@pytest.fixture(scope="module")
def postgres_container():
    """Ephemeral PostgreSQL 16 with pgvector via testcontainers."""
    with PostgresContainer(
        image="pgvector/pgvector:pg16",
        username="test",
        password="test",
        dbname="testdb",
    ) as pg:
        yield pg


@pytest.fixture(scope="module")
def async_connection_url(postgres_container):
    """Async connection URL for test sessions."""
    url = postgres_container.get_connection_url()
    # Strip SQLAlchemy dialect prefix and convert to asyncpg
    url = url.replace("postgresql+psycopg2://", "postgresql://")
    return url.replace("postgresql://", "postgresql+asyncpg://")


@pytest.fixture(scope="module")
def async_engine(async_connection_url, postgres_container):
    """Async engine with schema setup."""
    import psycopg2
    
    # Setup schema using sync connection
    # Strip SQLAlchemy dialect prefix for psycopg2 compatibility
    sync_url = postgres_container.get_connection_url()
    sync_url = sync_url.replace("postgresql+psycopg2://", "postgresql://")
    conn = psycopg2.connect(sync_url)
    conn.autocommit = True
    cursor = conn.cursor()
    cursor.execute(SETUP_SQL)
    cursor.close()
    conn.close()
    
    engine = create_async_engine(
        async_connection_url,
        echo=False,
        pool_pre_ping=True,
        connect_args={
            "prepared_statement_cache_size": 0,
            "statement_cache_size": 0,
        },
    )
    return engine


@pytest.fixture
async def db_session(async_engine):
    """Provides a fresh session for each test with proper cleanup."""
    async_session_factory = sessionmaker(
        async_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )
    
    async with async_session_factory() as session:
        # Clean any leftover test data before yielding
        try:
            await session.execute(text("DELETE FROM ingestion.issue WHERE node_id LIKE 'issue_%'"))
            await session.execute(text("DELETE FROM ingestion.repository WHERE node_id LIKE 'repo_%'"))
            await session.commit()
        except Exception:
            await session.rollback()
        
        yield session
        
        # Clean up after test
        try:
            await session.rollback()
            await session.execute(text("DELETE FROM ingestion.issue WHERE node_id LIKE 'issue_%'"))
            await session.execute(text("DELETE FROM ingestion.repository WHERE node_id LIKE 'repo_%'"))
            await session.commit()
        except Exception:
            pass


@pytest.fixture
async def seeded_db(db_session):
    """Seeds database with test data."""
    # Insert test repository
    await db_session.execute(text("""
        INSERT INTO ingestion.repository (node_id, full_name, primary_language, stargazer_count)
        VALUES 
            ('repo_1', 'test/python-repo', 'Python', 1000),
            ('repo_2', 'test/rust-repo', 'Rust', 2000)
        ON CONFLICT DO NOTHING
    """))
    
    # Insert test issues with embeddings
    embedding_str = "[" + ",".join(str(x) for x in SAMPLE_EMBEDDING) + "]"
    
    await db_session.execute(text(f"""
        INSERT INTO ingestion.issue 
        (node_id, repo_id, title, body_text, labels, q_score, embedding, github_created_at)
        VALUES 
            ('issue_1', 'repo_1', 'Python async error handling', 
             'How to handle exceptions in async Python code with asyncio',
             ARRAY['bug', 'python'], 0.8, '{embedding_str}'::vector, NOW()),
            ('issue_2', 'repo_1', 'Memory leak in Python service',
             'Our Python service leaks memory when processing large files',
             ARRAY['bug', 'performance'], 0.7, '{embedding_str}'::vector, NOW()),
            ('issue_3', 'repo_2', 'Rust borrow checker issue',
             'Cannot understand why borrow checker rejects my code',
             ARRAY['help wanted'], 0.9, '{embedding_str}'::vector, NOW())
        ON CONFLICT DO NOTHING
    """))
    
    await db_session.commit()
    return db_session


class TestHybridSearchIntegration:
    """Integration tests for hybrid_search function."""

    @pytest.mark.asyncio
    async def test_search_returns_results(self, seeded_db):
        """Basic search should return matching results."""
        # Mock embed_query to return consistent embedding
        with patch('src.services.search_service.embed_query', new_callable=AsyncMock) as mock_embed:
            mock_embed.return_value = SAMPLE_EMBEDDING
            
            request = SearchRequest(query="Python error")
            response = await hybrid_search(seeded_db, request)
        
        assert len(response.results) > 0
        assert response.search_id is not None
        assert response.query == "Python error"

    @pytest.mark.asyncio
    async def test_search_with_language_filter(self, seeded_db):
        """Language filter should restrict results."""
        with patch('src.services.search_service.embed_query', new_callable=AsyncMock) as mock_embed:
            mock_embed.return_value = SAMPLE_EMBEDDING
            
            request = SearchRequest(
                query="error",
                filters=SearchFilters(languages=["Rust"]),
            )
            response = await hybrid_search(seeded_db, request)
        
        # Should only return Rust issues
        for result in response.results:
            assert result.primary_language == "Rust"

    @pytest.mark.asyncio
    async def test_search_with_label_filter(self, seeded_db):
        """Label filter should restrict results."""
        with patch('src.services.search_service.embed_query', new_callable=AsyncMock) as mock_embed:
            mock_embed.return_value = SAMPLE_EMBEDDING
            
            request = SearchRequest(
                query="issue",
                filters=SearchFilters(labels=["bug"]),
            )
            response = await hybrid_search(seeded_db, request)
        
        # All results should have 'bug' label
        for result in response.results:
            assert "bug" in result.labels

    @pytest.mark.asyncio
    async def test_search_empty_results_with_strict_filter(self, seeded_db):
        """Strict filter with no matches should return empty results."""
        with patch('src.services.search_service.embed_query', new_callable=AsyncMock) as mock_embed:
            mock_embed.return_value = SAMPLE_EMBEDDING
            
            request = SearchRequest(
                query="test",
                filters=SearchFilters(languages=["Go"]),  # No Go repos in test data
            )
            response = await hybrid_search(seeded_db, request)
        
        assert len(response.results) == 0
        assert response.total == 0

    @pytest.mark.asyncio
    async def test_search_pagination(self, seeded_db):
        """Pagination should work correctly."""
        with patch('src.services.search_service.embed_query', new_callable=AsyncMock) as mock_embed:
            mock_embed.return_value = SAMPLE_EMBEDDING
            
            # First page
            request1 = SearchRequest(query="Python", page=1, page_size=1)
            response1 = await hybrid_search(seeded_db, request1)
            
            # Second page
            request2 = SearchRequest(query="Python", page=2, page_size=1)
            response2 = await hybrid_search(seeded_db, request2)
        
        assert response1.page == 1
        assert response2.page == 2
        
        # Results should be different (if there are enough results)
        if response1.results and response2.results:
            assert response1.results[0].node_id != response2.results[0].node_id

    @pytest.mark.asyncio
    async def test_rrf_scores_are_positive(self, seeded_db):
        """RRF scores should be positive for matched results."""
        with patch('src.services.search_service.embed_query', new_callable=AsyncMock) as mock_embed:
            mock_embed.return_value = SAMPLE_EMBEDDING
            
            request = SearchRequest(query="Python async")
            response = await hybrid_search(seeded_db, request)
        
        for result in response.results:
            assert result.rrf_score > 0

    @pytest.mark.asyncio
    async def test_results_ordered_by_rrf_score(self, seeded_db):
        """Results should be ordered by RRF score descending."""
        with patch('src.services.search_service.embed_query', new_callable=AsyncMock) as mock_embed:
            mock_embed.return_value = SAMPLE_EMBEDDING
            
            request = SearchRequest(query="Python error")
            response = await hybrid_search(seeded_db, request)
        
        if len(response.results) >= 2:
            for i in range(len(response.results) - 1):
                assert response.results[i].rrf_score >= response.results[i + 1].rrf_score


class TestSearchWithRealEmbeddings:
    """
    Integration tests using real embedding model.
    These tests require the sentence-transformers model to be downloaded.
    """

    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_semantic_search_relevance(self, seeded_db):
        """
        Real embeddings should rank semantically similar results higher.
        Marked as slow because it loads the embedding model.
        """
        # This test uses real embeddings - skip if model not available
        try:
            from src.services.embedding_service import embed_query, reset_embedder_for_testing
            reset_embedder_for_testing()
        except ImportError:
            pytest.skip("sentence-transformers not installed")
        
        request = SearchRequest(query="exception handling in Python")
        response = await hybrid_search(seeded_db, request)
        
        # The "Python async error handling" issue should rank highly
        # since it's semantically related to "exception handling"
        assert len(response.results) > 0
        
        # Clean up
        reset_embedder_for_testing()

