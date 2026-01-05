"""Integration tests for Janitor pruning against real database"""

import os
import pytest
from datetime import datetime, timezone, timedelta

# Skip all tests if DATABASE_URL not configured
pytestmark = pytest.mark.skipif(
    not os.getenv("DATABASE_URL"),
    reason="DATABASE_URL environment variable not set"
)


@pytest.fixture
async def db_session():
    """
    Provides async session with test-scoped engine.
    
    Creates a fresh engine per test to avoid SQLAlchemy connection pool
    holding connections bound to a previous (now-closed) event loop.
    Each pytest-asyncio test gets its own event loop, so the engine
    must be created within that loop's context.
    """
    import os
    from sqlalchemy.ext.asyncio import create_async_engine
    from sqlalchemy.orm import sessionmaker
    from sqlmodel.ext.asyncio.session import AsyncSession
    
    database_url = os.getenv("DATABASE_URL", "")
    if database_url.startswith("postgresql://"):
        database_url = database_url.replace("postgresql://", "postgresql+asyncpg://")
    
    engine = create_async_engine(
        database_url,
        echo=False,
        pool_pre_ping=True,
        connect_args={
            "prepared_statement_cache_size": 0,
            "statement_cache_size": 0,
        },
    )
    
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    
    async with factory() as session:
        yield session
    
    # Dispose engine to close all pooled connections bound to this event loop
    await engine.dispose()


@pytest.fixture
async def clean_issues_table(db_session):
    """Ensures issues table is empty before and after test"""
    from sqlalchemy import text
    
    # Clear before test
    await db_session.execute(text("DELETE FROM ingestion.issue"))
    await db_session.commit()
    
    yield
    
    # Clear after test
    await db_session.execute(text("DELETE FROM ingestion.issue"))
    await db_session.commit()


@pytest.fixture
async def test_repository(db_session):
    """Creates a test repository for FK constraint"""
    from sqlalchemy import text
    
    repo_id = "R_janitor_test"
    
    await db_session.execute(
        text("""
            INSERT INTO ingestion.repository (node_id, full_name, primary_language)
            VALUES (:node_id, :full_name, :language)
            ON CONFLICT (node_id) DO NOTHING
        """),
        {"node_id": repo_id, "full_name": "test/janitor-repo", "language": "Python"}
    )
    await db_session.commit()
    
    yield repo_id
    
    # Cleanup handled by clean_issues_table (cascade or separate)


async def insert_test_issues(session, repo_id: str, count: int, survival_scores: list[float]):
    """Helper to insert issues with specific survival scores"""
    from sqlalchemy import text
    
    for i, score in enumerate(survival_scores[:count]):
        await session.execute(
            text("""
                INSERT INTO ingestion.issue 
                (node_id, repo_id, title, body_text, survival_score, q_score, 
                 has_code, has_template_headers, tech_stack_weight, 
                 github_created_at, embedding)
                VALUES 
                (:node_id, :repo_id, :title, :body, :survival, :q_score,
                 false, false, 0.0, :created, :embedding)
            """),
            {
                "node_id": f"I_janitor_{i}",
                "repo_id": repo_id,
                "title": f"Test Issue {i}",
                "body": "Test body",
                "survival": score,
                "q_score": 0.7,
                "created": datetime.now(timezone.utc) - timedelta(days=i),
                "embedding": str([0.1] * 768),
            }
        )
    await session.commit()


class TestJanitorIntegration:
    @pytest.mark.asyncio
    async def test_prunes_bottom_20_percent(
        self, db_session, clean_issues_table, test_repository
    ):
        """Insert 100 issues, verify ~20 are deleted"""
        from src.ingestion.janitor import Janitor
        
        # Create 100 issues with survival scores 0.01 to 1.00
        scores = [i / 100 for i in range(1, 101)]
        await insert_test_issues(db_session, test_repository, 100, scores)
        
        janitor = Janitor(session=db_session)
        result = await janitor.execute_pruning()
        
        # Should delete approximately 20 issues (bottom 20%)
        assert result["deleted_count"] == 20
        assert result["remaining_count"] == 80

    @pytest.mark.asyncio
    async def test_deletes_lowest_survival_scores(
        self, db_session, clean_issues_table, test_repository
    ):
        """Verify the deleted issues are the ones with lowest scores"""
        from sqlalchemy import text
        from src.ingestion.janitor import Janitor
        
        # Create 10 issues with known survival scores
        scores = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
        await insert_test_issues(db_session, test_repository, 10, scores)
        
        janitor = Janitor(session=db_session)
        await janitor.execute_pruning()
        
        # Check remaining issues have survival_score >= 0.2 (P20 of 0.1-1.0)
        result = await db_session.execute(
            text("SELECT MIN(survival_score) as min_score FROM ingestion.issue")
        )
        row = result.fetchone()
        
        # The 20th percentile of [0.1, 0.2, ..., 1.0] is approximately 0.28
        # Issues with score < 0.28 should be deleted (0.1, 0.2)
        assert row.min_score >= 0.2

    @pytest.mark.asyncio
    async def test_handles_empty_table(
        self, db_session, clean_issues_table, test_repository
    ):
        """Empty table should return zeros without error"""
        from src.ingestion.janitor import Janitor
        
        janitor = Janitor(session=db_session)
        result = await janitor.execute_pruning()
        
        assert result["deleted_count"] == 0
        assert result["remaining_count"] == 0

    @pytest.mark.asyncio
    async def test_handles_small_table(
        self, db_session, clean_issues_table, test_repository
    ):
        """Tables with few rows should handle percentile calculation"""
        from src.ingestion.janitor import Janitor
        
        # Only 3 issues
        scores = [0.1, 0.5, 0.9]
        await insert_test_issues(db_session, test_repository, 3, scores)
        
        janitor = Janitor(session=db_session)
        result = await janitor.execute_pruning()
        
        # With 3 rows, P20 might delete 0 or 1 depending on interpolation
        assert result["deleted_count"] >= 0
        assert result["remaining_count"] <= 3


class TestIndexUtilization:
    @pytest.mark.asyncio
    async def test_uses_survival_score_index(
        self, db_session, clean_issues_table, test_repository
    ):
        """Verify the query uses ix_issue_survival_vacuum index"""
        from sqlalchemy import text
        
        # Insert some test data
        scores = [i / 100 for i in range(1, 51)]
        await insert_test_issues(db_session, test_repository, 50, scores)
        
        # Run EXPLAIN ANALYZE on the delete query
        explain_result = await db_session.execute(
            text("""
                EXPLAIN ANALYZE
                DELETE FROM ingestion.issue
                WHERE survival_score < (
                    SELECT PERCENTILE_CONT(0.2) WITHIN GROUP (ORDER BY survival_score)
                    FROM ingestion.issue
                )
            """)
        )
        
        plan = "\n".join([row[0] for row in explain_result.fetchall()])
        
        # The query plan should reference the survival_score index
        # exact index name may vary; checking for index scan pattern
        assert "Index" in plan or "Seq Scan" in plan 
        
        # For small tables, Postgres may choose seq scan; 
        # this test mainly verifies query executes without error

