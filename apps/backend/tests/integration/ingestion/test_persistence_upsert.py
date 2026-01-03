"""Integration tests for streaming persistence UPSERT conflict resolution against PostgreSQL with pgvector"""

import os
import pytest
from datetime import datetime, timezone, timedelta

try:
    from testcontainers.postgres import PostgresContainer
    TESTCONTAINERS_AVAILABLE = True
except ImportError:
    TESTCONTAINERS_AVAILABLE = False

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel.ext.asyncio.session import AsyncSession

from src.ingestion.embeddings import EmbeddedIssue
from src.ingestion.gatherer import IssueData
from src.ingestion.persistence import StreamingPersistence
from src.ingestion.quality_gate import QScoreComponents
from src.ingestion.scout import RepositoryData
from src.ingestion.survival_score import calculate_survival_score, days_since


# Skip entire module if testcontainers not installed
pytestmark = pytest.mark.skipif(
    not TESTCONTAINERS_AVAILABLE,
    reason="testcontainers[postgres] not installed; requires Docker"
)


# Schema setup SQL from migration a1b2c3d4e5f6
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

CREATE INDEX ix_ingestion_repository_full_name ON ingestion.repository(full_name);
CREATE INDEX ix_ingestion_repository_primary_language ON ingestion.repository(primary_language);
CREATE INDEX ix_ingestion_repository_stargazer_count ON ingestion.repository(stargazer_count);
CREATE INDEX ix_ingestion_repository_last_scraped_at ON ingestion.repository(last_scraped_at);

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
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX ix_ingestion_issue_repo_id ON ingestion.issue(repo_id);
CREATE INDEX ix_ingestion_issue_q_score ON ingestion.issue(q_score);
CREATE INDEX ix_ingestion_issue_survival_score ON ingestion.issue(survival_score);
CREATE INDEX ix_ingestion_issue_ingested_at ON ingestion.issue(ingested_at);
CREATE INDEX ix_issue_survival_vacuum ON ingestion.issue(survival_score, ingested_at);
"""


@pytest.fixture(scope="module")
def postgres_container():
    """Ephemeral PostgreSQL 16 with pgvector via testcontainers"""
    # Use pgvector image which has the vector extension pre-installed
    with PostgresContainer(
        image="pgvector/pgvector:pg16",
        username="test",
        password="test",
        dbname="testdb",
    ) as pg:
        yield pg


@pytest.fixture(scope="module")
def sync_connection_url(postgres_container):
    """Synchronous connection URL for schema setup"""
    url = postgres_container.get_connection_url()
    # Strip SQLAlchemy dialect prefix for plain PostgreSQL URL
    return url.replace("postgresql+psycopg2://", "postgresql://")


@pytest.fixture(scope="module")
def async_connection_url(postgres_container):
    """Async connection URL for test sessions"""
    url = postgres_container.get_connection_url()
    # Strip SQLAlchemy dialect and convert to asyncpg
    url = url.replace("postgresql+psycopg2://", "postgresql://")
    return url.replace("postgresql://", "postgresql+asyncpg://")


@pytest.fixture(scope="module")
def setup_schema(sync_connection_url):
    """Create schema and tables once per module using sync connection"""
    import psycopg2
    
    # Parse URL for psycopg2
    # Format: postgresql://user:password@host:port/dbname
    parts = sync_connection_url.replace("postgresql://", "").split("@")
    user_pass = parts[0].split(":")
    host_port_db = parts[1].split("/")
    host_port = host_port_db[0].split(":")
    
    conn = psycopg2.connect(
        user=user_pass[0],
        password=user_pass[1],
        host=host_port[0],
        port=host_port[1],
        dbname=host_port_db[1],
    )
    conn.autocommit = True
    
    with conn.cursor() as cur:
        cur.execute(SETUP_SQL)
    
    conn.close()
    return True


@pytest.fixture
async def db_session(async_connection_url, setup_schema):
    """Yield async session, clean tables after each test"""
    engine = create_async_engine(
        async_connection_url,
        echo=False,
        pool_pre_ping=True,
    )
    
    async_session_factory = sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )
    
    async with async_session_factory() as session:
        yield session
        
        # Cleanup: delete all rows after test
        await session.execute(text("DELETE FROM ingestion.issue"))
        await session.execute(text("DELETE FROM ingestion.repository"))
        await session.commit()
    
    await engine.dispose()


@pytest.fixture
def sample_q_components():
    return QScoreComponents(
        has_code=True,
        has_headers=True,
        tech_weight=0.5,
        is_junk=False,
    )


@pytest.fixture
def make_repository():
    def _make(
        node_id: str = "R_123",
        full_name: str = "owner/repo",
        primary_language: str = "Python",
        stargazer_count: int = 1000,
        issue_count_open: int = 50,
    ):
        return RepositoryData(
            node_id=node_id,
            full_name=full_name,
            primary_language=primary_language,
            stargazer_count=stargazer_count,
            issue_count_open=issue_count_open,
            topics=["python", "api"],
        )
    return _make


@pytest.fixture
def make_embedded_issue(sample_q_components):
    def _make(
        node_id: str = "I_123",
        repo_id: str = "R_123",
        q_score: float = 0.75,
        title: str = "Bug report",
        body: str = "Description of the bug",
        created_days_ago: int = 1,
    ):
        issue = IssueData(
            node_id=node_id,
            repo_id=repo_id,
            title=title,
            body_text=body,
            labels=["bug"],
            github_created_at=datetime.now(timezone.utc) - timedelta(days=created_days_ago),
            q_score=q_score,
            q_components=sample_q_components,
        )
        # 768-dim embedding
        return EmbeddedIssue(
            issue=issue,
            embedding=[0.1] * 768,
        )
    return _make


class TestRepositoryUpsert:
    """Test UPSERT conflict resolution for repositories"""

    @pytest.mark.asyncio
    async def test_insert_new_repository(self, db_session, make_repository):
        """Clean insert should create new row"""
        persistence = StreamingPersistence(db_session)
        repo = make_repository(node_id="R_new", full_name="test/new-repo")
        
        count = await persistence.upsert_repositories([repo])
        
        assert count == 1
        
        # Verify in database
        result = await db_session.execute(
            text("SELECT full_name FROM ingestion.repository WHERE node_id = :id"),
            {"id": "R_new"},
        )
        row = result.fetchone()
        assert row is not None
        assert row[0] == "test/new-repo"

    @pytest.mark.asyncio
    async def test_upsert_updates_on_conflict(self, db_session, make_repository):
        """Re-inserting same node_id should UPDATE, not duplicate"""
        persistence = StreamingPersistence(db_session)
        
        # First insert
        repo_v1 = make_repository(
            node_id="R_conflict",
            full_name="test/conflict-repo",
            stargazer_count=100,
        )
        await persistence.upsert_repositories([repo_v1])
        
        # Second insert with updated values
        repo_v2 = make_repository(
            node_id="R_conflict",
            full_name="test/conflict-repo",
            stargazer_count=9999,
        )
        count = await persistence.upsert_repositories([repo_v2])
        
        assert count == 1
        
        # Verify single row with updated value
        result = await db_session.execute(
            text("SELECT stargazer_count FROM ingestion.repository WHERE node_id = :id"),
            {"id": "R_conflict"},
        )
        rows = result.fetchall()
        assert len(rows) == 1
        assert rows[0][0] == 9999

    @pytest.mark.asyncio
    async def test_upsert_multiple_repositories(self, db_session, make_repository):
        """Batch upsert should handle multiple repos"""
        persistence = StreamingPersistence(db_session)
        repos = [
            make_repository(node_id=f"R_batch_{i}", full_name=f"batch/repo{i}")
            for i in range(5)
        ]
        
        count = await persistence.upsert_repositories(repos)
        
        assert count == 5
        
        result = await db_session.execute(
            text("SELECT COUNT(*) FROM ingestion.repository WHERE node_id LIKE 'R_batch_%'")
        )
        assert result.scalar() == 5


class TestIssueUpsert:
    """Test UPSERT conflict resolution for issues"""

    @pytest.mark.asyncio
    async def test_insert_new_issue(self, db_session, make_repository, make_embedded_issue):
        """Clean insert should create new issue row"""
        persistence = StreamingPersistence(db_session)
        
        # insert repository first (FK constraint)
        repo = make_repository(node_id="R_for_issue")
        await persistence.upsert_repositories([repo])
        
        embedded = make_embedded_issue(node_id="I_new", repo_id="R_for_issue")
        
        async def single_issue():
            yield embedded
        
        count = await persistence.persist_stream(single_issue())
        
        assert count == 1
        
        result = await db_session.execute(
            text("SELECT title, q_score FROM ingestion.issue WHERE node_id = :id"),
            {"id": "I_new"},
        )
        row = result.fetchone()
        assert row is not None
        assert row[0] == "Bug report"
        assert abs(row[1] - 0.75) < 0.01

    @pytest.mark.asyncio
    async def test_issue_upsert_updates_on_conflict(self, db_session, make_repository, make_embedded_issue):
        """Re-inserting same issue node_id should UPDATE"""
        persistence = StreamingPersistence(db_session)
        
        repo = make_repository(node_id="R_upsert")
        await persistence.upsert_repositories([repo])
        
        # First insert
        issue_v1 = make_embedded_issue(
            node_id="I_upsert",
            repo_id="R_upsert",
            title="Original title",
            q_score=0.6,
        )
        
        async def stream_v1():
            yield issue_v1
        
        await persistence.persist_stream(stream_v1())
        
        # Second insert with updated values
        issue_v2 = make_embedded_issue(
            node_id="I_upsert",
            repo_id="R_upsert",
            title="Updated title",
            q_score=0.9,
        )
        
        async def stream_v2():
            yield issue_v2
        
        count = await persistence.persist_stream(stream_v2())
        
        assert count == 1
        
        # Verify single row with updated values
        result = await db_session.execute(
            text("SELECT title, q_score FROM ingestion.issue WHERE node_id = :id"),
            {"id": "I_upsert"},
        )
        rows = result.fetchall()
        assert len(rows) == 1
        assert rows[0][0] == "Updated title"
        assert abs(rows[0][1] - 0.9) < 0.01

    @pytest.mark.asyncio
    async def test_survival_score_calculated_on_insert(self, db_session, make_repository, make_embedded_issue):
        """survival_score should be computed and stored"""
        persistence = StreamingPersistence(db_session)
        
        repo = make_repository(node_id="R_survival")
        await persistence.upsert_repositories([repo])
        
        # Issue with known q_score and age
        embedded = make_embedded_issue(
            node_id="I_survival",
            repo_id="R_survival",
            q_score=0.8,
            created_days_ago=5,
        )
        
        async def single_issue():
            yield embedded
        
        await persistence.persist_stream(single_issue())
        
        result = await db_session.execute(
            text("SELECT survival_score FROM ingestion.issue WHERE node_id = :id"),
            {"id": "I_survival"},
        )
        stored_score = result.scalar()
        
        # Verify score is positive and reasonable
        assert stored_score is not None
        assert stored_score > 0
        
        # Calculate expected score for comparison
        days_old = days_since(embedded.issue.github_created_at)
        expected_score = calculate_survival_score(embedded.issue.q_score, days_old)
        
        # Allow small tolerance due to timing
        assert abs(stored_score - expected_score) < 0.1


class TestBatchStreamPersistence:
    """Test batch persistence of 100 issues"""

    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_stream_100_issues(self, db_session, make_repository, make_embedded_issue):
        """Persist 100 issues via stream and verify all stored"""
        persistence = StreamingPersistence(db_session)
        issue_count = 100
        
        # Setup: create repository
        repo = make_repository(node_id="R_batch_100")
        await persistence.upsert_repositories([repo])
        
        async def issue_stream():
            for i in range(issue_count):
                yield make_embedded_issue(
                    node_id=f"I_batch_{i}",
                    repo_id="R_batch_100",
                    q_score=0.6 + (i % 10) * 0.04,  # Vary scores 0.6-0.96
                )
        
        count = await persistence.persist_stream(issue_stream())
        
        assert count == issue_count
        
        # Verify all in database
        result = await db_session.execute(
            text("SELECT COUNT(*) FROM ingestion.issue WHERE node_id LIKE 'I_batch_%'")
        )
        assert result.scalar() == issue_count

    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_batch_survival_scores_vary_correctly(self, db_session, make_repository, make_embedded_issue):
        """Issues with higher q_scores should have higher survival_scores (same age)"""
        persistence = StreamingPersistence(db_session)
        
        repo = make_repository(node_id="R_survival_batch")
        await persistence.upsert_repositories([repo])
        
        # Create issues with varying q_scores, same age
        async def issue_stream():
            for i, q in enumerate([0.5, 0.7, 0.9]):
                yield make_embedded_issue(
                    node_id=f"I_survival_var_{i}",
                    repo_id="R_survival_batch",
                    q_score=q,
                    created_days_ago=1,
                )
        
        await persistence.persist_stream(issue_stream())
        
        result = await db_session.execute(
            text("""
                SELECT node_id, q_score, survival_score 
                FROM ingestion.issue 
                WHERE node_id LIKE 'I_survival_var_%'
                ORDER BY q_score
            """)
        )
        rows = result.fetchall()
        
        # Verify survival scores increase with q_score
        prev_survival = 0
        for row in rows:
            assert row[2] > prev_survival, (
                f"survival_score should increase with q_score: {row}"
            )
            prev_survival = row[2]


class TestQScoreComponents:
    """Test Q-score component storage"""

    @pytest.mark.asyncio
    async def test_q_components_stored(self, db_session, make_repository, make_embedded_issue):
        """has_code, has_template_headers, tech_stack_weight should be stored"""
        persistence = StreamingPersistence(db_session)
        
        repo = make_repository(node_id="R_components")
        await persistence.upsert_repositories([repo])
        
        embedded = make_embedded_issue(node_id="I_components", repo_id="R_components")
        
        async def single_issue():
            yield embedded
        
        await persistence.persist_stream(single_issue())
        
        result = await db_session.execute(
            text("""
                SELECT has_code, has_template_headers, tech_stack_weight
                FROM ingestion.issue WHERE node_id = :id
            """),
            {"id": "I_components"},
        )
        row = result.fetchone()
        
        assert row is not None
        assert row[0] is True  # has_code
        assert row[1] is True  # has_template_headers
        assert abs(row[2] - 0.5) < 0.01  # tech_stack_weight


class TestVectorEmbedding:
    """Test 768-dim vector storage"""

    @pytest.mark.asyncio
    async def test_embedding_stored_correctly(self, db_session, make_repository, make_embedded_issue):
        """768-dim embedding should be stored in vector column"""
        persistence = StreamingPersistence(db_session)
        
        repo = make_repository(node_id="R_vector")
        await persistence.upsert_repositories([repo])
        
        embedded = make_embedded_issue(node_id="I_vector", repo_id="R_vector")
        
        async def single_issue():
            yield embedded
        
        await persistence.persist_stream(single_issue())
        
        # Query embedding dimension
        result = await db_session.execute(
            text("""
                SELECT vector_dims(embedding)
                FROM ingestion.issue WHERE node_id = :id
            """),
            {"id": "I_vector"},
        )
        dim = result.scalar()
        
        assert dim == 768

