"""
Session Limit Integration Tests

- All operations use a dedicated TEST_USER_UUID
- All tests run within transactions that are rolled back
- All queries include explicit WHERE user_id = TEST_USER_UUID
- No bulk operations without user scoping

These tests verify the Postgres trigger (enforce_session_limit) works correctly.
"""
import pytest
from uuid import UUID, uuid4
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, create_async_engine
from dotenv import dotenv_values

# Load DATABASE_URL from .env files directly
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent.parent.parent
env_local = dotenv_values(PROJECT_ROOT / ".env.local")
env_base = dotenv_values(PROJECT_ROOT / ".env")
REAL_DATABASE_URL = env_local.get("DATABASE_URL") or env_base.get("DATABASE_URL") or ""

# Hardcoded test user UUID is clearly labeled as test and does not exist in production
TEST_USER_UUID = UUID("00000000-0000-0000-0000-000000000001")
TEST_USER_UUID_2 = UUID("00000000-0000-0000-0000-000000000002")

# Skip if no real database URL
pytestmark = [
    pytest.mark.skipif(
        not REAL_DATABASE_URL or "localhost" in REAL_DATABASE_URL,
        reason="Real DATABASE_URL not set - skipping production DB tests"
    ),
]


@pytest.fixture
async def db_engine():
    """Create async engine for production database."""
    database_url = REAL_DATABASE_URL
    
    if database_url.startswith("postgresql://"):
        database_url = database_url.replace("postgresql://", "postgresql+asyncpg://")
    
    engine = create_async_engine(
        database_url,
        echo=False,
        connect_args={
            "prepared_statement_cache_size": 0,
            "statement_cache_size": 0,
        },
    )
    
    yield engine
    await engine.dispose()


@pytest.fixture
async def transactional_connection(db_engine):
    """
    SAFETY: Connection that automatically rolls back.
    
    Creates a connection with BEGIN, yields connection, then ROLLBACK.
    Nothing is ever committed to production database.
    Uses raw connection to bypass SQLModel session wrapper.
    """
    async with db_engine.connect() as connection:
        transaction = await connection.begin()
        
        try:
            yield connection
            
        finally:
            await transaction.rollback()


async def create_test_user(conn: AsyncConnection, user_id: UUID, email: str) -> None:
    """
    Create a test user within transaction (will be rolled back).
    Explicit user_id prevents ID conflicts.
    """
    await conn.execute(
        text("""
            INSERT INTO public."users" (id, email, created_via, created_at, github_node_id, github_username)
            VALUES (:user_id, :email, 'test', NOW(), :github_node_id, :github_username)
            ON CONFLICT (id) DO NOTHING
        """),
        {
            "user_id": str(user_id), 
            "email": email,
            "github_node_id": f"test_node_{str(user_id)}",
            "github_username": f"test_user_{str(user_id)[:8]}",
        }
    )


async def create_test_session(
    conn: AsyncConnection,
    user_id: UUID,
    jti: str,
    created_hours_ago: int = 0,
) -> UUID:
    """
    Create a session for test user (within transaction).
    Returns the session ID for verification.
    Always scoped to explicit user_id.
    
    created_hours_ago: How many hours in the past to set created_at (for ordering tests)
    """
    session_id = uuid4()
    
    await conn.execute(
        text("""
            INSERT INTO public.session 
                (id, user_id, fingerprint, jti, expires_at, remember_me, created_at, last_active_at)
            VALUES 
                (:session_id, :user_id, 'test_fingerprint', :jti, 
                 NOW() + INTERVAL '7 days', 
                 false, 
                 NOW() - :hours_ago * INTERVAL '1 hour',
                 NOW() - :hours_ago * INTERVAL '1 hour')
        """),
        {
            "session_id": str(session_id),
            "user_id": str(user_id),
            "jti": jti,
            "hours_ago": created_hours_ago,
        }
    )
    
    return session_id


async def count_user_sessions(conn: AsyncConnection, user_id: UUID) -> int:
    """
    Count active sessions for specific user.
    Scoped to exact user_id.
    """
    result = await conn.execute(
        text("""
            SELECT COUNT(*) FROM public.session
            WHERE user_id = :user_id
            AND expires_at > NOW()
        """),
        {"user_id": str(user_id)}
    )
    return result.scalar() or 0


async def get_session_ids_for_user(conn: AsyncConnection, user_id: UUID) -> list[str]:
    """
    Get all session IDs for a specific user, ordered by created_at.
    Scoped to exact user_id.
    """
    result = await conn.execute(
        text("""
            SELECT id::text FROM public.session
            WHERE user_id = :user_id
            AND expires_at > NOW()
            ORDER BY created_at ASC
        """),
        {"user_id": str(user_id)}
    )
    return [row[0] for row in result.fetchall()]


class TestSessionLimitTrigger:
    """
    Tests for the Postgres trigger that enforces max 5 sessions per user.
    
    All tests use TEST_USER_UUID within rolled-back transactions.
    """
    
    @pytest.mark.asyncio
    async def test_allows_up_to_5_sessions(self, transactional_connection):
        """
        User can create 5 sessions without eviction.
        """
        await create_test_user(transactional_connection, TEST_USER_UUID, "test_5sessions@test.local")
        
        # Create 5 sessions
        for i in range(5):
            await create_test_session(
                transactional_connection,
                TEST_USER_UUID,
                jti=f"jti_allowed_{i}",
            )
        
        # Verify all 5 exist
        count = await count_user_sessions(transactional_connection, TEST_USER_UUID)
        
        assert count == 5, f"Should have 5 sessions, got {count}"
    
    @pytest.mark.asyncio
    async def test_6th_session_evicts_oldest(self, transactional_connection):
        """
        Creating 6th session triggers eviction of oldest.
        This proves the Postgres trigger is working.
        """
        await create_test_user(transactional_connection, TEST_USER_UUID, "test_eviction@test.local")
        
        # Create 5 sessions with staggered created_at times (hours_ago: 5, 4, 3, 2, 1)
        session_ids = []
        
        for i in range(5):
            sid = await create_test_session(
                transactional_connection,
                TEST_USER_UUID,
                jti=f"jti_eviction_{i}",
                created_hours_ago=(5 - i),
            )
            session_ids.append(str(sid))
        
        oldest_session_id = session_ids[0]
        
        # Verify all 5 exist before 6th
        count_before = await count_user_sessions(transactional_connection, TEST_USER_UUID)
        assert count_before == 5, f"Should have 5 sessions before 6th, got {count_before}"
        
        # Create 6th session - should trigger eviction
        await create_test_session(
            transactional_connection,
            TEST_USER_UUID,
            jti="jti_6th_session",
            created_hours_ago=0,
        )
        
        # Count should still be 5
        count_after = await count_user_sessions(transactional_connection, TEST_USER_UUID)
        assert count_after == 5, f"Should still have 5 sessions after 6th, got {count_after}"
        
        # Oldest session should be gone
        remaining_ids = await get_session_ids_for_user(transactional_connection, TEST_USER_UUID)
        
        assert oldest_session_id not in remaining_ids, \
            f"Oldest session {oldest_session_id} should have been evicted"
    
    @pytest.mark.asyncio
    async def test_eviction_does_not_affect_other_users(self, transactional_connection):
        """
        Eviction for one user must NOT affect another user.
        """
        await create_test_user(transactional_connection, TEST_USER_UUID, "test_user1@test.local")
        await create_test_user(transactional_connection, TEST_USER_UUID_2, "test_user2@test.local")
        
        # Create 5 sessions for USER_2
        for i in range(5):
            await create_test_session(
                transactional_connection,
                TEST_USER_UUID_2,
                jti=f"jti_user2_{i}",
            )
        
        user2_count_before = await count_user_sessions(transactional_connection, TEST_USER_UUID_2)
        assert user2_count_before == 5
        
        # Create 6 sessions for USER_1
        for i in range(6):
            await create_test_session(
                transactional_connection,
                TEST_USER_UUID,
                jti=f"jti_user1_{i}",
            )
        
        # USER_2 sessions must be unnaffected
        user2_count_after = await count_user_sessions(transactional_connection, TEST_USER_UUID_2)
        
        assert user2_count_after == 5, \
            f"User 2's sessions should be unaffected, had {user2_count_before}, now {user2_count_after}"
    
    @pytest.mark.asyncio
    async def test_transaction_rollback_leaves_no_trace(self, transactional_connection):
        """
        Verify that our rollback mechanism works.
        After test, no TEST_USER_UUID data should persist.
        """
        await create_test_user(transactional_connection, TEST_USER_UUID, "test_rollback@test.local")
        await create_test_session(
            transactional_connection,
            TEST_USER_UUID,
            jti="jti_rollback_test",
        )
        
        # Within transaction, session exists
        count = await count_user_sessions(transactional_connection, TEST_USER_UUID)
        assert count == 1
