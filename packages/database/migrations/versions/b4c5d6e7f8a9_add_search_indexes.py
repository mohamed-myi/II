"""add search indexes for hybrid retrieval

Revision ID: b4c5d6e7f8a9
Revises: a1b2c3d4e5f6
Create Date: 2026-01-02

Adds infrastructure for SQL-based hybrid search with RRF:
1. Generated tsvector column for BM25 full-text search
2. GIN index on search_vector for fast text matching
3. HNSW vector index on embedding (ScaNN on AlloyDB; HNSW on pgvector)
4. Analytics schema and search_interactions table for golden dataset
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = 'b4c5d6e7f8a9'
down_revision: Union[str, Sequence[str], None] = 'a1b2c3d4e5f6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """
    Add search infrastructure to ingestion.issue table:
    1. search_vector: Generated tsvector column from title + body_text
    2. GIN index on search_vector for BM25 queries
    3. HNSW index on embedding for vector similarity (pgvector compatible)
    4. analytics.search_interactions table for interaction logging
    """
    
    # Add generated tsvector column for full-text search
    # Using STORED so the vector is computed once on INSERT/UPDATE
    op.execute("""
        ALTER TABLE ingestion.issue 
        ADD COLUMN search_vector tsvector 
        GENERATED ALWAYS AS (
            to_tsvector('english', COALESCE(title, '') || ' ' || COALESCE(body_text, ''))
        ) STORED
    """)
    
    # GIN index for fast tsvector matching with @@ operator
    op.execute("""
        CREATE INDEX ix_issue_search_vector 
        ON ingestion.issue 
        USING GIN (search_vector)
    """)
    
    # HNSW vector index for approximate nearest neighbor search
    # Uses cosine distance operator (<=>); compatible with pgvector and AlloyDB
    # m=16, ef_construction=64 are reasonable defaults for 768-dim vectors
    op.execute("""
        CREATE INDEX ix_issue_embedding_hnsw
        ON ingestion.issue 
        USING hnsw (embedding vector_cosine_ops)
        WITH (m = 16, ef_construction = 64)
    """)
    
    # Create analytics schema for search interaction logging
    op.execute("CREATE SCHEMA IF NOT EXISTS analytics")
    
    # Create search_interactions table for golden dataset collection
    op.create_table(
        'search_interactions',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False, server_default=sa.text('gen_random_uuid()')),
        sa.Column('search_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('query_text', sa.Text(), nullable=False),
        sa.Column('filters_json', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('result_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('selected_node_id', sa.String(), nullable=True),
        sa.Column('position', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        schema='analytics'
    )
    
    # Index for querying interactions by search_id (for validation)
    op.create_index(
        'ix_search_interactions_search_id',
        'search_interactions',
        ['search_id'],
        schema='analytics'
    )
    
    # Index for analyzing user behavior patterns
    op.create_index(
        'ix_search_interactions_user_id',
        'search_interactions',
        ['user_id'],
        schema='analytics'
    )
    
    # Index for time-based analytics queries
    op.create_index(
        'ix_search_interactions_created_at',
        'search_interactions',
        ['created_at'],
        schema='analytics'
    )


def downgrade() -> None:
    """Remove search infrastructure."""
    
    # Drop analytics table and indexes
    op.drop_index('ix_search_interactions_created_at', table_name='search_interactions', schema='analytics')
    op.drop_index('ix_search_interactions_user_id', table_name='search_interactions', schema='analytics')
    op.drop_index('ix_search_interactions_search_id', table_name='search_interactions', schema='analytics')
    op.drop_table('search_interactions', schema='analytics')
    
    # Drop analytics schema (only if empty)
    op.execute("DROP SCHEMA IF EXISTS analytics")
    
    # Drop vector index
    op.execute("DROP INDEX IF EXISTS ingestion.ix_issue_embedding_hnsw")
    
    # Drop GIN index
    op.execute("DROP INDEX IF EXISTS ingestion.ix_issue_search_vector")
    
    # Drop generated column
    op.execute("ALTER TABLE ingestion.issue DROP COLUMN IF EXISTS search_vector")

