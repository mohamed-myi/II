"""alloydb ingestion optimizations

Revision ID: a1b2c3d4e5f6
Revises: e3f4a5b6c7d8
Create Date: 2025-12-31

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel
import pgvector.sqlalchemy
from sqlalchemy.dialects import postgresql


revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, Sequence[str], None] = 'e3f4a5b6c7d8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """
    Rebuild ingestion tables for AlloyDB/GCP optimizations:
    - Vector dimension 256 → 768 (Nomic embed-text-v1.5)
    - Add Q-score/survival-score columns for Columnar Engine
    - Add composite index for Janitor pruning queries
    - Convert labels from JSONB to ARRAY for faster GIN filtering
    - Add Scout indexes on stargazer_count and last_scraped_at
    """
    
    # Drop existing ingestion tables (empty DB; no data loss)
    op.drop_table('issue', schema='ingestion')
    op.drop_table('repository', schema='ingestion')
    
    # Recreate repository with AlloyDB optimizations
    op.create_table(
        'repository',
        sa.Column('node_id', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column('full_name', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column('primary_language', sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column('issue_velocity_week', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('stargazer_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('languages', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('topics', postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column('last_scraped_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('node_id'),
        sa.UniqueConstraint('full_name', name='uq_repository_full_name'),
        schema='ingestion'
    )
    
    # Repository indexes for Scout queries
    op.create_index(
        'ix_ingestion_repository_full_name',
        'repository',
        ['full_name'],
        schema='ingestion'
    )
    op.create_index(
        'ix_ingestion_repository_primary_language',
        'repository',
        ['primary_language'],
        schema='ingestion'
    )
    op.create_index(
        'ix_ingestion_repository_stargazer_count',
        'repository',
        ['stargazer_count'],
        schema='ingestion'
    )
    op.create_index(
        'ix_ingestion_repository_last_scraped_at',
        'repository',
        ['last_scraped_at'],
        schema='ingestion'
    )
    
    # Recreate issue with AlloyDB optimizations (768-dim vector, score columns)
    op.create_table(
        'issue',
        sa.Column('node_id', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column('repo_id', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        # Q-Score components
        sa.Column('has_code', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('has_template_headers', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('tech_stack_weight', postgresql.REAL(), nullable=False, server_default='0.0'),
        # Calculated scores
        sa.Column('q_score', postgresql.REAL(), nullable=False, server_default='0.0'),
        sa.Column('survival_score', postgresql.REAL(), nullable=False, server_default='0.0'),
        # Content
        sa.Column('title', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column('body_text', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column('labels', postgresql.ARRAY(sa.String()), nullable=True),
        # 768-dim Nomic embeddings
        sa.Column('embedding', pgvector.sqlalchemy.vector.VECTOR(dim=768), nullable=True),
        # Timestamps
        sa.Column('github_created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('ingested_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(['repo_id'], ['ingestion.repository.node_id']),
        sa.PrimaryKeyConstraint('node_id'),
        schema='ingestion'
    )
    
    # Issue indexes
    op.create_index(
        'ix_ingestion_issue_repo_id',
        'issue',
        ['repo_id'],
        schema='ingestion'
    )
    op.create_index(
        'ix_ingestion_issue_q_score',
        'issue',
        ['q_score'],
        schema='ingestion'
    )
    op.create_index(
        'ix_ingestion_issue_survival_score',
        'issue',
        ['survival_score'],
        schema='ingestion'
    )
    op.create_index(
        'ix_ingestion_issue_ingested_at',
        'issue',
        ['ingested_at'],
        schema='ingestion'
    )
    op.create_index(
        'ix_ingestion_issue_github_created_at',
        'issue',
        ['github_created_at'],
        schema='ingestion'
    )
    
    # Composite index for Janitor's bottom-20% pruning
    op.create_index(
        'ix_issue_survival_vacuum',
        'issue',
        ['survival_score', 'ingested_at'],
        schema='ingestion'
    )


def downgrade() -> None:
    """Revert to original 256-dim schema."""
    
    # Drop AlloyDB-optimized tables
    op.drop_table('issue', schema='ingestion')
    op.drop_table('repository', schema='ingestion')
    
    # Recreate original repository
    op.create_table(
        'repository',
        sa.Column('node_id', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column('full_name', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column('primary_language', sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column('languages', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('topics', postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column('stargazer_count', sa.Integer(), nullable=False),
        sa.Column('quality_score', sa.Float(), nullable=False),
        sa.Column('last_scraped_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('node_id'),
        schema='ingestion'
    )
    op.create_index(
        'ix_ingestion_repository_full_name',
        'repository',
        ['full_name'],
        schema='ingestion'
    )
    op.create_index(
        'ix_ingestion_repository_primary_language',
        'repository',
        ['primary_language'],
        schema='ingestion'
    )
    
    # Recreate original issue (256-dim)
    op.create_table(
        'issue',
        sa.Column('node_id', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column('repo_id', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column('title', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column('body_text', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column('author_association', sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column('labels', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('comment_count', sa.Integer(), nullable=False),
        sa.Column('heat_score', sa.Float(), nullable=False),
        sa.Column('embedding', pgvector.sqlalchemy.vector.VECTOR(dim=256), nullable=True),
        sa.Column('github_created_at', sa.DateTime(), nullable=False),
        sa.Column('ingested_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['repo_id'], ['ingestion.repository.node_id']),
        sa.PrimaryKeyConstraint('node_id'),
        schema='ingestion'
    )
    op.create_index(
        'ix_ingestion_issue_heat_score',
        'issue',
        ['heat_score'],
        schema='ingestion'
    )
    op.create_index(
        'ix_ingestion_issue_ingested_at',
        'issue',
        ['ingested_at'],
        schema='ingestion'
    )
