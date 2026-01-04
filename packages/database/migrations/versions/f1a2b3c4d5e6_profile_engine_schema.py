"""profile engine schema: linked_accounts and user_profiles extension

Revision ID: f1a2b3c4d5e6
Revises: e3f4a5b6c7d8
Create Date: 2026-01-04

Adds support for the Profile Engine feature:
1. Renames history_vector to resume_vector and raw_intent_text to intent_text
2. Adds github_vector and combined_vector fields
3. Adds intent, resume, and GitHub metadata fields
4. Adds onboarding state fields
5. Creates linked_accounts table for OAuth token storage
6. Moves HNSW index from intent_vector to combined_vector
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import ARRAY, JSONB


revision: str = 'f1a2b3c4d5e6'
down_revision: Union[str, Sequence[str], None] = 'e3f4a5b6c7d8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Rename existing columns in user_profiles
    op.alter_column(
        'userprofile',
        'history_vector',
        new_column_name='resume_vector',
        schema='public'
    )
    op.alter_column(
        'userprofile',
        'raw_intent_text',
        new_column_name='intent_text',
        schema='public'
    )
    
    # 2. Add new vector columns (768-dim for Nomic embeddings)
    op.execute("""
        ALTER TABLE public.userprofile 
        ADD COLUMN github_vector vector(768),
        ADD COLUMN combined_vector vector(768)
    """)
    
    # 3. Add intent fields
    op.add_column(
        'userprofile',
        sa.Column('intent_stack_areas', ARRAY(sa.String()), nullable=True),
        schema='public'
    )
    op.add_column(
        'userprofile',
        sa.Column('intent_experience', sa.String(20), nullable=True),
        schema='public'
    )
    
    # 4. Add resume fields
    op.add_column(
        'userprofile',
        sa.Column('resume_skills', ARRAY(sa.String()), nullable=True),
        schema='public'
    )
    op.add_column(
        'userprofile',
        sa.Column('resume_job_titles', ARRAY(sa.String()), nullable=True),
        schema='public'
    )
    op.add_column(
        'userprofile',
        sa.Column('resume_raw_entities', JSONB, nullable=True),
        schema='public'
    )
    op.add_column(
        'userprofile',
        sa.Column('resume_uploaded_at', sa.DateTime(timezone=True), nullable=True),
        schema='public'
    )
    
    # 5. Add GitHub fields
    op.add_column(
        'userprofile',
        sa.Column('github_username', sa.String(255), nullable=True),
        schema='public'
    )
    op.add_column(
        'userprofile',
        sa.Column('github_languages', ARRAY(sa.String()), nullable=True),
        schema='public'
    )
    op.add_column(
        'userprofile',
        sa.Column('github_topics', ARRAY(sa.String()), nullable=True),
        schema='public'
    )
    op.add_column(
        'userprofile',
        sa.Column('github_data', JSONB, nullable=True),
        schema='public'
    )
    op.add_column(
        'userprofile',
        sa.Column('github_fetched_at', sa.DateTime(timezone=True), nullable=True),
        schema='public'
    )
    
    # 6. Add state fields
    op.add_column(
        'userprofile',
        sa.Column(
            'onboarding_status',
            sa.String(20),
            nullable=False,
            server_default='not_started'
        ),
        schema='public'
    )
    op.add_column(
        'userprofile',
        sa.Column('onboarding_completed_at', sa.DateTime(timezone=True), nullable=True),
        schema='public'
    )
    
    # 7. Create linked_accounts table for OAuth token storage
    op.create_table(
        'linked_accounts',
        sa.Column('id', sa.dialects.postgresql.UUID(), nullable=False, server_default=sa.text('gen_random_uuid()')),
        sa.Column('user_id', sa.dialects.postgresql.UUID(), nullable=False),
        sa.Column('provider', sa.String(50), nullable=False),
        sa.Column('provider_user_id', sa.String(255), nullable=False),
        sa.Column('access_token', sa.Text(), nullable=False),
        sa.Column('refresh_token', sa.Text(), nullable=True),
        sa.Column('scopes', ARRAY(sa.String()), nullable=False, server_default='{}'),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['user_id'], ['public.users.id'], ondelete='CASCADE'),
        sa.UniqueConstraint('user_id', 'provider', name='uq_linked_accounts_user_provider'),
        schema='public'
    )
    
    op.create_index(
        'ix_linked_accounts_user_id',
        'linked_accounts',
        ['user_id'],
        schema='public'
    )
    op.create_index(
        'ix_linked_accounts_provider',
        'linked_accounts',
        ['provider'],
        schema='public'
    )
    
    # 8. Update HNSW index: drop from intent_vector, create on combined_vector
    # First check if intent_vector index exists and drop it
    op.execute("""
        DROP INDEX IF EXISTS public.ix_userprofile_intent_vector
    """)
    
    # Create HNSW index on combined_vector for recommendation queries
    op.execute("""
        CREATE INDEX ix_userprofile_combined_vector 
        ON public.userprofile 
        USING hnsw (combined_vector vector_cosine_ops)
        WITH (m = 16, ef_construction = 64)
    """)


def downgrade() -> None:
    # Drop HNSW index on combined_vector
    op.execute("""
        DROP INDEX IF EXISTS public.ix_userprofile_combined_vector
    """)
    
    # Recreate HNSW index on intent_vector
    op.execute("""
        CREATE INDEX ix_userprofile_intent_vector 
        ON public.userprofile 
        USING hnsw (intent_vector vector_cosine_ops)
        WITH (m = 16, ef_construction = 64)
    """)
    
    # Drop linked_accounts table
    op.drop_index('ix_linked_accounts_provider', table_name='linked_accounts', schema='public')
    op.drop_index('ix_linked_accounts_user_id', table_name='linked_accounts', schema='public')
    op.drop_table('linked_accounts', schema='public')
    
    # Drop state fields
    op.drop_column('userprofile', 'onboarding_completed_at', schema='public')
    op.drop_column('userprofile', 'onboarding_status', schema='public')
    
    # Drop GitHub fields
    op.drop_column('userprofile', 'github_fetched_at', schema='public')
    op.drop_column('userprofile', 'github_data', schema='public')
    op.drop_column('userprofile', 'github_topics', schema='public')
    op.drop_column('userprofile', 'github_languages', schema='public')
    op.drop_column('userprofile', 'github_username', schema='public')
    
    # Drop resume fields
    op.drop_column('userprofile', 'resume_uploaded_at', schema='public')
    op.drop_column('userprofile', 'resume_raw_entities', schema='public')
    op.drop_column('userprofile', 'resume_job_titles', schema='public')
    op.drop_column('userprofile', 'resume_skills', schema='public')
    
    # Drop intent fields
    op.drop_column('userprofile', 'intent_experience', schema='public')
    op.drop_column('userprofile', 'intent_stack_areas', schema='public')
    
    # Drop new vector columns
    op.drop_column('userprofile', 'combined_vector', schema='public')
    op.drop_column('userprofile', 'github_vector', schema='public')
    
    # Rename columns back
    op.alter_column(
        'userprofile',
        'intent_text',
        new_column_name='raw_intent_text',
        schema='public'
    )
    op.alter_column(
        'userprofile',
        'resume_vector',
        new_column_name='history_vector',
        schema='public'
    )

