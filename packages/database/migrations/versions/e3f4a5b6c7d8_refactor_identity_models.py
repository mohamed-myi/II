"""refactor identity models for database native constraints

Revision ID: e3f4a5b6c7d8
Revises: d2e3f4a5b6c7
Create Date: 2025-12-29

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'e3f4a5b6c7d8'
down_revision: Union[str, Sequence[str], None] = 'd2e3f4a5b6c7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """
    1. Rename user table to users (reserved keyword fix)
    2. Add unique constraint on (email, created_via) for race condition prevention
    3. Convert ip_address from VARCHAR to INET type
    4. Add timezone to timestamp columns
    """
    
    # 1. Rename user table to users
    op.rename_table('user', 'users', schema='public')
    
    # 1b. Re-add fingerprint column (removed in d2e3f4a5b6c7 but needed for risk assessment)
    op.add_column(
        'session',
        sa.Column('fingerprint', sa.String(), nullable=False, server_default=''),
        schema='public'
    )
    
    # Update session limit trigger to reference new table name
    op.execute("""
        CREATE OR REPLACE FUNCTION enforce_session_limit()
        RETURNS TRIGGER AS $$
        DECLARE
            session_count INTEGER;
            max_sessions INTEGER := 5;
        BEGIN
            SELECT COUNT(*) INTO session_count
            FROM public.session
            WHERE user_id = NEW.user_id 
              AND expires_at > NOW();
            
            IF session_count >= max_sessions THEN
                DELETE FROM public.session
                WHERE id = (
                    SELECT id 
                    FROM public.session
                    WHERE user_id = NEW.user_id 
                      AND expires_at > NOW()
                    ORDER BY created_at ASC
                    LIMIT 1
                );
            END IF;
            
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """)
    
    # 2. Add unique constraint on (email, created_via)
    op.create_unique_constraint(
        'uq_users_email_provider',
        'users',
        ['email', 'created_via'],
        schema='public'
    )
    
    # 3. Convert ip_address from VARCHAR to INET
    op.execute("""
        ALTER TABLE public.session 
        ALTER COLUMN ip_address TYPE INET 
        USING ip_address::inet
    """)
    
    # 4. Add timezone to timestamp columns
    # users.created_at
    op.execute("""
        ALTER TABLE public.users 
        ALTER COLUMN created_at TYPE TIMESTAMP WITH TIME ZONE 
        USING created_at AT TIME ZONE 'UTC'
    """)
    
    # session.created_at and last_active_at
    op.execute("""
        ALTER TABLE public.session 
        ALTER COLUMN created_at TYPE TIMESTAMP WITH TIME ZONE 
        USING created_at AT TIME ZONE 'UTC'
    """)
    op.execute("""
        ALTER TABLE public.session 
        ALTER COLUMN last_active_at TYPE TIMESTAMP WITH TIME ZONE 
        USING last_active_at AT TIME ZONE 'UTC'
    """)
    op.execute("""
        ALTER TABLE public.session 
        ALTER COLUMN deviation_logged_at TYPE TIMESTAMP WITH TIME ZONE 
        USING deviation_logged_at AT TIME ZONE 'UTC'
    """)
    
    # userprofile.updated_at
    op.execute("""
        ALTER TABLE public.userprofile 
        ALTER COLUMN updated_at TYPE TIMESTAMP WITH TIME ZONE 
        USING updated_at AT TIME ZONE 'UTC'
    """)
    
    # bookmarkedissue.created_at
    op.execute("""
        ALTER TABLE public.bookmarkedissue 
        ALTER COLUMN created_at TYPE TIMESTAMP WITH TIME ZONE 
        USING created_at AT TIME ZONE 'UTC'
    """)
    
    # personalnote.updated_at
    op.execute("""
        ALTER TABLE public.personalnote 
        ALTER COLUMN updated_at TYPE TIMESTAMP WITH TIME ZONE 
        USING updated_at AT TIME ZONE 'UTC'
    """)
    
    # ingestion.issue.ingested_at
    op.execute("""
        ALTER TABLE ingestion.issue 
        ALTER COLUMN ingested_at TYPE TIMESTAMP WITH TIME ZONE 
        USING ingested_at AT TIME ZONE 'UTC'
    """)


def downgrade() -> None:
    """Revert all changes"""
    
    # Revert ingestion.issue.ingested_at
    op.execute("""
        ALTER TABLE ingestion.issue 
        ALTER COLUMN ingested_at TYPE TIMESTAMP WITHOUT TIME ZONE
    """)
    
    # Revert personalnote.updated_at
    op.execute("""
        ALTER TABLE public.personalnote 
        ALTER COLUMN updated_at TYPE TIMESTAMP WITHOUT TIME ZONE
    """)
    
    # Revert bookmarkedissue.created_at
    op.execute("""
        ALTER TABLE public.bookmarkedissue 
        ALTER COLUMN created_at TYPE TIMESTAMP WITHOUT TIME ZONE
    """)
    
    # Revert userprofile.updated_at
    op.execute("""
        ALTER TABLE public.userprofile 
        ALTER COLUMN updated_at TYPE TIMESTAMP WITHOUT TIME ZONE
    """)
    
    # Revert session timestamps
    op.execute("""
        ALTER TABLE public.session 
        ALTER COLUMN deviation_logged_at TYPE TIMESTAMP WITHOUT TIME ZONE
    """)
    op.execute("""
        ALTER TABLE public.session 
        ALTER COLUMN last_active_at TYPE TIMESTAMP WITHOUT TIME ZONE
    """)
    op.execute("""
        ALTER TABLE public.session 
        ALTER COLUMN created_at TYPE TIMESTAMP WITHOUT TIME ZONE
    """)
    
    # Revert ip_address from INET to VARCHAR
    op.execute("""
        ALTER TABLE public.session 
        ALTER COLUMN ip_address TYPE VARCHAR(45) 
        USING ip_address::text
    """)
    
    # Revert users.created_at
    op.execute("""
        ALTER TABLE public.users 
        ALTER COLUMN created_at TYPE TIMESTAMP WITHOUT TIME ZONE
    """)
    
    # Drop unique constraint
    op.drop_constraint('uq_users_email_provider', 'users', schema='public')
    
    # Drop fingerprint column (to match state before this migration)
    op.drop_column('session', 'fingerprint', schema='public')
    
    # Rename users table back to user
    op.rename_table('users', 'user', schema='public')
    
    # Restore original trigger function referencing old table name
    op.execute("""
        CREATE OR REPLACE FUNCTION enforce_session_limit()
        RETURNS TRIGGER AS $$
        DECLARE
            session_count INTEGER;
            max_sessions INTEGER := 5;
        BEGIN
            SELECT COUNT(*) INTO session_count
            FROM public.session
            WHERE user_id = NEW.user_id 
              AND expires_at > NOW();
            
            IF session_count >= max_sessions THEN
                DELETE FROM public.session
                WHERE id = (
                    SELECT id 
                    FROM public.session
                    WHERE user_id = NEW.user_id 
                      AND expires_at > NOW()
                    ORDER BY created_at ASC
                    LIMIT 1
                );
            END IF;
            
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """)
