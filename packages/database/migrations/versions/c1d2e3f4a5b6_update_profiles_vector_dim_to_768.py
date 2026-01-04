"""update_profiles_vector_dim_to_768

Revision ID: c1d2e3f4a5b6
Revises: b4c5d6e7f8a9
Create Date: 2026-01-03

Alters userprofile vector columns from 256-dim to 768-dim
to match nomic-embed-text-v1.5 embeddings.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'c1d2e3f4a5b6'
down_revision: Union[str, Sequence[str], None] = 'b4c5d6e7f8a9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade userprofile vector columns from 256 to 768 dimensions."""
    # ALTER COLUMN TYPE for pgvector columns
    op.execute("""
        ALTER TABLE public.userprofile 
        ALTER COLUMN history_vector TYPE vector(768)
    """)
    op.execute("""
        ALTER TABLE public.userprofile 
        ALTER COLUMN intent_vector TYPE vector(768)
    """)


def downgrade() -> None:
    """Downgrade userprofile vector columns from 768 to 256 dimensions."""
    op.execute("""
        ALTER TABLE public.userprofile 
        ALTER COLUMN history_vector TYPE vector(256)
    """)
    op.execute("""
        ALTER TABLE public.userprofile 
        ALTER COLUMN intent_vector TYPE vector(256)
    """)
