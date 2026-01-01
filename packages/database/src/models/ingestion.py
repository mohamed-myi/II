from typing import List, Optional, Dict
from datetime import datetime
import sqlalchemy as sa
from sqlmodel import SQLModel, Field, Relationship, Column
from sqlalchemy.dialects.postgresql import JSONB, ARRAY, REAL
from pgvector.sqlalchemy import Vector

# Aligns with nomic-embed-text-v1.5 output and INGESTION.md Phase 2 spec
VECTOR_DIM = 768


class Repository(SQLModel, table=True):
    __table_args__ = {"schema": "ingestion"}

    node_id: str = Field(primary_key=True)
    full_name: str = Field(index=True, unique=True)
    primary_language: Optional[str] = Field(default=None, index=True)

    # Scout logic: repo-level velocity for discovery queries
    issue_velocity_week: int = Field(default=0)
    stargazer_count: int = Field(default=0, index=True)

    languages: Dict = Field(default_factory=dict, sa_column=Column(JSONB))
    topics: List[str] = Field(default_factory=list, sa_column=Column(ARRAY(sa.String)))

    last_scraped_at: Optional[datetime] = Field(
        default=None,
        sa_column=sa.Column(sa.DateTime(timezone=True), index=True),
    )

    issues: List["Issue"] = Relationship(back_populates="repository")


class Issue(SQLModel, table=True):
    __table_args__ = (
        # Composite index for Janitor's bottom-20% pruning query
        sa.Index("ix_issue_survival_vacuum", "survival_score", "ingested_at"),
        {"schema": "ingestion"},
    )

    node_id: str = Field(primary_key=True)
    repo_id: str = Field(foreign_key="ingestion.repository.node_id", index=True)

    # Q-Score components (0.0 to 1.0); enables AlloyDB Columnar Engine scans
    has_code: bool = Field(default=False)
    has_template_headers: bool = Field(default=False)
    tech_stack_weight: float = Field(default=0.0)

    # Calculated scores (Phase III logic)
    q_score: float = Field(default=0.0, index=True, sa_column=Column(REAL))
    survival_score: float = Field(default=0.0, index=True, sa_column=Column(REAL))

    # Content
    title: str
    body_text: str
    labels: List[str] = Field(default_factory=list, sa_column=Column(ARRAY(sa.String)))

    # 768-dim Nomic embeddings; cast to halfvec at DB level for 10GB optimization
    embedding: List[float] = Field(sa_column=Column(Vector(VECTOR_DIM)))

    github_created_at: datetime
    ingested_at: datetime = Field(
        sa_column=sa.Column(
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
            index=True,
        )
    )

    repository: Repository = Relationship(back_populates="issues")