from uuid import UUID
from datetime import datetime
from typing import List, Optional, Dict, Any
from sqlmodel import SQLModel, Field, Relationship, Column
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
import sqlalchemy as sa
from pgvector.sqlalchemy import Vector


class UserProfile(SQLModel, table=True):
    __tablename__ = "userprofile"
    __table_args__ = {"schema": "public"}
    
    user_id: UUID = Field(primary_key=True, foreign_key="public.users.id")
    
    # Vector fields (4 total); combined_vector is the only one used for recommendations
    intent_vector: Optional[List[float]] = Field(default=None, sa_column=Column(Vector(768)))
    resume_vector: Optional[List[float]] = Field(default=None, sa_column=Column(Vector(768)))
    github_vector: Optional[List[float]] = Field(default=None, sa_column=Column(Vector(768)))
    combined_vector: Optional[List[float]] = Field(default=None, sa_column=Column(Vector(768)))
    
    # Manual intent fields (Quick Start)
    intent_stack_areas: Optional[List[str]] = Field(default=None, sa_column=Column(ARRAY(sa.String)))
    intent_text: Optional[str] = Field(default=None)
    intent_experience: Optional[str] = Field(default=None, max_length=20)
    
    # Resume fields
    resume_skills: Optional[List[str]] = Field(default=None, sa_column=Column(ARRAY(sa.String)))
    resume_job_titles: Optional[List[str]] = Field(default=None, sa_column=Column(ARRAY(sa.String)))
    resume_raw_entities: Optional[Dict[str, Any]] = Field(default=None, sa_column=Column(JSONB))
    resume_uploaded_at: Optional[datetime] = Field(default=None)
    
    # GitHub fields
    github_username: Optional[str] = Field(default=None, max_length=255)
    github_languages: Optional[List[str]] = Field(default=None, sa_column=Column(ARRAY(sa.String)))
    github_topics: Optional[List[str]] = Field(default=None, sa_column=Column(ARRAY(sa.String)))
    github_data: Optional[Dict[str, Any]] = Field(default=None, sa_column=Column(JSONB))
    github_fetched_at: Optional[datetime] = Field(default=None)
    
    # Preference fields (hard filters for Stage 1 SQL)
    preferred_languages: Optional[List[str]] = Field(default=None, sa_column=Column(ARRAY(sa.String)))
    preferred_topics: Optional[List[str]] = Field(default=None, sa_column=Column(ARRAY(sa.String)))
    min_heat_threshold: float = Field(default=0.6)
    
    # State fields
    is_calculating: bool = Field(default=False)
    onboarding_status: str = Field(
        default="not_started",
        sa_column=sa.Column(sa.String(20), server_default="not_started", nullable=False)
    )
    onboarding_completed_at: Optional[datetime] = Field(default=None)
    updated_at: datetime = Field(
        sa_column=sa.Column(
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
            nullable=False,
        )
    )

    user: "User" = Relationship(back_populates="profile")
