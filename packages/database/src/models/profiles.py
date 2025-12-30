from uuid import UUID
from datetime import datetime
from typing import List
from sqlmodel import SQLModel, Field, Relationship, Column
from sqlalchemy.dialects.postgresql import ARRAY
import sqlalchemy as sa
from pgvector.sqlalchemy import Vector

class UserProfile(SQLModel, table=True):
    __table_args__ = {"schema": "public"}
    
    user_id: UUID = Field(primary_key=True, foreign_key="public.users.id")
    
    history_vector: List[float] = Field(sa_column=Column(Vector(256)))
    intent_vector: List[float] = Field(sa_column=Column(Vector(256)))
    
    preferred_languages: List[str] = Field(sa_column=Column(ARRAY(sa.String)))
    preferred_topics: List[str] = Field(sa_column=Column(ARRAY(sa.String)))
    min_heat_threshold: float = Field(default=0.6)
    
    raw_intent_text: str
    is_calculating: bool = Field(default=False)
    updated_at: datetime = Field(
        sa_column=sa.Column(
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        )
    )

    user: "User" = Relationship(back_populates="profile")