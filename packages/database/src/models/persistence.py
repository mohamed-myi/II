from uuid import UUID, uuid4
from datetime import datetime
from typing import List
import sqlalchemy as sa
from sqlmodel import SQLModel, Field, Relationship

class BookmarkedIssue(SQLModel, table=True):
    __table_args__ = {"schema": "public"}
    
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    user_id: UUID = Field(foreign_key="public.users.id")
    issue_node_id: str
    github_url: str
    title_snapshot: str
    body_snapshot: str
    
    is_resolved: bool = Field(default=False)
    created_at: datetime = Field(
        sa_column=sa.Column(
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        )
    )

    user: "User" = Relationship(back_populates="bookmarks")
    notes: List["PersonalNote"] = Relationship(back_populates="bookmark")

class PersonalNote(SQLModel, table=True):
    __table_args__ = {"schema": "public"}
    
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    bookmark_id: UUID = Field(foreign_key="public.bookmarkedissue.id")
    content: str
    updated_at: datetime = Field(
        sa_column=sa.Column(
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        )
    )
    
    bookmark: BookmarkedIssue = Relationship(back_populates="notes")