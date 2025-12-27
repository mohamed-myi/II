from uuid import UUID, uuid4
from datetime import datetime
from typing import Optional, List
from sqlmodel import SQLModel, Field, Relationship

class User(SQLModel, table=True):
    __table_args__ = {"schema": "public"}

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    github_node_id: str = Field(unique=True, index=True)
    github_username: str
    google_id: Optional[str] = Field(default=None, unique=True)
    email: str = Field(unique=True, index=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    
    sessions: List["Session"] = Relationship(back_populates="user")
    profile: Optional["UserProfile"] = Relationship(back_populates="user")
    bookmarks: List["BookmarkedIssue"] = Relationship(back_populates="user")


class Session(SQLModel, table=True):
    __table_args__ = {"schema": "public"}
    
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    user_id: UUID = Field(foreign_key="public.user.id")
    fingerprint: str
    jti: str = Field(unique=True)
    expires_at: datetime

    user: User = Relationship(back_populates="sessions")

    
    