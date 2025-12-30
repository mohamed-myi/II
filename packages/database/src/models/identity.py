from uuid import UUID, uuid4
from datetime import datetime
from typing import Optional, List
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import INET
from sqlmodel import SQLModel, Field, Relationship


class User(SQLModel, table=True):
    __tablename__ = "users"
    __table_args__ = {"schema": "public"}

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    github_node_id: Optional[str] = Field(default=None, unique=True, index=True)
    github_username: Optional[str] = Field(default=None)
    google_id: Optional[str] = Field(default=None, unique=True)
    email: str = Field(unique=True, index=True)
    created_at: datetime = Field(
        sa_column=sa.Column(
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        )
    )
    created_via: str = Field(
        default="github",
        sa_column=sa.Column(sa.String, server_default="github", nullable=False)
    )
    
    sessions: List["Session"] = Relationship(back_populates="user")
    profile: Optional["UserProfile"] = Relationship(back_populates="user")
    bookmarks: List["BookmarkedIssue"] = Relationship(back_populates="user")


class Session(SQLModel, table=True):
    __table_args__ = {"schema": "public"}
    
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    user_id: UUID = Field(foreign_key="public.users.id")
    fingerprint: str = Field(default="")
    jti: str = Field(unique=True)
    expires_at: datetime
    remember_me: bool = Field(default=False)
    created_at: datetime = Field(
        sa_column=sa.Column(
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        )
    )
    last_active_at: datetime = Field(
        sa_column=sa.Column(
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        )
    )
    ip_address: Optional[str] = Field(
        default=None,
        sa_column=sa.Column(INET, nullable=True)
    )
    user_agent_string: Optional[str] = Field(default=None)
    # Metadata binding fields; populated at login, used for risk assessment
    os_family: Optional[str] = Field(default=None, max_length=32)
    ua_family: Optional[str] = Field(default=None, max_length=64)
    asn: Optional[str] = Field(default=None, max_length=32)
    country_code: Optional[str] = Field(default=None, max_length=2)
    deviation_logged_at: Optional[datetime] = Field(default=None)

    user: User = Relationship(back_populates="sessions")