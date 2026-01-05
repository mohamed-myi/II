from uuid import UUID, uuid4
from datetime import datetime
from typing import Optional, List
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import INET, ARRAY
from sqlmodel import SQLModel, Field, Relationship, Column


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
    linked_accounts: List["LinkedAccount"] = Relationship(back_populates="user")


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


class LinkedAccount(SQLModel, table=True):
    """Stores OAuth tokens for services connected after initial login.
    Used for profile features that require API access (e.g., GitHub activity analysis).
    """
    __tablename__ = "linked_accounts"
    __table_args__ = (
        sa.UniqueConstraint("user_id", "provider", name="uq_linked_accounts_user_provider"),
        {"schema": "public"},
    )
    
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    user_id: UUID = Field(foreign_key="public.users.id", index=True)
    provider: str = Field(max_length=50, index=True)
    provider_user_id: str = Field(max_length=255)
    
    # Token storage (encrypted at application level via Fernet)
    access_token: str
    refresh_token: Optional[str] = Field(default=None)
    scopes: List[str] = Field(
        default_factory=list,
        sa_column=Column(ARRAY(sa.String), server_default="{}", nullable=False)
    )
    expires_at: Optional[datetime] = Field(default=None)
    
    created_at: datetime = Field(
        sa_column=sa.Column(
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        )
    )
    # Null if active; set when user revokes access
    revoked_at: Optional[datetime] = Field(default=None)
    
    user: User = Relationship(back_populates="linked_accounts")
