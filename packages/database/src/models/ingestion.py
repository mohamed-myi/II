from typing import List, Optional, Dict
from datetime import datetime
import sqlalchemy as sa
from sqlmodel import SQLModel, Field, Relationship, Column
from sqlalchemy.dialects.postgresql import JSONB, ARRAY
from pgvector.sqlalchemy import Vector

class Repository(SQLModel, table=True):
    __table_args__ = {"schema": "ingestion"}
    
    node_id: str = Field(primary_key=True)
    full_name: str = Field(index=True)
    primary_language: Optional[str] = Field(index=True)
    languages: Dict = Field(default_factory=dict, sa_column=Column(JSONB))
    topics: List[str] = Field(sa_column=Column(ARRAY(sa.String)))
    stargazer_count: int = Field(default=0)
    quality_score: float = Field(default=1.0)
    last_scraped_at: Optional[datetime] = None

    issues: List["Issue"] = Relationship(back_populates="repository")

class Issue(SQLModel, table=True):
    __table_args__ = {"schema": "ingestion"}
    
    node_id: str = Field(primary_key=True)
    repo_id: str = Field(foreign_key="ingestion.repository.node_id")
    title: str
    body_text: str
    author_association: Optional[str] = None
    labels: List[Dict] = Field(default_factory=list, sa_column=Column(JSONB))
    comment_count: int = Field(default=0)
    
    heat_score: float = Field(index=True)
    
    # 256-dim Matryoshka Vector
    embedding: List[float] = Field(sa_column=Column(Vector(256))) 
    
    github_created_at: datetime
    ingested_at: datetime = Field(default_factory=datetime.utcnow, index=True)

    repository: Repository = Relationship(back_populates="issues")