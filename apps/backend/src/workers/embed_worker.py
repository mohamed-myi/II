"""
Embed Worker: Cloud Run service for vector generation tasks.
Handles embedding requests from Cloud Tasks for profile vectors.
"""
import logging
from contextlib import asynccontextmanager
from typing import Optional
from uuid import UUID

from fastapi import FastAPI, HTTPException, Request, Header
from pydantic import BaseModel
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from session import async_session_factory
from models.profiles import UserProfile
from src.core.config import get_settings
from src.services.embedding_service import embed_query, close_embedder
from src.services.profile_embedding_service import (
    calculate_combined_vector,
    format_intent_text,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

logger = logging.getLogger(__name__)
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Embed worker starting up")
    yield
    await close_embedder()
    logger.info("Embed worker shut down")


app = FastAPI(
    title="IssueIndex Embed Worker",
    description="Cloud Tasks worker for vector generation",
    version="0.1.0",
    lifespan=lifespan,
)


class EmbedResumeRequest(BaseModel):
    """Request payload for resume embedding task."""
    job_id: str
    user_id: str
    markdown_text: str


class EmbedGitHubRequest(BaseModel):
    """Request payload for GitHub embedding task."""
    job_id: str
    user_id: str
    formatted_text: str


class EmbedIntentRequest(BaseModel):
    """Request payload for intent embedding task."""
    job_id: str
    user_id: str
    stack_areas: list[str]
    text: str


class GitHubFetchRequest(BaseModel):
    """Request payload for GitHub fetch task."""
    job_id: str
    user_id: str
    created_at: str


def _verify_cloud_tasks_token(
    x_cloudtasks_taskname: Optional[str] = Header(None),
) -> bool:
    """
    Verifies request is from Cloud Tasks.
    In production, also verify OIDC token.
    For development, allows all requests.
    """
    if settings.environment == "development":
        return True
    
    if x_cloudtasks_taskname:
        return True
    
    return False


async def _get_profile(db: AsyncSession, user_id: UUID) -> Optional[UserProfile]:
    """Fetches profile by user ID."""
    statement = select(UserProfile).where(UserProfile.user_id == user_id)
    result = await db.exec(statement)
    return result.first()


@app.get("/health")
async def health_check():
    """Health check endpoint for Cloud Run."""
    return {"status": "ok", "service": "embed-worker"}


@app.post("/tasks/embed/resume")
async def embed_resume(
    request: EmbedResumeRequest,
    x_cloudtasks_taskname: Optional[str] = Header(None),
):
    """
    Generates resume vector from markdown text.
    Called after Docling and GLiNER processing completes.
    Updates profile with resume_vector and recalculates combined_vector.
    """
    if not _verify_cloud_tasks_token(x_cloudtasks_taskname):
        raise HTTPException(status_code=403, detail="Forbidden")
    
    user_id = UUID(request.user_id)
    logger.info(f"Processing resume embedding for job {request.job_id}, user {user_id}")
    
    try:
        vector = await embed_query(request.markdown_text)
        
        if vector is None:
            logger.error(f"Resume embedding failed for job {request.job_id}")
            raise HTTPException(status_code=500, detail="Embedding generation failed")
        
        async with async_session_factory() as db:
            profile = await _get_profile(db, user_id)
            
            if profile is None:
                logger.warning(f"Profile not found for user {user_id}; job {request.job_id} abandoned")
                return {"status": "abandoned", "reason": "profile_not_found"}
            
            profile.resume_vector = vector
            
            combined = await calculate_combined_vector(
                intent_vector=profile.intent_vector,
                resume_vector=vector,
                github_vector=profile.github_vector,
            )
            profile.combined_vector = combined
            profile.is_calculating = False
            
            await db.commit()
        
        logger.info(f"Resume embedding completed for job {request.job_id}")
        return {"status": "completed", "job_id": request.job_id}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Resume embedding failed for job {request.job_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/tasks/embed/github")
async def embed_github(
    request: EmbedGitHubRequest,
    x_cloudtasks_taskname: Optional[str] = Header(None),
):
    """
    Generates GitHub vector from formatted text.
    Updates profile with github_vector and recalculates combined_vector.
    """
    if not _verify_cloud_tasks_token(x_cloudtasks_taskname):
        raise HTTPException(status_code=403, detail="Forbidden")
    
    user_id = UUID(request.user_id)
    logger.info(f"Processing GitHub embedding for job {request.job_id}, user {user_id}")
    
    try:
        vector = await embed_query(request.formatted_text)
        
        if vector is None:
            logger.error(f"GitHub embedding failed for job {request.job_id}")
            raise HTTPException(status_code=500, detail="Embedding generation failed")
        
        async with async_session_factory() as db:
            profile = await _get_profile(db, user_id)
            
            if profile is None:
                logger.warning(f"Profile not found for user {user_id}; job {request.job_id} abandoned")
                return {"status": "abandoned", "reason": "profile_not_found"}
            
            profile.github_vector = vector
            
            combined = await calculate_combined_vector(
                intent_vector=profile.intent_vector,
                resume_vector=profile.resume_vector,
                github_vector=vector,
            )
            profile.combined_vector = combined
            profile.is_calculating = False
            
            await db.commit()
        
        logger.info(f"GitHub embedding completed for job {request.job_id}")
        return {"status": "completed", "job_id": request.job_id}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"GitHub embedding failed for job {request.job_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/tasks/embed/intent")
async def embed_intent(
    request: EmbedIntentRequest,
    x_cloudtasks_taskname: Optional[str] = Header(None),
):
    """
    Generates intent vector from stack areas and text.
    Updates profile with intent_vector and recalculates combined_vector.
    Note: Intent embedding is currently synchronous but this endpoint
    enables future async capability if needed.
    """
    if not _verify_cloud_tasks_token(x_cloudtasks_taskname):
        raise HTTPException(status_code=403, detail="Forbidden")
    
    user_id = UUID(request.user_id)
    logger.info(f"Processing intent embedding for job {request.job_id}, user {user_id}")
    
    try:
        formatted_text = format_intent_text(request.stack_areas, request.text)
        vector = await embed_query(formatted_text)
        
        if vector is None:
            logger.error(f"Intent embedding failed for job {request.job_id}")
            raise HTTPException(status_code=500, detail="Embedding generation failed")
        
        async with async_session_factory() as db:
            profile = await _get_profile(db, user_id)
            
            if profile is None:
                logger.warning(f"Profile not found for user {user_id}; job {request.job_id} abandoned")
                return {"status": "abandoned", "reason": "profile_not_found"}
            
            profile.intent_vector = vector
            
            combined = await calculate_combined_vector(
                intent_vector=vector,
                resume_vector=profile.resume_vector,
                github_vector=profile.github_vector,
            )
            profile.combined_vector = combined
            profile.is_calculating = False
            
            await db.commit()
        
        logger.info(f"Intent embedding completed for job {request.job_id}")
        return {"status": "completed", "job_id": request.job_id}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Intent embedding failed for job {request.job_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/tasks/github/fetch")
async def fetch_github(
    request: GitHubFetchRequest,
    x_cloudtasks_taskname: Optional[str] = Header(None),
):
    """
    Executes full GitHub profile fetch and embedding.
    This is the main entry point for GitHub async processing.
    """
    if not _verify_cloud_tasks_token(x_cloudtasks_taskname):
        raise HTTPException(status_code=403, detail="Forbidden")
    
    user_id = UUID(request.user_id)
    logger.info(f"Processing GitHub fetch for job {request.job_id}, user {user_id}")
    
    try:
        from src.services.github_profile_service import execute_github_fetch
        
        async with async_session_factory() as db:
            result = await execute_github_fetch(db, user_id)
        
        logger.info(f"GitHub fetch completed for job {request.job_id}")
        return {"status": "completed", "job_id": request.job_id, "result": result}
        
    except Exception as e:
        logger.exception(f"GitHub fetch failed for job {request.job_id}: {e}")
        
        async with async_session_factory() as db:
            profile = await _get_profile(db, user_id)
            if profile:
                profile.is_calculating = False
                await db.commit()
        
        raise HTTPException(status_code=500, detail=str(e))

