"""
Resume Worker: Cloud Run service for resume parsing tasks.
Handles full resume pipeline: Docling parse, GLiNER extract, normalize, embed.
"""
import base64
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from session import async_session_factory
from models.profiles import UserProfile
from src.core.config import get_settings
from src.services.embedding_service import embed_query, close_embedder
from src.services.profile_embedding_service import calculate_combined_vector
from src.services.resume_parsing_service import (
    parse_resume_to_markdown,
    extract_entities,
    normalize_entities,
    check_minimal_data,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

logger = logging.getLogger(__name__)
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Resume worker starting up")
    yield
    await close_embedder()
    logger.info("Resume worker shut down")


app = FastAPI(
    title="IssueIndex Resume Worker",
    description="Cloud Tasks worker for resume parsing pipeline",
    version="0.1.0",
    lifespan=lifespan,
)


class ResumeParseRequest(BaseModel):
    """Request payload for resume parsing task from Cloud Tasks."""
    job_id: str
    user_id: str
    filename: str
    content_type: Optional[str]
    file_bytes_b64: str
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
    return {"status": "ok", "service": "resume-worker"}


@app.post("/tasks/resume/parse")
async def parse_resume(
    request: ResumeParseRequest,
    x_cloudtasks_taskname: Optional[str] = Header(None),
):
    """
    Executes full resume parsing pipeline:
    1. Docling: Parse PDF/DOCX to Markdown
    2. GLiNER: Extract entities (skills, job titles)
    3. Normalize: Map to taxonomy
    4. Embed: Generate 768-dim vector
    5. Update: Store results in profile
    
    File bytes are base64 encoded in the request.
    """
    if not _verify_cloud_tasks_token(x_cloudtasks_taskname):
        raise HTTPException(status_code=403, detail="Forbidden")
    
    user_id = UUID(request.user_id)
    logger.info(f"Processing resume parse for job {request.job_id}, user {user_id}")
    
    try:
        file_bytes = base64.b64decode(request.file_bytes_b64)
        
        logger.info(f"Stage 1: Docling parse for job {request.job_id}")
        markdown = parse_resume_to_markdown(file_bytes, request.filename)
        
        logger.info(f"Stage 2: GLiNER extract for job {request.job_id}")
        raw_entities = extract_entities(markdown)
        
        logger.info(f"Stage 3: Normalize entities for job {request.job_id}")
        skills, job_titles, raw_data = normalize_entities(raw_entities)
        
        minimal_warning = check_minimal_data(len(skills))
        if minimal_warning:
            logger.info(f"Minimal data warning for job {request.job_id}: {minimal_warning}")
        
        async with async_session_factory() as db:
            profile = await _get_profile(db, user_id)
            
            if profile is None:
                logger.warning(f"Profile not found for user {user_id}; job {request.job_id} abandoned")
                return {"status": "abandoned", "reason": "profile_not_found"}
            
            profile.resume_skills = skills if skills else []
            profile.resume_job_titles = job_titles if job_titles else []
            profile.resume_raw_entities = raw_data
            profile.resume_uploaded_at = datetime.now(timezone.utc)
            
            await db.commit()
        
        logger.info(f"Stage 4: Generate embedding for job {request.job_id}")
        vector = await embed_query(markdown)
        
        async with async_session_factory() as db:
            profile = await _get_profile(db, user_id)
            
            if profile is None:
                logger.warning(f"Profile deleted during processing; job {request.job_id} abandoned")
                return {"status": "abandoned", "reason": "profile_deleted"}
            
            profile.resume_vector = vector
            
            combined = await calculate_combined_vector(
                intent_vector=profile.intent_vector,
                resume_vector=vector,
                github_vector=profile.github_vector,
            )
            profile.combined_vector = combined
            profile.is_calculating = False
            
            await db.commit()
        
        logger.info(f"Resume parse completed for job {request.job_id}")
        return {
            "status": "completed",
            "job_id": request.job_id,
            "skills_count": len(skills),
            "job_titles_count": len(job_titles),
            "vector_generated": vector is not None,
            "minimal_data_warning": minimal_warning,
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Resume parse failed for job {request.job_id}: {e}")
        
        try:
            async with async_session_factory() as db:
                profile = await _get_profile(db, user_id)
                if profile:
                    profile.is_calculating = False
                    await db.commit()
        except Exception as cleanup_error:
            logger.warning(f"Failed to cleanup is_calculating flag: {cleanup_error}")
        
        raise HTTPException(status_code=500, detail=str(e))

