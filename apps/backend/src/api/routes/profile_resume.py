"""Resume profile API routes for uploading and managing resume data."""
from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel
from sqlmodel.ext.asyncio.session import AsyncSession

from src.api.dependencies import get_db
from src.middleware.auth import require_auth
from src.services.resume_parsing_service import (
    process_resume,
    get_resume_data,
    delete_resume,
    MAX_FILE_SIZE,
)
from src.core.errors import (
    handle_profile_error,
    ResumeParseError,
    UnsupportedFormatError,
    FileTooLargeError,
)
from models.identity import User, Session


router = APIRouter()


class ResumeUploadResponse(BaseModel):
    """Response after uploading and parsing a resume."""
    status: str
    skills: list[str]
    job_titles: list[str]
    vector_status: Optional[str]
    uploaded_at: str
    minimal_data_warning: Optional[str] = None


class ResumeDataResponse(BaseModel):
    """Response containing stored resume data."""
    status: str
    skills: list[str]
    job_titles: list[str]
    vector_status: Optional[str]
    uploaded_at: Optional[str]


def _handle_resume_error(e: Exception) -> HTTPException:
    """Converts resume-related exceptions to user-friendly HTTP responses."""
    if isinstance(e, UnsupportedFormatError):
        return HTTPException(status_code=400, detail="Please upload a PDF or DOCX file")
    if isinstance(e, FileTooLargeError):
        return HTTPException(status_code=413, detail="Resume must be under 5MB")
    if isinstance(e, ResumeParseError):
        return HTTPException(
            status_code=422,
            detail="We couldn't read your resume. Try a different format?"
        )
    
    return handle_profile_error(e)


@router.post("/resume", response_model=ResumeUploadResponse)
async def upload_resume(
    file: UploadFile = File(...),
    auth: tuple[User, Session] = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
) -> ResumeUploadResponse:
    """
    Uploads and parses a resume file.
    
    Accepts PDF or DOCX files up to 5MB.
    Extracts skills and job titles via Docling and GLiNER.
    Generates resume_vector and recalculates combined_vector.
    
    The original file is processed in memory and never stored.
    Only the extracted metadata and vector are persisted.
    
    Returns:
        ResumeUploadResponse with extracted skills and vector status.
    
    Errors:
        400: Unsupported file format (not PDF or DOCX)
        413: File too large (exceeds 5MB)
        422: Unable to parse file content
    """
    user, _ = auth
    
    file_bytes = await file.read()
    
    if len(file_bytes) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="Resume must be under 5MB")
    
    try:
        result = await process_resume(
            db,
            user.id,
            file_bytes,
            file.filename or "resume",
            file.content_type,
        )
    except (UnsupportedFormatError, FileTooLargeError, ResumeParseError) as e:
        raise _handle_resume_error(e)
    
    return ResumeUploadResponse(
        status=result["status"],
        skills=result["skills"],
        job_titles=result["job_titles"],
        vector_status=result["vector_status"],
        uploaded_at=result["uploaded_at"],
        minimal_data_warning=result.get("minimal_data_warning"),
    )


@router.get("/resume", response_model=ResumeDataResponse)
async def get_resume(
    auth: tuple[User, Session] = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
) -> ResumeDataResponse:
    """
    Returns stored resume data.
    
    Returns:
        ResumeDataResponse with extracted skills and job titles.
    
    Errors:
        404: No resume data found; use POST /profile/resume first.
    """
    user, _ = auth
    
    data = await get_resume_data(db, user.id)
    
    if data is None:
        raise HTTPException(
            status_code=404,
            detail="No resume data found. Upload a resume first."
        )
    
    return ResumeDataResponse(
        status=data["status"],
        skills=data["skills"],
        job_titles=data["job_titles"],
        vector_status=data["vector_status"],
        uploaded_at=data["uploaded_at"],
    )


@router.delete("/resume")
async def delete_resume_data(
    auth: tuple[User, Session] = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Clears resume data and vector.
    
    Triggers combined_vector recalculation from remaining sources.
    
    Returns:
        Confirmation of deletion.
    
    Errors:
        404: No resume data to delete.
    """
    user, _ = auth
    
    was_deleted = await delete_resume(db, user.id)
    
    if not was_deleted:
        raise HTTPException(
            status_code=404,
            detail="No resume data to delete"
        )
    
    return {"deleted": True, "message": "Resume data cleared"}
