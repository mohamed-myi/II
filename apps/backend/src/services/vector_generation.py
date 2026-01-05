"""
Vector generation wrapper with retry support.
Provides synchronous retry with exponential backoff for embedding operations.
"""
import asyncio
import logging
from typing import Optional
from uuid import UUID

from sqlmodel.ext.asyncio.session import AsyncSession
from sqlmodel import select

from models.profiles import UserProfile
from src.services.profile_embedding_service import generate_intent_vector as _generate_intent_vector
from src.services.embedding_service import embed_query

logger = logging.getLogger(__name__)

MAX_RETRIES = 3
BASE_BACKOFF_SECONDS = 1


async def generate_intent_vector_with_retry(
    stack_areas: list[str],
    text: str,
    max_retries: int = MAX_RETRIES,
) -> Optional[list[float]]:
    """
    Generates intent vector with exponential backoff retry.
    Returns None if all retries fail; logs error but does not raise.
    """
    for attempt in range(max_retries):
        try:
            vector = await _generate_intent_vector(stack_areas, text)
            if vector is not None:
                return vector
            
            logger.warning(
                f"Intent vector returned None on attempt {attempt + 1}/{max_retries}"
            )
            
        except Exception as e:
            logger.warning(
                f"Intent vector generation failed on attempt {attempt + 1}/{max_retries}: {e}"
            )
        
        if attempt < max_retries - 1:
            backoff = BASE_BACKOFF_SECONDS * (2 ** attempt)
            logger.info(f"Retrying intent vector in {backoff}s")
            await asyncio.sleep(backoff)
    
    logger.error(
        f"Intent vector generation permanently failed after {max_retries} attempts"
    )
    return None


async def generate_resume_vector_with_retry(
    markdown_text: str,
    max_retries: int = MAX_RETRIES,
) -> Optional[list[float]]:
    """
    Generates resume vector with exponential backoff retry.
    Returns None if all retries fail; logs error but does not raise.
    """
    for attempt in range(max_retries):
        try:
            vector = await embed_query(markdown_text)
            if vector is not None:
                return vector
            
            logger.warning(
                f"Resume vector returned None on attempt {attempt + 1}/{max_retries}"
            )
            
        except Exception as e:
            logger.warning(
                f"Resume vector generation failed on attempt {attempt + 1}/{max_retries}: {e}"
            )
        
        if attempt < max_retries - 1:
            backoff = BASE_BACKOFF_SECONDS * (2 ** attempt)
            logger.info(f"Retrying resume vector in {backoff}s")
            await asyncio.sleep(backoff)
    
    logger.error(
        f"Resume vector generation permanently failed after {max_retries} attempts"
    )
    return None


async def generate_github_vector_with_retry(
    text: str,
    max_retries: int = MAX_RETRIES,
) -> Optional[list[float]]:
    """
    Generates GitHub vector with exponential backoff retry.
    Returns None if all retries fail; logs error but does not raise.
    """
    for attempt in range(max_retries):
        try:
            vector = await embed_query(text)
            if vector is not None:
                return vector
            
            logger.warning(
                f"GitHub vector returned None on attempt {attempt + 1}/{max_retries}"
            )
            
        except Exception as e:
            logger.warning(
                f"GitHub vector generation failed on attempt {attempt + 1}/{max_retries}: {e}"
            )
        
        if attempt < max_retries - 1:
            backoff = BASE_BACKOFF_SECONDS * (2 ** attempt)
            logger.info(f"Retrying GitHub vector in {backoff}s")
            await asyncio.sleep(backoff)
    
    logger.error(
        f"GitHub vector generation permanently failed after {max_retries} attempts"
    )
    return None


async def check_profile_exists(
    db: AsyncSession,
    user_id: UUID,
) -> bool:
    """Checks if profile exists and has not been deleted during processing."""
    statement = select(UserProfile.user_id).where(UserProfile.user_id == user_id)
    result = await db.exec(statement)
    return result.first() is not None


__all__ = [
    "generate_intent_vector_with_retry",
    "generate_resume_vector_with_retry",
    "generate_github_vector_with_retry",
    "check_profile_exists",
    "MAX_RETRIES",
    "BASE_BACKOFF_SECONDS",
]

