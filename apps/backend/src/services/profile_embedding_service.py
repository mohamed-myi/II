"""
Profile embedding service for vector generation and combination.
"""

import logging
import math
from typing import Optional

from src.services.embedding_service import embed_query

logger = logging.getLogger(__name__)


def _l2_normalize(vector: list[float]) -> list[float]:
    """Returns zero vector if input has zero magnitude."""
    magnitude = math.sqrt(sum(x * x for x in vector))
    if magnitude == 0:
        return vector
    return [x / magnitude for x in vector]


def _weighted_sum(vectors_and_weights: list[tuple[list[float], float]]) -> list[float]:
    """Assumes all vectors have same dimension."""
    if not vectors_and_weights:
        return []
    
    dim = len(vectors_and_weights[0][0])
    result = [0.0] * dim
    
    for vector, weight in vectors_and_weights:
        for i in range(dim):
            result[i] += vector[i] * weight
    
    return result


def format_intent_text(stack_areas: list[str], text: str) -> str:
    """
    Embed format per PROFILE.md lines 96 to 103.
    Languages and experience_level are not embedded; used for Stage 1 SQL filtering.
    """
    stack_str = ", ".join(stack_areas) if stack_areas else ""
    
    if stack_str and text:
        return f"{stack_str}. {text}"
    elif stack_str:
        return stack_str
    else:
        return text


async def generate_intent_vector(
    stack_areas: list[str],
    text: str,
) -> Optional[list[float]]:
    formatted_text = format_intent_text(stack_areas, text)
    
    if not formatted_text:
        logger.warning("Cannot generate intent vector: no text content")
        return None
    
    logger.info(f"Generating intent vector for text length {len(formatted_text)}")
    
    vector = await embed_query(formatted_text)
    
    if vector is None:
        logger.warning("Intent vector generation failed")
        return None
    
    return vector


async def calculate_combined_vector(
    intent_vector: Optional[list[float]],
    resume_vector: Optional[list[float]],
    github_vector: Optional[list[float]],
) -> Optional[list[float]]:
    """
    Weighted fusion per PROFILE.md lines 129 to 138.
    L2 normalizes each source before fusion, then normalizes the result.
    """
    has_intent = intent_vector is not None
    has_resume = resume_vector is not None
    has_github = github_vector is not None
    
    if not has_intent and not has_resume and not has_github:
        return None
    
    normalized_intent = _l2_normalize(intent_vector) if has_intent else None
    normalized_resume = _l2_normalize(resume_vector) if has_resume else None
    normalized_github = _l2_normalize(github_vector) if has_github else None
    
    vectors_and_weights: list[tuple[list[float], float]] = []
    
    if has_intent and has_resume and has_github:
        vectors_and_weights = [
            (normalized_intent, 0.5),
            (normalized_resume, 0.3),
            (normalized_github, 0.2),
        ]
    elif has_intent and has_resume:
        vectors_and_weights = [
            (normalized_intent, 0.6),
            (normalized_resume, 0.4),
        ]
    elif has_intent and has_github:
        vectors_and_weights = [
            (normalized_intent, 0.7),
            (normalized_github, 0.3),
        ]
    elif has_resume and has_github:
        vectors_and_weights = [
            (normalized_resume, 0.6),
            (normalized_github, 0.4),
        ]
    elif has_intent:
        return normalized_intent
    elif has_resume:
        return normalized_resume
    else:
        return normalized_github
    
    combined = _weighted_sum(vectors_and_weights)
    return _l2_normalize(combined)


__all__ = [
    "format_intent_text",
    "generate_intent_vector",
    "calculate_combined_vector",
]

