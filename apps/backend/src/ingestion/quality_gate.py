"""Q score quality gate; formula Q = 0.4C + 0.3H + 0.2E - 0.5P"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

_workspace_root = Path(__file__).parent.parent.parent.parent.parent
if str(_workspace_root) not in sys.path:
    sys.path.insert(0, str(_workspace_root))

from packages.shared.src.constants import (
    TECH_KEYWORDS_BY_LANGUAGE,
    DEFAULT_TECH_KEYWORDS,
    TEMPLATE_HEADERS,
    JUNK_PATTERNS,
)


JUNK_REGEXES: list[re.Pattern[str]] = [
    re.compile(re.escape(pattern), re.IGNORECASE)
    for pattern in JUNK_PATTERNS
]


@dataclass
class QScoreComponents:
    """C = code blocks; H = template headers; E = tech keyword weight; P = junk spam"""
    has_code: bool
    has_headers: bool
    tech_weight: float
    is_junk: bool


def compute_q_score(components: QScoreComponents) -> float:
    """Returns float in range negative 0.5 to 0.9"""
    return (
        0.4 * float(components.has_code) +
        0.3 * float(components.has_headers) +
        0.2 * components.tech_weight -
        0.5 * float(components.is_junk)
    )


def extract_components(title: str, body: str, language: str) -> QScoreComponents:
    """Uses language specific keywords for tech weight; caps at 3 hits = 1.0"""
    has_code = "```" in body

    body_lower = body.lower()
    has_headers = any(
        header.lower() in body_lower
        for header in TEMPLATE_HEADERS
    )

    keywords = TECH_KEYWORDS_BY_LANGUAGE.get(language, DEFAULT_TECH_KEYWORDS)
    combined_text = f"{title} {body}".lower()
    keyword_hits = sum(1 for kw in keywords if kw.lower() in combined_text)
    tech_weight = min(1.0, keyword_hits / 3.0)

    is_junk = any(pattern.search(body) for pattern in JUNK_REGEXES)

    return QScoreComponents(
        has_code=has_code,
        has_headers=has_headers,
        tech_weight=tech_weight,
        is_junk=is_junk,
    )


def passes_quality_gate(score: float, threshold: float = 0.6) -> bool:
    return score >= threshold


def evaluate_issue(title: str, body: str, language: str, threshold: float = 0.6) -> tuple[float, bool]:
    """Returns tuple of q_score and passes boolean"""
    components = extract_components(title, body, language)
    score = compute_q_score(components)
    return score, passes_quality_gate(score, threshold)

