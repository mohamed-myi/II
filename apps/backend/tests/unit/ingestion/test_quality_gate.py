"""Unit tests for Q score quality gate"""

import pytest
from unittest.mock import patch

from src.ingestion.quality_gate import (
    QScoreComponents,
    compute_q_score,
    extract_components,
    passes_quality_gate,
    evaluate_issue,
)


class TestComputeQScore:
    def test_all_positive_components_max_score(self):
        components = QScoreComponents(
            has_code=True,
            has_headers=True,
            tech_weight=1.0,
            is_junk=False,
        )
        score = compute_q_score(components)
        assert score == pytest.approx(0.9)

    def test_only_code_block(self):
        components = QScoreComponents(
            has_code=True,
            has_headers=False,
            tech_weight=0.0,
            is_junk=False,
        )
        score = compute_q_score(components)
        assert score == pytest.approx(0.4)

    def test_only_headers(self):
        components = QScoreComponents(
            has_code=False,
            has_headers=True,
            tech_weight=0.0,
            is_junk=False,
        )
        score = compute_q_score(components)
        assert score == pytest.approx(0.3)

    def test_only_tech_weight(self):
        components = QScoreComponents(
            has_code=False,
            has_headers=False,
            tech_weight=0.5,
            is_junk=False,
        )
        score = compute_q_score(components)
        assert score == pytest.approx(0.1)

    def test_junk_penalty_applied(self):
        components = QScoreComponents(
            has_code=True,
            has_headers=False,
            tech_weight=0.0,
            is_junk=True,
        )
        score = compute_q_score(components)
        assert score == pytest.approx(-0.1)

    def test_all_components_zero(self):
        components = QScoreComponents(
            has_code=False,
            has_headers=False,
            tech_weight=0.0,
            is_junk=False,
        )
        score = compute_q_score(components)
        assert score == pytest.approx(0.0)

    def test_junk_only_minimum_score(self):
        components = QScoreComponents(
            has_code=False,
            has_headers=False,
            tech_weight=0.0,
            is_junk=True,
        )
        score = compute_q_score(components)
        assert score == pytest.approx(-0.5)

    def test_mixed_components(self):
        components = QScoreComponents(
            has_code=True,
            has_headers=True,
            tech_weight=0.5,
            is_junk=False,
        )
        score = compute_q_score(components)
        assert score == pytest.approx(0.8)


class TestExtractComponents:

    def test_detects_code_block(self):
        body = "Here is the error:\n```python\nraise TypeError()\n```"
        components = extract_components("Bug", body, "Python")
        assert components.has_code is True

    def test_no_code_block(self):
        body = "The application crashes when I click the button"
        components = extract_components("Bug", body, "Python")
        assert components.has_code is False

    def test_detects_template_headers(self):
        body = "## Description\nThe app crashes\n## Steps to Reproduce\n1. Click"
        components = extract_components("Bug", body, "Python")
        assert components.has_headers is True

    def test_no_template_headers(self):
        body = "The app crashes when clicking the button"
        components = extract_components("Bug", body, "Python")
        assert components.has_headers is False

    def test_header_detection_case_insensitive(self):
        body = "## DESCRIPTION\nThis is a bug"
        components = extract_components("Bug", body, "Python")
        assert components.has_headers is True

    def test_python_keywords_detected(self):
        body = "Getting typeerror and importerror when using async await"
        components = extract_components("Bug", body, "Python")
        assert components.tech_weight >= 0.6

    def test_typescript_keywords_detected(self):
        body = "React component throws TypeError with Promise"
        components = extract_components("Bug", body, "TypeScript")
        assert components.tech_weight >= 0.6

    def test_keywords_from_title_and_body(self):
        title = "TypeError in async function"
        body = "The error occurs when using await asyncio FastAPI"
        components = extract_components(title, body, "Python")
        assert components.tech_weight >= 0.6

    def test_unknown_language_uses_defaults(self):
        body = "Application crash with error and exception"
        components = extract_components("Bug", body, "Haskell")
        assert components.tech_weight >= 0.6

    def test_tech_weight_caps_at_one(self):
        body = "TypeError ImportError AttributeError KeyError ValueError RuntimeError"
        components = extract_components("Bug", body, "Python")
        assert components.tech_weight == 1.0

    def test_detects_junk_plus_one(self):
        body = "+1 I also have this issue"
        components = extract_components("Bug", body, "Python")
        assert components.is_junk is True

    def test_detects_junk_me_too(self):
        body = "Me too, same problem here"
        components = extract_components("Bug", body, "Python")
        assert components.is_junk is True

    def test_detects_junk_same_issue(self):
        body = "Same issue as above"
        components = extract_components("Bug", body, "Python")
        assert components.is_junk is True

    def test_junk_detection_case_insensitive(self):
        body = "ME TOO! This is annoying"
        components = extract_components("Bug", body, "Python")
        assert components.is_junk is True

    def test_not_junk_with_valid_content(self):
        body = "The application crashes with a TypeError when I click save"
        components = extract_components("Bug report", body, "Python")
        assert components.is_junk is False


class TestPassesQualityGate:

    def test_passes_at_threshold(self):
        assert passes_quality_gate(0.6, threshold=0.6) is True

    def test_passes_above_threshold(self):
        assert passes_quality_gate(0.8, threshold=0.6) is True

    def test_fails_below_threshold(self):
        assert passes_quality_gate(0.5, threshold=0.6) is False

    def test_fails_at_zero(self):
        assert passes_quality_gate(0.0, threshold=0.6) is False

    def test_fails_negative_score(self):
        assert passes_quality_gate(-0.5, threshold=0.6) is False

    def test_custom_threshold(self):
        assert passes_quality_gate(0.4, threshold=0.3) is True
        assert passes_quality_gate(0.2, threshold=0.3) is False


class TestEvaluateIssue:

    def test_returns_score_and_passes_tuple(self):
        title = "TypeError in production"
        body = "```python\nraise TypeError()\n```\n## Description\nError"
        score, passes = evaluate_issue(title, body, "Python")

        assert isinstance(score, float)
        assert isinstance(passes, bool)

    def test_high_quality_issue_passes(self):
        title = "TypeError when using async await"
        body = """
## Description
Getting TypeError in async function

## Steps to Reproduce
```python
async def main():
    raise TypeError()
```
"""
        score, passes = evaluate_issue(title, body, "Python")

        assert score >= 0.6
        assert passes is True

    def test_low_quality_issue_fails(self):
        title = "Bug"
        body = "+1 same issue"

        score, passes = evaluate_issue(title, body, "Python")

        assert score < 0.6
        assert passes is False


class TestEdgeCases:

    def test_empty_body(self):
        components = extract_components("Title", "", "Python")
        assert components.has_code is False
        assert components.has_headers is False
        assert components.is_junk is False

    def test_empty_title_and_body(self):
        components = extract_components("", "", "Python")
        score = compute_q_score(components)
        assert score == 0.0

    def test_unicode_content(self):
        body = "## Description\n```python\nprint('日本語')\n```"
        components = extract_components("Bug 🐛", body, "Python")
        assert components.has_code is True
        assert components.has_headers is True

    def test_very_long_body(self):
        body = "TypeError ImportError asyncio Django FastAPI " * 100
        components = extract_components("Bug", body, "Python")
        assert components.tech_weight == 1.0

    def test_partial_code_block(self):
        body = "Here is code: ``` print('hello')"
        components = extract_components("Bug", body, "Python")
        assert components.has_code is True

