"""Unit tests for profile embedding service."""
import math
import pytest
from unittest.mock import AsyncMock, patch


class TestFormatIntentText:
    
    def test_formats_stack_areas_and_text(self):
        from src.services.profile_embedding_service import format_intent_text
        
        result = format_intent_text(
            stack_areas=["backend", "data_engineering"],
            text="I want to contribute to async Python libraries"
        )
        
        assert result == "backend, data_engineering. I want to contribute to async Python libraries"
    
    def test_formats_single_stack_area(self):
        from src.services.profile_embedding_service import format_intent_text
        
        result = format_intent_text(
            stack_areas=["frontend"],
            text="Looking for React component bugs"
        )
        
        assert result == "frontend. Looking for React component bugs"
    
    def test_handles_empty_stack_areas(self):
        from src.services.profile_embedding_service import format_intent_text
        
        result = format_intent_text(
            stack_areas=[],
            text="I want to work on open source"
        )
        
        assert result == "I want to work on open source"
    
    def test_handles_only_stack_areas(self):
        from src.services.profile_embedding_service import format_intent_text
        
        result = format_intent_text(
            stack_areas=["backend", "devops"],
            text=""
        )
        
        assert result == "backend, devops"
    
    def test_handles_empty_inputs(self):
        from src.services.profile_embedding_service import format_intent_text
        
        result = format_intent_text(stack_areas=[], text="")
        
        assert result == ""


class TestL2Normalization:
    
    def test_normalizes_to_unit_vector(self):
        from src.services.profile_embedding_service import _l2_normalize
        
        vector = [3.0, 4.0]
        result = _l2_normalize(vector)
        
        magnitude = math.sqrt(sum(x * x for x in result))
        assert abs(magnitude - 1.0) < 1e-10
    
    def test_preserves_direction(self):
        from src.services.profile_embedding_service import _l2_normalize
        
        vector = [3.0, 4.0]
        result = _l2_normalize(vector)
        
        assert abs(result[0] - 0.6) < 1e-10
        assert abs(result[1] - 0.8) < 1e-10
    
    def test_handles_zero_vector(self):
        from src.services.profile_embedding_service import _l2_normalize
        
        vector = [0.0, 0.0, 0.0]
        result = _l2_normalize(vector)
        
        assert result == [0.0, 0.0, 0.0]
    
    def test_handles_large_dimension_vector(self):
        from src.services.profile_embedding_service import _l2_normalize
        
        vector = [1.0] * 768
        result = _l2_normalize(vector)
        
        magnitude = math.sqrt(sum(x * x for x in result))
        assert abs(magnitude - 1.0) < 1e-10


class TestGenerateIntentVector:
    
    @pytest.mark.asyncio
    async def test_generates_vector_from_stack_and_text(self):
        from src.services.profile_embedding_service import generate_intent_vector
        
        mock_vector = [0.1] * 768
        
        with patch("src.services.profile_embedding_service.embed_query", new_callable=AsyncMock) as mock_embed:
            mock_embed.return_value = mock_vector
            
            result = await generate_intent_vector(
                stack_areas=["backend", "data_engineering"],
                text="I want to contribute to async Python libraries"
            )
            
            mock_embed.assert_called_once_with(
                "backend, data_engineering. I want to contribute to async Python libraries"
            )
            assert result == mock_vector
    
    @pytest.mark.asyncio
    async def test_returns_none_on_embedding_failure(self):
        from src.services.profile_embedding_service import generate_intent_vector
        
        with patch("src.services.profile_embedding_service.embed_query", new_callable=AsyncMock) as mock_embed:
            mock_embed.return_value = None
            
            result = await generate_intent_vector(
                stack_areas=["backend"],
                text="Some text"
            )
            
            assert result is None
    
    @pytest.mark.asyncio
    async def test_returns_none_for_empty_input(self):
        from src.services.profile_embedding_service import generate_intent_vector
        
        with patch("src.services.profile_embedding_service.embed_query", new_callable=AsyncMock) as mock_embed:
            result = await generate_intent_vector(stack_areas=[], text="")
            
            mock_embed.assert_not_called()
            assert result is None


class TestCalculateCombinedVector:
    """All 7 fallback cases per PROFILE.md lines 129 to 138."""
    
    def _create_mock_vector(self, base_value: float, dim: int = 768) -> list[float]:
        return [base_value] * dim
    
    def _vector_magnitude(self, vector: list[float]) -> float:
        return math.sqrt(sum(x * x for x in vector))
    
    @pytest.mark.asyncio
    async def test_returns_none_when_no_sources(self):
        from src.services.profile_embedding_service import calculate_combined_vector
        
        result = await calculate_combined_vector(
            intent_vector=None,
            resume_vector=None,
            github_vector=None,
        )
        
        assert result is None
    
    @pytest.mark.asyncio
    async def test_intent_only_returns_normalized_intent(self):
        from src.services.profile_embedding_service import calculate_combined_vector
        
        intent = self._create_mock_vector(2.0)
        
        result = await calculate_combined_vector(
            intent_vector=intent,
            resume_vector=None,
            github_vector=None,
        )
        
        assert result is not None
        magnitude = self._vector_magnitude(result)
        assert abs(magnitude - 1.0) < 1e-10
    
    @pytest.mark.asyncio
    async def test_resume_only_returns_normalized_resume(self):
        from src.services.profile_embedding_service import calculate_combined_vector
        
        resume = self._create_mock_vector(3.0)
        
        result = await calculate_combined_vector(
            intent_vector=None,
            resume_vector=resume,
            github_vector=None,
        )
        
        assert result is not None
        magnitude = self._vector_magnitude(result)
        assert abs(magnitude - 1.0) < 1e-10
    
    @pytest.mark.asyncio
    async def test_github_only_returns_normalized_github(self):
        from src.services.profile_embedding_service import calculate_combined_vector
        
        github = self._create_mock_vector(4.0)
        
        result = await calculate_combined_vector(
            intent_vector=None,
            resume_vector=None,
            github_vector=github,
        )
        
        assert result is not None
        magnitude = self._vector_magnitude(result)
        assert abs(magnitude - 1.0) < 1e-10
    
    @pytest.mark.asyncio
    async def test_intent_plus_resume_uses_correct_weights(self):
        from src.services.profile_embedding_service import calculate_combined_vector
        
        intent = [1.0, 0.0, 0.0]
        resume = [0.0, 1.0, 0.0]
        
        result = await calculate_combined_vector(
            intent_vector=intent,
            resume_vector=resume,
            github_vector=None,
        )
        
        assert result is not None
        # Weighted sum [0.6, 0.4, 0], magnitude sqrt(0.52)
        expected_x = 0.6 / math.sqrt(0.52)
        expected_y = 0.4 / math.sqrt(0.52)
        
        assert abs(result[0] - expected_x) < 1e-10
        assert abs(result[1] - expected_y) < 1e-10
        
        magnitude = self._vector_magnitude(result)
        assert abs(magnitude - 1.0) < 1e-10
    
    @pytest.mark.asyncio
    async def test_intent_plus_github_uses_correct_weights(self):
        from src.services.profile_embedding_service import calculate_combined_vector
        
        intent = [1.0, 0.0, 0.0]
        github = [0.0, 1.0, 0.0]
        
        result = await calculate_combined_vector(
            intent_vector=intent,
            resume_vector=None,
            github_vector=github,
        )
        
        assert result is not None
        # Weighted sum [0.7, 0.3, 0], magnitude sqrt(0.58)
        expected_x = 0.7 / math.sqrt(0.58)
        expected_y = 0.3 / math.sqrt(0.58)
        
        assert abs(result[0] - expected_x) < 1e-10
        assert abs(result[1] - expected_y) < 1e-10
        
        magnitude = self._vector_magnitude(result)
        assert abs(magnitude - 1.0) < 1e-10
    
    @pytest.mark.asyncio
    async def test_resume_plus_github_uses_correct_weights(self):
        from src.services.profile_embedding_service import calculate_combined_vector
        
        resume = [1.0, 0.0, 0.0]
        github = [0.0, 1.0, 0.0]
        
        result = await calculate_combined_vector(
            intent_vector=None,
            resume_vector=resume,
            github_vector=github,
        )
        
        assert result is not None
        # Weighted sum [0.6, 0.4, 0], magnitude sqrt(0.52)
        expected_x = 0.6 / math.sqrt(0.52)
        expected_y = 0.4 / math.sqrt(0.52)
        
        assert abs(result[0] - expected_x) < 1e-10
        assert abs(result[1] - expected_y) < 1e-10
        
        magnitude = self._vector_magnitude(result)
        assert abs(magnitude - 1.0) < 1e-10
    
    @pytest.mark.asyncio
    async def test_all_three_uses_correct_weights(self):
        from src.services.profile_embedding_service import calculate_combined_vector
        
        intent = [1.0, 0.0, 0.0]
        resume = [0.0, 1.0, 0.0]
        github = [0.0, 0.0, 1.0]
        
        result = await calculate_combined_vector(
            intent_vector=intent,
            resume_vector=resume,
            github_vector=github,
        )
        
        assert result is not None
        # Weighted sum [0.5, 0.3, 0.2], magnitude sqrt(0.38)
        expected_x = 0.5 / math.sqrt(0.38)
        expected_y = 0.3 / math.sqrt(0.38)
        expected_z = 0.2 / math.sqrt(0.38)
        
        assert abs(result[0] - expected_x) < 1e-10
        assert abs(result[1] - expected_y) < 1e-10
        assert abs(result[2] - expected_z) < 1e-10
        
        magnitude = self._vector_magnitude(result)
        assert abs(magnitude - 1.0) < 1e-10
    
    @pytest.mark.asyncio
    async def test_combined_vector_is_unit_vector_768dim(self):
        from src.services.profile_embedding_service import calculate_combined_vector
        
        intent = self._create_mock_vector(1.5, 768)
        resume = self._create_mock_vector(2.5, 768)
        github = self._create_mock_vector(0.5, 768)
        
        result = await calculate_combined_vector(
            intent_vector=intent,
            resume_vector=resume,
            github_vector=github,
        )
        
        assert result is not None
        assert len(result) == 768
        
        magnitude = self._vector_magnitude(result)
        assert abs(magnitude - 1.0) < 1e-10


class TestWeightedSum:
    
    def test_computes_weighted_sum(self):
        from src.services.profile_embedding_service import _weighted_sum
        
        v1 = [1.0, 0.0]
        v2 = [0.0, 1.0]
        
        result = _weighted_sum([(v1, 0.6), (v2, 0.4)])
        
        assert abs(result[0] - 0.6) < 1e-10
        assert abs(result[1] - 0.4) < 1e-10
    
    def test_returns_empty_for_no_inputs(self):
        from src.services.profile_embedding_service import _weighted_sum
        
        result = _weighted_sum([])
        
        assert result == []

