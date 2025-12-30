"""
Rate Limiter Unit Tests

Tests the in-memory rate limiter backend which is used as fallback
when Redis is not available (development/testing).
"""
import time
from unittest.mock import patch

import pytest

from src.middleware.rate_limit import (
    InMemoryRateLimiter,
    reset_rate_limiter,
)


class TestInMemoryRateLimiter:
    """Tests for the in-memory rate limiter backend."""
    
    def setup_method(self):
        self.limiter = InMemoryRateLimiter()
    
    def teardown_method(self):
        reset_rate_limiter()
    
    @pytest.mark.asyncio
    async def test_allows_first_request(self):
        is_limited, retry_after = await self.limiter.is_rate_limited(
            "127.0.0.1", max_requests=10, window_seconds=60
        )
        
        assert is_limited is False
        assert retry_after is None
    
    @pytest.mark.asyncio
    async def test_allows_up_to_max_requests(self):
        for i in range(10):
            is_limited, _ = await self.limiter.is_rate_limited(
                "127.0.0.1", max_requests=10, window_seconds=60
            )
            assert is_limited is False
    
    @pytest.mark.asyncio
    async def test_blocks_after_max_requests(self):
        for _ in range(10):
            await self.limiter.is_rate_limited(
                "127.0.0.1", max_requests=10, window_seconds=60
            )
        
        is_limited, retry_after = await self.limiter.is_rate_limited(
            "127.0.0.1", max_requests=10, window_seconds=60
        )
        
        assert is_limited is True
        assert retry_after is not None
        assert retry_after > 0
    
    @pytest.mark.asyncio
    async def test_different_keys_have_separate_limits(self):
        for _ in range(10):
            await self.limiter.is_rate_limited(
                "127.0.0.1", max_requests=10, window_seconds=60
            )
        
        is_limited, _ = await self.limiter.is_rate_limited(
            "192.168.1.1", max_requests=10, window_seconds=60
        )
        
        assert is_limited is False
    
    @pytest.mark.asyncio
    async def test_window_expires_after_timeout(self):
        for _ in range(10):
            await self.limiter.is_rate_limited(
                "127.0.0.1", max_requests=10, window_seconds=60
            )
        
        # Simulate time passing beyond window
        with patch.object(time, "time", return_value=time.time() + 61):
            is_limited, _ = await self.limiter.is_rate_limited(
                "127.0.0.1", max_requests=10, window_seconds=60
            )
        
        assert is_limited is False
    
    @pytest.mark.asyncio
    async def test_retry_after_is_correct(self):
        base_time = time.time()
        
        with patch.object(time, "time", return_value=base_time):
            for _ in range(10):
                await self.limiter.is_rate_limited(
                    "127.0.0.1", max_requests=10, window_seconds=60
                )
        
        # 30 seconds later
        with patch.object(time, "time", return_value=base_time + 30):
            is_limited, retry_after = await self.limiter.is_rate_limited(
                "127.0.0.1", max_requests=10, window_seconds=60
            )
        
        assert is_limited is True
        # Should be approximately 30 seconds until oldest expires (60 - 30 + 1)
        assert 30 <= retry_after <= 32
    
    @pytest.mark.asyncio
    async def test_clear_resets_storage(self):
        for _ in range(10):
            await self.limiter.is_rate_limited(
                "127.0.0.1", max_requests=10, window_seconds=60
            )
        
        await self.limiter.clear()
        
        is_limited, _ = await self.limiter.is_rate_limited(
            "127.0.0.1", max_requests=10, window_seconds=60
        )
        assert is_limited is False
    
    @pytest.mark.asyncio
    async def test_clear_specific_key(self):
        await self.limiter.is_rate_limited("key1", max_requests=1, window_seconds=60)
        await self.limiter.is_rate_limited("key2", max_requests=1, window_seconds=60)
        
        await self.limiter.clear("key1")
        
        # key1 should be cleared
        is_limited1, _ = await self.limiter.is_rate_limited(
            "key1", max_requests=1, window_seconds=60
        )
        # key2 should still be at limit
        is_limited2, _ = await self.limiter.is_rate_limited(
            "key2", max_requests=1, window_seconds=60
        )
        
        assert is_limited1 is False
        assert is_limited2 is True

# NOTE: TestCompoundKey tests are in test_redis_rate_limit.py to avoid duplication
