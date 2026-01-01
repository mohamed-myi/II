"""Unit tests for cost aware rate limiters"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import time

from src.ingestion.rate_limiter import (
    InMemoryCostLimiter,
    RedisCostLimiter,
    create_cost_limiter,
)


class TestInMemoryCostLimiterInit:

    def test_default_remaining_is_hourly_quota(self):
        limiter = InMemoryCostLimiter()
        assert limiter._remaining == 5000

    def test_custom_initial_remaining(self):
        limiter = InMemoryCostLimiter(initial_remaining=1000)
        assert limiter._remaining == 1000


class TestInMemoryCostLimiterRecordCost:

    async def test_decrements_remaining(self):
        limiter = InMemoryCostLimiter(initial_remaining=100)
        await limiter.record_cost(10)
        assert await limiter.get_remaining_points() == 90

    async def test_cannot_go_below_zero(self):
        limiter = InMemoryCostLimiter(initial_remaining=5)
        await limiter.record_cost(10)
        assert await limiter.get_remaining_points() == 0

    async def test_accumulates_total_cost(self):
        limiter = InMemoryCostLimiter()
        await limiter.record_cost(10)
        await limiter.record_cost(25)
        await limiter.record_cost(5)
        assert limiter.get_total_cost_recorded() == 40


class TestInMemoryCostLimiterCanAfford:

    async def test_returns_true_when_sufficient(self):
        limiter = InMemoryCostLimiter(initial_remaining=100)
        assert await limiter.can_afford(50) is True

    async def test_returns_false_when_insufficient(self):
        limiter = InMemoryCostLimiter(initial_remaining=10)
        assert await limiter.can_afford(50) is False

    async def test_boundary_exact_remaining_is_affordable(self):
        limiter = InMemoryCostLimiter(initial_remaining=50)
        assert await limiter.can_afford(50) is True


class TestInMemoryCostLimiterWaitUntilAffordable:

    async def test_returns_immediately_when_affordable(self):
        limiter = InMemoryCostLimiter(initial_remaining=100)

        with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            await limiter.wait_until_affordable(50)
            mock_sleep.assert_not_called()

    async def test_blocks_until_reset_time(self):
        limiter = InMemoryCostLimiter(initial_remaining=0)
        limiter._reset_at = time.time() + 2

        call_count = 0

        async def mock_sleep_and_reset(seconds):
            nonlocal call_count
            call_count += 1
            # Simulate time passing; trigger reset
            limiter._reset_at = time.time() - 1

        with patch("asyncio.sleep", side_effect=mock_sleep_and_reset):
            await limiter.wait_until_affordable(10)

        assert call_count >= 1

    async def test_resets_quota_after_reset_time_passes(self):
        limiter = InMemoryCostLimiter(initial_remaining=0)
        limiter._reset_at = time.time() - 1

        await limiter.wait_until_affordable(10)
        assert await limiter.get_remaining_points() == 5000

    async def test_caps_sleep_at_60_seconds(self):
        limiter = InMemoryCostLimiter(initial_remaining=0)
        limiter._reset_at = time.time() + 120

        sleep_calls = []

        async def capture_sleep(seconds):
            sleep_calls.append(seconds)
            # Restore quota to exit loop
            limiter._remaining = 5000

        with patch("asyncio.sleep", side_effect=capture_sleep):
            await limiter.wait_until_affordable(10)

        assert sleep_calls[0] <= 61


class TestInMemoryCostLimiterSetRemainingFromResponse:
    async def test_updates_both_remaining_and_reset_at(self):
        limiter = InMemoryCostLimiter()
        future_reset = int(time.time()) + 3600
        await limiter.set_remaining_from_response(remaining=4500, reset_at=future_reset)

        assert limiter._remaining == 4500
        assert limiter._reset_at == float(future_reset)

    async def test_handles_zero_reset_at(self):
        limiter = InMemoryCostLimiter()
        await limiter.set_remaining_from_response(remaining=4500, reset_at=0)

        assert await limiter.get_remaining_points() == 4500
        assert limiter._reset_at == 0.0


class TestInMemoryCostLimiterLazyReset:

    async def test_resets_quota_when_past_reset_time(self):
        limiter = InMemoryCostLimiter(initial_remaining=0)
        limiter._reset_at = time.time() - 1

        remaining = await limiter.get_remaining_points()
        assert remaining == 5000

    async def test_no_reset_when_before_reset_time(self):
        limiter = InMemoryCostLimiter(initial_remaining=100)
        limiter._reset_at = time.time() + 3600

        remaining = await limiter.get_remaining_points()
        assert remaining == 100

    async def test_no_reset_when_reset_at_is_zero(self):
        limiter = InMemoryCostLimiter(initial_remaining=100)
        limiter._reset_at = 0.0

        remaining = await limiter.get_remaining_points()
        assert remaining == 100


class TestRedisCostLimiter:

    @pytest.fixture
    def mock_redis(self):
        redis = AsyncMock()
        redis.get = AsyncMock(return_value=None)
        redis.set = AsyncMock()
        redis.eval = AsyncMock()
        return redis

    async def test_record_cost_calls_eval_with_lua_script(self, mock_redis):
        limiter = RedisCostLimiter(mock_redis)
        await limiter.record_cost(10)

        mock_redis.eval.assert_called_once()
        call_args = mock_redis.eval.call_args
        assert "remaining" in call_args[0][0].lower()
        assert limiter.REMAINING_KEY in call_args[0]
        assert "10" in call_args[0]

    async def test_can_afford_checks_remaining_key(self, mock_redis):
        mock_redis.get.return_value = "4500"
        limiter = RedisCostLimiter(mock_redis)

        result = await limiter.can_afford(100)

        assert result is True
        mock_redis.get.assert_any_call(limiter.REMAINING_KEY)

    async def test_can_afford_defaults_to_hourly_quota_on_nil(self, mock_redis):
        mock_redis.get.return_value = None
        limiter = RedisCostLimiter(mock_redis)

        result = await limiter.can_afford(100)

        assert result is True

    async def test_wait_until_affordable_sleeps_until_reset(self, mock_redis):
        call_count = [0]
        
        async def get_side_effect(key):
            call_count[0] += 1
            if key == RedisCostLimiter.REMAINING_KEY:
                # First call: 0 remaining, second call: has quota
                return "0" if call_count[0] <= 2 else "5000"
            elif key == RedisCostLimiter.RESET_AT_KEY:
                return str(int(time.time()) + 2)
            return None
        
        mock_redis.get = AsyncMock(side_effect=get_side_effect)

        limiter = RedisCostLimiter(mock_redis)

        with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            await limiter.wait_until_affordable(10)
            mock_sleep.assert_called()

    async def test_set_remaining_from_response_writes_both_keys(self, mock_redis):
        limiter = RedisCostLimiter(mock_redis)
        await limiter.set_remaining_from_response(remaining=4500, reset_at=1704067200)

        mock_redis.set.assert_any_call(limiter.REMAINING_KEY, 4500)
        mock_redis.set.assert_any_call(limiter.RESET_AT_KEY, 1704067200)

    async def test_get_remaining_returns_int_from_redis(self, mock_redis):
        mock_redis.get.return_value = "4500"
        limiter = RedisCostLimiter(mock_redis)

        remaining = await limiter.get_remaining_points()

        assert remaining == 4500
        assert isinstance(remaining, int)

    async def test_lazy_reset_restores_quota_when_past_reset(self, mock_redis):
        past_reset = str(int(time.time()) - 10)
        mock_redis.get.return_value = past_reset

        limiter = RedisCostLimiter(mock_redis)
        await limiter._check_and_reset_if_needed()

        mock_redis.set.assert_called_with(limiter.REMAINING_KEY, 5000)


class TestCreateCostLimiterFactory:

    def test_returns_redis_limiter_when_client_provided(self):
        mock_redis = MagicMock()
        limiter = create_cost_limiter(redis_client=mock_redis)

        assert isinstance(limiter, RedisCostLimiter)

    def test_returns_inmemory_limiter_when_no_client(self):
        limiter = create_cost_limiter(redis_client=None)

        assert isinstance(limiter, InMemoryCostLimiter)

    def test_returns_inmemory_limiter_by_default(self):
        limiter = create_cost_limiter()

        assert isinstance(limiter, InMemoryCostLimiter)

