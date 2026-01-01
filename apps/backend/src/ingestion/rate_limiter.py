"""Cost aware rate limiter for GitHub GraphQL API"""

from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class CostAwareLimiter(ABC):
    """Async interface supports both in memory and Redis implementations"""

    async def record_cost(self, cost: int) -> None:
        ...

    async def can_afford(self, estimated_cost: int) -> bool:
        ...

    async def wait_until_affordable(self, estimated_cost: int) -> None:
        ...

    async def get_remaining_points(self) -> int:
        ...

    async def set_remaining_from_response(self, remaining: int, reset_at: int) -> None:
        ...


class InMemoryCostLimiter(CostAwareLimiter):
    """Uses lazy reset logic to avoid background timers"""

    HOURLY_QUOTA: int = 5000

    def __init__(self, initial_remaining: int | None = None):
        self._remaining = initial_remaining if initial_remaining is not None else self.HOURLY_QUOTA
        self._reset_at: float = 0.0
        self._lock = asyncio.Lock()
        self._total_cost_recorded: int = 0

    def _maybe_reset_quota(self) -> None:
        """Must be called while holding _lock"""
        if self._reset_at > 0 and time.time() >= self._reset_at:
            self._remaining = self.HOURLY_QUOTA
            self._reset_at = 0.0

    async def record_cost(self, cost: int) -> None:
        async with self._lock:
            self._maybe_reset_quota()
            self._remaining = max(0, self._remaining - cost)
            self._total_cost_recorded += cost
            logger.debug(f"Recorded cost: {cost}, remaining: {self._remaining}")

    async def can_afford(self, estimated_cost: int) -> bool:
        async with self._lock:
            self._maybe_reset_quota()
            return self._remaining >= estimated_cost

    async def wait_until_affordable(self, estimated_cost: int) -> None:
        while True:
            async with self._lock:
                self._maybe_reset_quota()
                if self._remaining >= estimated_cost:
                    return

                if self._reset_at > 0:
                    wait_seconds = max(0, self._reset_at - time.time())
                    if wait_seconds > 0:
                        logger.info(
                            f"Rate limit exhausted, waiting {wait_seconds:.0f}s until reset"
                        )
            
            await asyncio.sleep(min(wait_seconds + 1, 60) if self._reset_at > 0 else 1.0)

    async def get_remaining_points(self) -> int:
        async with self._lock:
            self._maybe_reset_quota()
            return self._remaining

    async def set_remaining_from_response(self, remaining: int, reset_at: int) -> None:
        async with self._lock:
            self._remaining = remaining
            self._reset_at = float(reset_at)

    def get_total_cost_recorded(self) -> int:
        return self._total_cost_recorded


class RedisCostLimiter(CostAwareLimiter):
    """Uses Lua scripts for atomic operations in distributed execution"""

    HOURLY_QUOTA: int = 5000
    REMAINING_KEY = "ingestion:graphql:remaining"
    RESET_AT_KEY = "ingestion:graphql:reset_at"
    TOTAL_COST_KEY = "ingestion:graphql:total_cost"

    def __init__(self, redis_client):
        self._redis = redis_client

    async def _check_and_reset_if_needed(self) -> None:
        reset_at = await self._redis.get(self.RESET_AT_KEY)
        if reset_at and time.time() >= int(reset_at):
            await self._redis.set(self.REMAINING_KEY, self.HOURLY_QUOTA)

    async def record_cost(self, cost: int) -> None:
        script = """
        local remaining = tonumber(redis.call('GET', KEYS[1]) or ARGV[2])
        remaining = math.max(0, remaining - tonumber(ARGV[1]))
        redis.call('SET', KEYS[1], remaining)
        redis.call('INCRBY', KEYS[2], ARGV[1])
        return remaining
        """
        await self._redis.eval(
            script,
            2,
            self.REMAINING_KEY,
            self.TOTAL_COST_KEY,
            str(cost),
            str(self.HOURLY_QUOTA),
        )

    async def can_afford(self, estimated_cost: int) -> bool:
        await self._check_and_reset_if_needed()
        remaining = await self._redis.get(self.REMAINING_KEY)
        remaining = int(remaining) if remaining else self.HOURLY_QUOTA
        return remaining >= estimated_cost

    async def wait_until_affordable(self, estimated_cost: int) -> None:
        while not await self.can_afford(estimated_cost):
            reset_at = await self._redis.get(self.RESET_AT_KEY)
            if reset_at:
                wait_seconds = max(0, int(reset_at) - time.time())
                if wait_seconds > 0:
                    await asyncio.sleep(min(wait_seconds + 1, 60))
                    continue
            await asyncio.sleep(1.0)

    async def get_remaining_points(self) -> int:
        await self._check_and_reset_if_needed()
        remaining = await self._redis.get(self.REMAINING_KEY)
        return int(remaining) if remaining else self.HOURLY_QUOTA

    async def set_remaining_from_response(self, remaining: int, reset_at: int) -> None:
        await self._redis.set(self.REMAINING_KEY, remaining)
        await self._redis.set(self.RESET_AT_KEY, reset_at)


def create_cost_limiter(redis_client=None) -> CostAwareLimiter:
    """Uses Redis if available; otherwise in memory"""
    if redis_client:
        logger.info("Using Redis-backed cost limiter")
        return RedisCostLimiter(redis_client)

    logger.info("Using in-memory cost limiter (single instance only)")
    return InMemoryCostLimiter()
