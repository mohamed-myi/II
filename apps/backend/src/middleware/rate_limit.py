"""
Sliding window rate limiter; uses Redis in production;
falls back to in memory storage when Redis unavailable
"""
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from fastapi import HTTPException, Request, Depends

from src.core.config import get_settings
from src.core.audit import log_audit_event, AuditEvent
from src.middleware.context import RequestContext, get_request_context

logger = logging.getLogger(__name__)


class RateLimiterBackend(ABC):
    @abstractmethod
    async def is_rate_limited(
        self,
        key: str,
        max_requests: int,
        window_seconds: int,
    ) -> tuple[bool, int | None]:
        """Returns tuple of is_limited and retry_after_seconds"""
        pass
    
    @abstractmethod
    async def clear(self, key: str | None = None) -> None:
        pass


class RedisRateLimiter(RateLimiterBackend):
    """Uses INCR + EXPIRE pattern; atomic operations prevent race conditions"""
    
    def __init__(self, redis_client):
        self._redis = redis_client
    
    async def is_rate_limited(
        self,
        key: str,
        max_requests: int,
        window_seconds: int,
    ) -> tuple[bool, int | None]:
        redis_key = f"rate_limit:{key}"
        
        count = await self._redis.incr(redis_key)
        
        if count == 1:
            await self._redis.expire(redis_key, window_seconds)
        
        if count > max_requests:
            ttl = await self._redis.ttl(redis_key)
            retry_after = max(1, ttl) if ttl > 0 else 1
            return True, retry_after
        
        return False, None
    
    async def clear(self, key: str | None = None) -> None:
        if key:
            await self._redis.delete(f"rate_limit:{key}")
        else:
            async for k in self._redis.scan_iter("rate_limit:*"):
                await self._redis.delete(k)


@dataclass
class InMemoryRateLimiter(RateLimiterBackend):
    """Development only; state lost on restart and not shared across instances"""
    storage: dict[str, list[float]] = field(default_factory=dict)
    
    def _prune_expired(self, timestamps: list[float], now: float, window: int) -> list[float]:
        cutoff = now - window
        return [ts for ts in timestamps if ts > cutoff]
    
    async def is_rate_limited(
        self,
        key: str,
        max_requests: int,
        window_seconds: int,
    ) -> tuple[bool, int | None]:
        now = time.time()
        
        if key not in self.storage:
            self.storage[key] = []
        
        self.storage[key] = self._prune_expired(
            self.storage[key], now, window_seconds
        )
        
        if len(self.storage[key]) >= max_requests:
            oldest = min(self.storage[key])
            retry_after = int(oldest + window_seconds - now) + 1
            return True, max(1, retry_after)
        
        self.storage[key].append(now)
        return False, None
    
    async def clear(self, key: str | None = None) -> None:
        if key:
            self.storage.pop(key, None)
        else:
            self.storage.clear()


# Global rate limiter instance
_rate_limiter: RateLimiterBackend | None = None
_limiter_initialized: bool = False


async def get_rate_limiter() -> RateLimiterBackend:
    """Tries Redis first; falls back to in memory if unavailable"""
    global _rate_limiter, _limiter_initialized
    
    if _rate_limiter is not None:
        return _rate_limiter
    
    if _limiter_initialized:
        _rate_limiter = InMemoryRateLimiter()
        return _rate_limiter
    
    _limiter_initialized = True
    
    from src.core.redis import get_redis
    redis_client = await get_redis()
    
    if redis_client:
        _rate_limiter = RedisRateLimiter(redis_client)
        logger.info("Rate limiter using Redis backend")
    else:
        _rate_limiter = InMemoryRateLimiter()
        logger.info("Rate limiter using in-memory backend (development mode)")
    
    return _rate_limiter


def reset_rate_limiter() -> None:
    """For testing only"""
    global _rate_limiter, _limiter_initialized
    if _rate_limiter and isinstance(_rate_limiter, InMemoryRateLimiter):
        _rate_limiter.storage.clear()


def reset_rate_limiter_instance() -> None:
    """For testing only"""
    global _rate_limiter, _limiter_initialized
    _rate_limiter = None
    _limiter_initialized = False


def _build_compound_key(ip_address: str, flow_id: str | None) -> str:
    if flow_id:
        return f"{ip_address}:{flow_id}"
    return ip_address


async def check_auth_rate_limit(
    request: Request,
    ctx: RequestContext = Depends(get_request_context),
) -> None:
    """Raises 429 if rate limit exceeded; uses compound key of IP + login_flow_id for NAT differentiation"""
    settings = get_settings()
    limiter = await get_rate_limiter()
    
    key = _build_compound_key(ctx.ip_address, ctx.login_flow_id)
    
    is_limited, retry_after = await limiter.is_rate_limited(
        key=key,
        max_requests=settings.max_auth_requests_per_minute,
        window_seconds=settings.rate_limit_window_seconds,
    )
    
    if is_limited:
        log_audit_event(
            AuditEvent.RATE_LIMITED,
            ip_address=ctx.ip_address,
            metadata={"retry_after": retry_after, "key": key},
        )
        raise HTTPException(
            status_code=429,
            detail="Too many requests",
            headers={"Retry-After": str(retry_after)},
        )
