"""Async Redis client; falls back to in memory storage if Redis not configured"""
import logging
from typing import Optional

from src.core.config import get_settings

logger = logging.getLogger(__name__)

_redis_client = None
_redis_available: Optional[bool] = None


async def get_redis():
    """Lazy initialization with connection pooling; returns None if unavailable"""
    global _redis_client, _redis_available
    
    if _redis_available is False:
        return None
    
    if _redis_client is not None:
        return _redis_client
    
    settings = get_settings()
    
    if not settings.redis_url:
        logger.warning(
            "REDIS_URL not configured; rate limiting will use in memory storage"
        )
        _redis_available = False
        return None
    
    try:
        import redis.asyncio as redis
        
        _redis_client = redis.from_url(
            settings.redis_url,
            encoding="utf-8",
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
        )
        
        await _redis_client.ping()
        logger.info("Connected to Redis successfully")
        _redis_available = True
        return _redis_client
        
    except ImportError:
        logger.warning(
            "redis package not installed; rate limiting will use in memory storage"
        )
        _redis_available = False
        return None
        
    except Exception as e:
        logger.warning(f"Failed to connect to Redis: {e}; using in-memory fallback")
        _redis_available = False
        return None


async def close_redis() -> None:
    """Called on app shutdown"""
    global _redis_client, _redis_available
    
    if _redis_client is not None:
        await _redis_client.close()
        _redis_client = None
        _redis_available = None
        logger.info("Redis connection closed")


def reset_redis_for_testing() -> None:
    """For testing only"""
    global _redis_client, _redis_available
    _redis_client = None
    _redis_available = None
