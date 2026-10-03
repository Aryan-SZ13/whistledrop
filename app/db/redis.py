import asyncio
import logging
from typing import Dict, Optional
import redis.asyncio as aioredis
from redis.asyncio import Redis

from app.core.config import settings

logger = logging.getLogger(__name__)

_loop_clients: Dict[asyncio.AbstractEventLoop, Redis] = {}
_fallback_client: Optional[Redis] = None


async def init_redis() -> Redis:
    """Initialize the asynchronous Redis connection pool for the current event loop."""
    return get_redis()


async def close_redis() -> None:
    """Close the asynchronous Redis connection pool for the current event loop."""
    global _fallback_client
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is not None and loop in _loop_clients:
        client = _loop_clients.pop(loop)
        await client.aclose()
        logger.info("Async Redis client for active event loop closed.")
    elif _fallback_client is not None:
        await _fallback_client.aclose()
        _fallback_client = None
        logger.info("Async Redis fallback client closed.")


def get_redis() -> Redis:
    """Retrieve the asynchronous Redis client instance bound to the current event loop.

    Maintains loop-affinity to prevent asyncio event-loop cross-contamination.
    """
    global _fallback_client
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is not None:
        if loop not in _loop_clients:
            _loop_clients[loop] = aioredis.from_url(
                settings.REDIS_URL,
                encoding="utf-8",
                decode_responses=False,
                socket_connect_timeout=2.0,
                socket_timeout=2.0,
            )
        return _loop_clients[loop]

    if _fallback_client is None:
        _fallback_client = aioredis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=False,
            socket_connect_timeout=2.0,
            socket_timeout=2.0,
        )
    return _fallback_client
