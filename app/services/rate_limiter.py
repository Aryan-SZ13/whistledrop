from dataclasses import dataclass
import hashlib
import hmac
import logging
import secrets
import time
from typing import Optional
import redis.exceptions as redis_exceptions

from app.core.config import settings
from app.db.redis import get_redis

logger = logging.getLogger(__name__)

POLICY_VERSION = "v1"

SINGLE_POLICY_LUA_SCRIPT = """
local key = KEYS[1]
local window = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
local request_id = ARGV[3]

local time_result = redis.call('TIME')
local now = tonumber(time_result[1]) + tonumber(time_result[2]) / 1000000
local window_start = now - window

redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)
local current_count = redis.call('ZCARD', key)

if current_count >= limit then
    local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
    local retry_after = 1
    if #oldest > 0 then
        retry_after = math.ceil(tonumber(oldest[2]) + window - now)
        if retry_after < 1 then retry_after = 1 end
    end
    return { 0, retry_after }
end

redis.call('ZADD', key, now, request_id)
redis.call('EXPIRE', key, math.ceil(window))
return { 1, 0 }
"""

MULTI_POLICY_LUA_SCRIPT = """
local client_key = KEYS[1]
local global_key = KEYS[2]
local client_window = tonumber(ARGV[1])
local client_limit = tonumber(ARGV[2])
local global_window = tonumber(ARGV[3])
local global_limit = tonumber(ARGV[4])
local request_id = ARGV[5]

local time_result = redis.call('TIME')
local now = tonumber(time_result[1]) + tonumber(time_result[2]) / 1000000

redis.call('ZREMRANGEBYSCORE', client_key, '-inf', now - client_window)
redis.call('ZREMRANGEBYSCORE', global_key, '-inf', now - global_window)

local client_count = redis.call('ZCARD', client_key)
local global_count = redis.call('ZCARD', global_key)

if client_count >= client_limit or global_count >= global_limit then
    local retry_after = 1

    if client_count >= client_limit then
        local oldest_c = redis.call('ZRANGE', client_key, 0, 0, 'WITHSCORES')
        if #oldest_c > 0 then
            local ra = math.ceil(tonumber(oldest_c[2]) + client_window - now)
            if ra > retry_after then retry_after = ra end
        end
    end

    if global_count >= global_limit then
        local oldest_g = redis.call('ZRANGE', global_key, 0, 0, 'WITHSCORES')
        if #oldest_g > 0 then
            local ra = math.ceil(tonumber(oldest_g[2]) + global_window - now)
            if ra > retry_after then retry_after = ra end
        end
    end

    if retry_after < 1 then retry_after = 1 end
    return { 0, retry_after }
end

redis.call('ZADD', client_key, now, request_id)
redis.call('ZADD', global_key, now, request_id)

redis.call('EXPIRE', client_key, math.ceil(client_window))
redis.call('EXPIRE', global_key, math.ceil(global_window))

return { 1, 0 }
"""


class RateLimitUnavailableError(Exception):
    """Raised when Redis is unreachable, failing closed to prevent abuse."""
    pass


@dataclass(frozen=True)
class RateLimitPolicy:
    key_prefix: str
    max_requests: int
    window_seconds: int


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    retry_after: int


class RateLimiterService:
    """Production rate limiter using Redis Sorted Sets and atomic Lua scripts."""

    def __init__(self) -> None:
        self._single_script_sha: Optional[str] = None
        self._multi_script_sha: Optional[str] = None

    def derive_client_bucket(self, client_ip: str) -> str:
        """Derive an opaque HMAC-SHA256 client bucket identifier.

        Uses dedicated RATE_LIMIT_KEY_SECRET exclusively.
        The client IP is never stored in Redis keys in plaintext.
        Truncated to 16 hex characters.
        """
        canonical = client_ip.strip()
        return hmac.new(
            settings.RATE_LIMIT_KEY_SECRET.encode("utf-8"),
            canonical.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()[:16]

    def build_key(self, policy_prefix: str, bucket_identifier: str) -> str:
        """Format a policy-versioned Redis key."""
        return f"rl:{POLICY_VERSION}:{policy_prefix}:{bucket_identifier}"

    def _generate_request_id(self) -> str:
        """Generate a collision-resistant unique member identifier for sorted set storage.

        Must not rely on timestamp alone since concurrent requests can share timestamps.
        """
        return f"{time.time():.6f}-{secrets.token_hex(4)}"

    async def _execute_single_script(
        self,
        key: str,
        window: int,
        limit: int,
        request_id: str,
    ) -> RateLimitResult:
        redis_client = get_redis()
        try:
            if not self._single_script_sha:
                self._single_script_sha = await redis_client.script_load(SINGLE_POLICY_LUA_SCRIPT)
            res = await redis_client.evalsha(
                self._single_script_sha,
                1,
                key,
                window,
                limit,
                request_id,
            )
        except redis_exceptions.NoScriptError:
            self._single_script_sha = await redis_client.script_load(SINGLE_POLICY_LUA_SCRIPT)
            res = await redis_client.evalsha(
                self._single_script_sha,
                1,
                key,
                window,
                limit,
                request_id,
            )
        except redis_exceptions.RedisError as e:
            logger.error("Rate limiting service failure: %s", type(e).__name__)
            raise RateLimitUnavailableError("Rate limiting service unavailable") from e

        allowed = bool(res[0])
        retry_after = int(res[1])
        return RateLimitResult(allowed=allowed, retry_after=retry_after)

    async def _execute_multi_script(
        self,
        client_key: str,
        global_key: str,
        client_window: int,
        client_limit: int,
        global_window: int,
        global_limit: int,
        request_id: str,
    ) -> RateLimitResult:
        redis_client = get_redis()
        try:
            if not self._multi_script_sha:
                self._multi_script_sha = await redis_client.script_load(MULTI_POLICY_LUA_SCRIPT)
            res = await redis_client.evalsha(
                self._multi_script_sha,
                2,
                client_key,
                global_key,
                client_window,
                client_limit,
                global_window,
                global_limit,
                request_id,
            )
        except redis_exceptions.NoScriptError:
            self._multi_script_sha = await redis_client.script_load(MULTI_POLICY_LUA_SCRIPT)
            res = await redis_client.evalsha(
                self._multi_script_sha,
                2,
                client_key,
                global_key,
                client_window,
                client_limit,
                global_window,
                global_limit,
                request_id,
            )
        except redis_exceptions.RedisError as e:
            logger.error("Rate limiting service failure: %s", type(e).__name__)
            raise RateLimitUnavailableError("Rate limiting service unavailable") from e

        allowed = bool(res[0])
        retry_after = int(res[1])
        return RateLimitResult(allowed=allowed, retry_after=retry_after)

    async def check_rate_limit(
        self,
        policy: RateLimitPolicy,
        client_ip: str,
    ) -> RateLimitResult:
        """Evaluate a single rate limit policy against a client bucket."""
        bucket = self.derive_client_bucket(client_ip)
        key = self.build_key(policy.key_prefix, bucket)
        req_id = self._generate_request_id()
        result = await self._execute_single_script(
            key=key,
            window=policy.window_seconds,
            limit=policy.max_requests,
            request_id=req_id,
        )
        if not result.allowed:
            logger.info("Rate limit exceeded: endpoint=%s", policy.key_prefix)
        return result

    async def check_multi_rate_limit(
        self,
        client_policy: RateLimitPolicy,
        global_policy: RateLimitPolicy,
        client_ip: str,
    ) -> RateLimitResult:
        """Atomically evaluate both client-scoped and global policies in one Lua invocation.

        Used specifically for case code tracking to defend against both per-client probing
        and distributed system-wide brute force without creating case-code-specific keys.
        """
        client_bucket = self.derive_client_bucket(client_ip)
        client_key = self.build_key(client_policy.key_prefix, client_bucket)
        # Global key is fixed and literal: never includes user input or case codes
        global_key = self.build_key(global_policy.key_prefix, "all")
        req_id = self._generate_request_id()

        result = await self._execute_multi_script(
            client_key=client_key,
            global_key=global_key,
            client_window=client_policy.window_seconds,
            client_limit=client_policy.max_requests,
            global_window=global_policy.window_seconds,
            global_limit=global_policy.max_requests,
            request_id=req_id,
        )
        if not result.allowed:
            logger.info("Rate limit exceeded: endpoint=%s", client_policy.key_prefix)
        return result


rate_limiter = RateLimiterService()
