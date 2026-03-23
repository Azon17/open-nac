"""
Redis: session cache, CoA lookups, rate limiting.
"""

import os
import json
import logging
from typing import Optional

import redis.asyncio as redis

logger = logging.getLogger("nac.redis")


class RedisPool:
    def __init__(self):
        self.pool: Optional[redis.Redis] = None

    async def initialize(self):
        self.pool = redis.Redis(
            host=os.getenv("REDIS_HOST", "redis-1"),
            port=int(os.getenv("REDIS_PORT", "6379")),
            password=os.getenv("REDIS_PASSWORD", ""),
            db=0,
            decode_responses=True,
            max_connections=50,
        )
        await self.pool.ping()
        logger.info("Redis connected")

    async def close(self):
        if self.pool:
            await self.pool.close()

    # ── Session directory ──

    async def set_session(self, mac: str, data: dict, ttl: int = 86400):
        key = f"session:{mac.lower()}"
        await self.pool.setex(key, ttl, json.dumps(data))

    async def get_session(self, mac: str) -> Optional[dict]:
        key = f"session:{mac.lower()}"
        raw = await self.pool.get(key)
        return json.loads(raw) if raw else None

    async def delete_session(self, mac: str):
        await self.pool.delete(f"session:{mac.lower()}")

    # ── Auth cache ──

    async def cache_auth_result(self, mac: str, result: dict, ttl: int = 3600):
        key = f"auth:{mac.lower()}"
        await self.pool.setex(key, ttl, json.dumps(result))

    async def get_cached_auth(self, mac: str) -> Optional[dict]:
        raw = await self.pool.get(f"auth:{mac.lower()}")
        return json.loads(raw) if raw else None

    # ── Rate limiting ──

    async def check_rate_limit(self, identifier: str, max_attempts: int = 5, window: int = 300) -> bool:
        key = f"ratelimit:{identifier}"
        count = await self.pool.incr(key)
        if count == 1:
            await self.pool.expire(key, window)
        return count <= max_attempts

    # ── Stats counters ──

    async def incr_counter(self, name: str, ttl: int = 3600):
        key = f"stat:{name}"
        await self.pool.incr(key)
        await self.pool.expire(key, ttl)

    async def get_counter(self, name: str) -> int:
        val = await self.pool.get(f"stat:{name}")
        return int(val) if val else 0


redis_pool = RedisPool()
