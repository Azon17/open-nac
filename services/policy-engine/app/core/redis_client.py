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

    async def set_session(self, mac, data, ttl=86400):
        await self.pool.setex(f"session:{mac.lower()}", ttl, json.dumps(data))

    async def get_session(self, mac):
        raw = await self.pool.get(f"session:{mac.lower()}")
        return json.loads(raw) if raw else None

    async def delete_session(self, mac):
        await self.pool.delete(f"session:{mac.lower()}")

    async def cache_auth_result(self, mac, result, ttl=3600):
        await self.pool.setex(f"auth:{mac.lower()}", ttl, json.dumps(result))

    async def get_cached_auth(self, mac):
        raw = await self.pool.get(f"auth:{mac.lower()}")
        return json.loads(raw) if raw else None

    async def check_rate_limit(self, identifier, max_attempts=5, window=300):
        key = f"ratelimit:{identifier}"
        count = await self.pool.incr(key)
        if count == 1:
            await self.pool.expire(key, window)
        return count <= max_attempts

    async def incr_counter(self, name, ttl=3600):
        key = f"stat:{name}"
        await self.pool.incr(key)
        await self.pool.expire(key, ttl)

    async def get_counter(self, name):
        val = await self.pool.get(f"stat:{name}")
        return int(val) if val else 0

redis_pool = RedisPool()
