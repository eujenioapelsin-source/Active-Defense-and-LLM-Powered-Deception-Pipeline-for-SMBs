import redis.asyncio as aioredis
from dataclasses import dataclass

@dataclass
class BehaviorReport:
    request_count: int
    distinct_categories: int
    just_banned: bool

class BehavioralDetector:
    def __init__(self, redis_url: str):
        self.redis = aioredis.from_url(redis_url, decode_responses=True)

    async def evaluate(self, ip: str, category: str | None) -> BehaviorReport:
        pipe = self.redis.pipeline()
        key = f"behavior:{ip}"
        pipe.incr(key)
        pipe.expire(key, 60)
        if category:
            pipe.sadd(f"cats:{ip}", category)
            pipe.expire(f"cats:{ip}", 60)
        res = await pipe.execute()
        count = res[0]
        cats = await self.redis.scard(f"cats:{ip}") if category else 0
        return BehaviorReport(request_count=count, distinct_categories=cats, just_banned=False)

    async def is_banned(self, ip: str) -> bool:
        return await self.redis.exists(f"banned:{ip}") > 0

    async def ban(self, ip: str, ttl: int = 3600):
        await self.redis.setex(f"banned:{ip}", ttl, "1")

    async def close(self):
        await self.redis.aclose()