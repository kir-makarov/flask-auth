import redis
from core.config import settings



jwt_redis_blocklist = redis.StrictRedis(
    host=settings.redis.host,
    port=settings.redis.port,
    db=settings.redis.db,
    decode_responses=True
)
