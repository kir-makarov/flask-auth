from flask_sqlalchemy import SQLAlchemy
import redis

from core.config import settings


db = SQLAlchemy()

jwt_redis = redis.StrictRedis(
    host=settings.redis.host,
    port=settings.redis.port,
    db=settings.redis.db,
    decode_responses=True
)
