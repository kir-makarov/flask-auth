from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from core.config import settings
import redis

db = SQLAlchemy()

jwt_redis = redis.StrictRedis(
    host=settings.redis.host,
    port=settings.redis.port,
    db=settings.redis.db,
    decode_responses=True
)
