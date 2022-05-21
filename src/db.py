from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from core.config import settings
import redis

db = SQLAlchemy()

jwt_redis_blocklist = redis.StrictRedis(
    host="localhost", port=6379, db=0, decode_responses=True
)


def init_db(app: Flask):
    app.config['SQLALCHEMY_DATABASE_URI'] = settings.postgres.uri
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)
