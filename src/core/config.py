import os
from datetime import timedelta
from pydantic import BaseSettings
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


class Base(BaseSettings):
    class Config:
        env_file = '.env'
        env_file_encoding = 'utf-8'
        arbitrary_types_allowed = True


class RedisSettings(Base):
    host: str = os.getenv('REDIS_HOST', 'localhost')
    port: str = os.getenv('REDIS_PORT', 6379)
    db: int = os.getenv('REDIS_DB', 0)
    ACCESS_EXPIRES: int = 60 * 60

    class Config:
        env_prefix = 'redis_'


class PostgresSettings(Base):
    host: str = os.getenv('POSTGRES_HOST', 'localhost')
    port: str = os.getenv('POSTGRES_PORT', 5432)
    db: str = os.getenv('POSTGRES_DB', 'flask-auth')
    user: str = os.getenv('POSTGRES_USER', 'admin')
    password: str = os.getenv('POSTGRES_USER', 'admin')
    uri = f"postgresql://{user}:{password}@{host}:{port}/{db}"

    class Config:
        env_prefix = 'postgres_'


class JaegerSettings(Base):
    host: str = os.getenv('JAEGER_HOST', 'localhost')
    port: int = os.getenv('JAEGER_PORT', 6831)

    class Config:
        env_prefix = 'jaeger_'


class Settings(Base):
    ACCESS_EXPIRES = timedelta(hours=1)
    REFRESH_EXPIRES = timedelta(days=10)

    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    JWT_SECRET_KEY: str = os.getenv('JWT_SECRET_KEY', 'secret_key')
    JWT_ACCESS_TOKEN_EXPIRES: int = os.getenv('JWT_ACCESS_TOKEN_EXPIRES', 3600)

    OAUTH_GOOGLE_CLIENT_ID: str = os.getenv('OAUTH_GOOGLE_CLIENT_ID', "")
    OAUTH_GOOGLE_CLIENT_SECRET: str = os.getenv('OAUTH_GOOGLE_CLIENT_SECRET', "")
    OAUTH_GOOGLE_SERVER_METADATA_URL: str = os.getenv('OAUTH_GOOGLE_SERVER_METADATA_URL', "")

    OAUTH_YANDEX_CLIENT_ID: str = os.getenv('OAUTH_YANDEX_CLIENT_ID', "")
    OAUTH_YANDEX_CLIENT_SECRET: str = os.getenv('OAUTH_YANDEX_CLIENT_SECRET', "")
    OAUTH_YANDEX_API_BASE_URL: str = os.getenv('OAUTH_YANDEX_API_BASE_URL', "")
    OAUTH_YANDEX_ACCESS_TOKEN_URL: str = os.getenv('OAUTH_YANDEX_ACCESS_TOKEN_URL', "")
    OAUTH_YANDEX_AUTHORIZE_URL: str = os.getenv('OAUTH_YANDEX_AUTHORIZE_URL', "")

    postgres: PostgresSettings = PostgresSettings()
    jaeger: JaegerSettings = JaegerSettings()
    redis: RedisSettings = RedisSettings()


settings = Settings()
limiter = Limiter(key_func=get_remote_address)
