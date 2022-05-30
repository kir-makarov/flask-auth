import os
from datetime import timedelta
from pydantic import BaseSettings


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


class Settings(Base):

    ACCESS_EXPIRES = timedelta(hours=1)
    REFRESH_EXPIRES = timedelta(days=10)

    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    JWT_SECRET_KEY: str = os.getenv('JWT_SECRET_KEY', 'secret_key')
    JWT_ACCESS_TOKEN_EXPIRES: int = os.getenv('JWT_ACCESS_TOKEN_EXPIRES', 3600)

    postgres: PostgresSettings = PostgresSettings()
    redis: RedisSettings = RedisSettings()


settings = Settings()
