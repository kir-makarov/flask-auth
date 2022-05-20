import os
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
    db: str = os.getenv('POSTGRES_DB', 'movies')
    user: str = os.getenv('POSTGRES_USER', 'admin')
    password: str = os.getenv('POSTGRES_USER', 'admin')
    uri = f"postgresql://{user}:{password}@{host}:{port}/{db}"
    class Config:
        env_prefix = 'postgres_'


class Settings(Base):

    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    postgres: PostgresSettings = PostgresSettings()
    redis: RedisSettings = RedisSettings()

settings = Settings()
