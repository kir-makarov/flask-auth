from core.config import settings
from db import jwt_redis


class AuthService:

    def redis_key(self, user_id: str, user_agent: str) -> str:
        """Key template for redis db."""
        return f"{user_id}:{user_agent}"

    def save_refresh_token_in_redis(self, user_id: str, user_agent: str, token: str):
        """Saves refresh token in Redis db."""
        redis_key: str = self.redis_key(user_id=user_id, user_agent=user_agent)
        jwt_redis.set(redis_key, token, ex=settings.REFRESH_EXPIRES)

    def get_refresh_token_from_redis(self, user_id: str, user_agent: str) -> str:
        """Gets refresh token from Redis db."""
        redis_key: str = self.redis_key(user_id=user_id, user_agent=user_agent)
        return jwt_redis.get(redis_key)

    def delete_user_refresh_token(self, user_id: str, user_agent: str):
        """Deletes user refresh token from Redis db."""
        redis_key: str = self.redis_key(user_id=user_id, user_agent=user_agent)
        jwt_redis.delete(redis_key)


auth_service = AuthService()
