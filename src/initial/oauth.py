from authlib.integrations.flask_client import OAuth
from flask import Flask

from core import const
from core.config import settings

oauth = OAuth()

oauth.register(name=const.OAUTH_GOOGLE, client_kwargs={"scope": "openid email profile"})

oauth.register(name=const.OAUTH_YANDEX,
               api_base_url=settings.OAUTH_YANDEX_API_BASE_URL,
               access_token_url=settings.OAUTH_YANDEX_ACCESS_TOKEN_URL,
               authorize_url=settings.OAUTH_YANDEX_AUTHORIZE_URL,
               userinfo_endpoint="info")


def initialize_oath(app: Flask):
    app.config["GOOGLE_CLIENT_ID"] = settings.OAUTH_GOOGLE_CLIENT_ID
    app.config["GOOGLE_CLIENT_SECRET"] = settings.OAUTH_GOOGLE_CLIENT_SECRET
    app.secret_key = settings.OAUTH_GOOGLE_CLIENT_SECRET
    app.config["GOOGLE_SERVER_METADATA_URL"] = settings.OAUTH_GOOGLE_SERVER_METADATA_URL

    app.config["YANDEX_CLIENT_ID"] = settings.OAUTH_YANDEX_CLIENT_ID
    app.config["YANDEX_CLIENT_SECRET"] = settings.OAUTH_YANDEX_CLIENT_SECRET

    oauth.init_app(app=app)
