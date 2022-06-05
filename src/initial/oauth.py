from authlib.integrations.flask_client import OAuth
from flask import Flask

from core import const
from core.config import settings

oauth = OAuth()

oauth.register(name=const.OAUTH_GOOGLE, client_kwargs={"scope": "openid email profile"})


def initialize_oath(app: Flask):
    app.config["GOOGLE_CLIENT_ID"] = settings.OAUTH_GOOGLE_CLIENT_ID
    app.config["GOOGLE_CLIENT_SECRET"] = settings.OAUTH_GOOGLE_CLIENT_SECRET
    app.secret_key = settings.OAUTH_GOOGLE_CLIENT_SECRET
    app.config["GOOGLE_SERVER_METADATA_URL"] = settings.OAUTH_GOOGLE_SERVER_METADATA_URL

    oauth.init_app(app=app)
