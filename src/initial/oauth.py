from authlib.integrations.flask_client import OAuth
from flask import Flask

from core import const
from core.config import settings

oauth = OAuth()

oauth.register(name=const.OAUTH_GOOGLE, client_kwargs={"scope": "openid email profile"})

oauth.register(
    name=const.OAUTH_FACEBOOK,
    client_id=settings.OAUTH_FACEBOOK_CLIENT_ID,
    client_secret=settings.OAUTH_FACEBOOK_CLIENT_SECRET,
    access_token_url='https://graph.facebook.com/oauth/access_token',
    access_token_params=None,
    authorize_url='https://www.facebook.com/dialog/oauth',
    authorize_params=None,
    api_base_url='https://graph.facebook.com/',
    client_kwargs={'scope': 'email'},
)


def initialize_oath(app: Flask):
    app.config["GOOGLE_CLIENT_ID"] = settings.OAUTH_GOOGLE_CLIENT_ID
    app.config["GOOGLE_CLIENT_SECRET"] = settings.OAUTH_GOOGLE_CLIENT_SECRET
    app.secret_key = settings.OAUTH_GOOGLE_CLIENT_SECRET
    # app.secret_key = settings.OAUTH_FACEBOOK_CLIENT_SECRET
    app.config["GOOGLE_SERVER_METADATA_URL"] = settings.OAUTH_GOOGLE_SERVER_METADATA_URL

    oauth.init_app(app=app)
