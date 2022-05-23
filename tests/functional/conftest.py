import pytest
from flask import Flask
from flask_jwt_extended import JWTManager
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy

from services.v1.user import User, UserRegister, UserLogin, UserLogout, TokenRefresh, ChangePassword


@pytest.fixture(scope='function')
def client():
    app = Flask(__name__)
    app.config["JWT_SECRET_KEY"] = "test_key"
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = 60
    api = Api(app)
    jwt = JWTManager(app)

    api.add_resource(User, '/v1/user/<user_id>')
    api.add_resource(UserRegister, '/v1/register')
    api.add_resource(UserLogin, '/v1/login')
    api.add_resource(UserLogout, '/v1/logout')
    api.add_resource(TokenRefresh, '/v1/refresh')
    api.add_resource(ChangePassword, '/v1/user/<user_id>/change-password')

    db = SQLAlchemy()

    app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://admin:admin@127.0.0.1:5432/flask-auth-test"
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)

    yield app.test_client()



