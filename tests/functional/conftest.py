import pytest
from flask import Flask
from flask_jwt_extended import JWTManager
from flask_restful import Api

from app import app
from db import db, jwt_redis
from initial.jwt import initialize_jwt
from initial.routes import initialize_routes
from models.user import UserModel


@pytest.fixture(scope='function', autouse=True)
def client():
    app = Flask(__name__)
    app.config["JWT_SECRET_KEY"] = "test_key"
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = 60
    app.config["TESTING"] = True
    initialize_jwt(app)
    initialize_routes(app)

    test_db_uri = "postgresql://admin:admin@postgres:5432/flask-auth-test"

    app.config['SQLALCHEMY_DATABASE_URI'] = test_db_uri
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    with app.app_context():
        db.init_app(app)
        db.create_all()

    yield app

    with app.app_context():
        db.drop_all()
        db.session.close()
    jwt_redis.flushall()
