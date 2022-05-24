import pytest
from flask_jwt_extended import JWTManager
from flask_restful import Api

from app import app
from db import db
from models.user import UserModel


@pytest.fixture(scope='function', autouse=True)
def client():
    app.config["JWT_SECRET_KEY"] = "test_key"
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = 60
    app.config["TESTING"] = True
    api = Api(app)
    jwt = JWTManager(app)

    test_db_uri = "postgresql://admin:admin@127.0.0.1:5432/flask-auth-test"

    app.config['SQLALCHEMY_DATABASE_URI'] = test_db_uri
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    with app.app_context():
        db.init_app(app)
        db.create_all()

    yield app

    with app.app_context():
        db.drop_all()
        db.session.close()
