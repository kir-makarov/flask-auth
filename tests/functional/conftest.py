import uuid

import pytest
from flask_jwt_extended import JWTManager
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy_utils import create_database, drop_database

from app import app
from models.user import UserModel


@pytest.fixture(scope='function')
def client():
    app.config["JWT_SECRET_KEY"] = "test_key"
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = 60
    api = Api(app)
    jwt = JWTManager(app)

    test_db_uri = "postgresql://admin:admin@127.0.0.1:5432/flask-auth-test-" + uuid.uuid4().hex

    create_database(test_db_uri)

    app.config['SQLALCHEMY_DATABASE_URI'] = test_db_uri
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db = SQLAlchemy(app)

    db.init_app(app)
    db.create_all()

    yield app.test_client()

    drop_database(test_db_uri)
    db.session.close()