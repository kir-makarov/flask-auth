import http
import os
import redis

from flask import Flask, jsonify
from flask_restful import Api
from flask_jwt_extended import JWTManager
from dotenv import load_dotenv

from models.user import UserModel
from src.services.v1.user import UserRegister, User, UserLogin, UserLogout, TokenRefresh

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PROPAGATE_EXCEPTIONS'] = True
app.secret_key = 'team4'
api = Api(app)

load_dotenv()


@app.before_first_request
def create_tables():
    db.create_all()


app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = os.getenv("JWT_ACCESS_TOKEN_EXPIRES")

jwt = JWTManager(app)
jwt_redis_blocklist = redis.StrictRedis(
    host="localhost", port=6379, db=0, decode_responses=True
)


@jwt.expired_token_loader
def expired_token_callback():
    return jsonify({
        'description': 'The token has expired.',
        'error': 'token_expired'
    }), http.HTTPStatus.UNAUTHORIZED


@jwt.token_in_blocklist_loader
def check_if_token_is_revoked(jwt_header, jwt_payload: dict):
    jti = jwt_payload["jti"]
    token_in_redis = jwt_redis_blocklist.get(jti)
    return token_in_redis is not None


@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({
        'description': 'Signature verification failed.',
        'error': 'invalid_token'
    }), http.HTTPStatus.UNAUTHORIZED


@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({
        'description': 'Request does not contain an access token.',
        'error': 'authorization_required'
    }), http.HTTPStatus.UNAUTHORIZED


@jwt.needs_fresh_token_loader
def token_not_fresh_callback():
    return jsonify({
        'description': 'The token is not fresh.',
        'error': 'fresh_token_required'
    }), http.HTTPStatus.UNAUTHORIZED


@jwt.revoked_token_loader
def revoked_token_callback():
    return jsonify({
        'description': 'The token has been revoked.',
        'error': 'token_revoked'
    }), http.HTTPStatus.UNAUTHORIZED


api.add_resource(UserRegister, '/register')
api.add_resource(User, '/user/<int:user_id>')
api.add_resource(UserLogin, '/login')
api.add_resource(UserLogout, '/logout')
api.add_resource(TokenRefresh, '/refresh')

if __name__ == '__main__':
    from db import db, init_db

    init_db(app)
    app.app_context().push()
    db.create_all()

    # user creation example
    admin = UserModel(username='admin', password='password')
    db.session.add(admin)
    db.session.commit()

    # query example
    UserModel.query.all()
    fetched_admin = UserModel.query.filter_by(username='admin').first()

    app.run(port=5000, debug=True)
