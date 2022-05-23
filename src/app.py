import http
from db import db, init_db
from flask import Flask, jsonify
from flask_restful import Api
from flask_jwt_extended import JWTManager
from services.v1.user import UserRegister, User, UserLogin, UserLogout, TokenRefresh, ChangePassword
from db import jwt_redis
from core.config import settings

app = Flask(__name__)

app.config["JWT_SECRET_KEY"] = settings.JWT_SECRET_KEY
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = settings.JWT_ACCESS_TOKEN_EXPIRES

api = Api(app)
jwt = JWTManager(app)


@app.before_first_request
def create_tables():
    db.create_all()


@jwt.expired_token_loader
def expired_token_callback():
    return jsonify({
        'description': 'The token has expired.',
        'error': 'token_expired'
    }), http.HTTPStatus.UNAUTHORIZED


@jwt.token_in_blocklist_loader
def check_if_token_is_revoked(jwt_header, jwt_payload: dict):
    jti = jwt_payload["jti"]
    token_in_redis = jwt_redis.get(jti)
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
def revoked_token_callback(jwt_header, jwt_payload: dict):
    return jsonify({
        'description': 'The token has been revoked.',
        'error': 'token_revoked'
    }), http.HTTPStatus.UNAUTHORIZED


@jwt.additional_claims_loader
def add_claims_to_jwt(identity):  # Remember identity is what we define when creating the access token
    print('####', identity)
    if identity == 1:   # instead of hard-coding, we should read from a config file or database to get a list of admins instead
        return {'is_admin': True}
    return {'is_admin': False}


api.add_resource(User, '/v1/user/<user_id>')
api.add_resource(UserRegister, '/v1/register')
api.add_resource(UserLogin, '/v1/login')
api.add_resource(UserLogout, '/v1/logout')
api.add_resource(TokenRefresh, '/v1/refresh')
api.add_resource(ChangePassword, '/v1/change-password')


if __name__ == '__main__':
    init_db(app)
    app.run(port=5000, debug=True)
