import http
from db import db
from flasgger import Swagger
from flask import Flask, jsonify
from flask_restful import Api
from flask_jwt_extended import JWTManager
from db import jwt_redis
from core.config import settings

app = Flask(__name__)

app.config["JWT_SECRET_KEY"] = settings.JWT_SECRET_KEY
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = settings.JWT_ACCESS_TOKEN_EXPIRES
app.config['SQLALCHEMY_DATABASE_URI'] = settings.postgres.uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

api = Api(app)
app.api = api
jwt = JWTManager(app)
app.jwt = jwt

swagger = Swagger(app=app)


@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload: dict):
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


@jwt.user_lookup_loader
def invalid_user_lookup_loader(jwt_header, jwt_payload: dict):
    return jsonify({
        'description': 'Signature verification failed.',
        'error': 'invalid_token'
    }), http.HTTPStatus.UNAUTHORIZED


@jwt.user_lookup_loader
def invalid_user_lookup_loader(jwt_header, jwt_payload: dict):
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


from resources.auth import TokenRefresh, Validate, Login, Logout
from resources.user import User, UserList, UserRegister, ChangePassword
from resources.role_user import RoleUser
from resources.role import Role

# USER
api.add_resource(UserList, '/v1/user/')
api.add_resource(User, '/v1/user/<user_id>')
api.add_resource(UserRegister, '/v1/register')
api.add_resource(ChangePassword, '/v1/user/<user_id>/change-password')
api.add_resource(RoleUser, '/v1/user/<user_id>/role/')

# AUTH
api.add_resource(Login, '/v1/login')
api.add_resource(Logout, '/v1/logout')
api.add_resource(TokenRefresh, '/v1/refresh')
api.add_resource(Validate, '/v1/validate')

# ROLE
api.add_resource(Role, '/v1/role')


def create_app(flask_app):
    db.init_app(flask_app)
    flask_app.run(host='0.0.0.0', port=5000, debug=True)


if __name__ == '__main__':
    db.init_app(app)
    app.run(host='0.0.0.0', port=5000, debug=True)
