import http
from flask import jsonify
from flask_jwt_extended import JWTManager
from db import jwt_redis


def initialize_jwt(app):

    jwt = JWTManager(app)

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
