import http
from flask import jsonify
from flask_restful import Resource, reqparse
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity,
    get_jwt,
)

from core import const
from core.config import settings
from models.user import UserModel
from db import jwt_redis
from services.auth import auth_service
from services.permissions import user_must_match

user_parser = reqparse.RequestParser()
user_parser.add_argument(
    'username',
    type=str,
    required=True,
    help=const.MSG_FIELD_CANNOT_BE_BLANK
)
user_parser.add_argument(
    'password',
    type=str,
    required=True,
    help=const.MSG_FIELD_CANNOT_BE_BLANK
)
user_parser.add_argument("User-Agent", location="headers")


class UserRegister(Resource):

    def post(self):
        data = user_parser.parse_args()

        if UserModel.find_by_username(data['username']):
            return {"message": const.MSG_USER_ALREADY_EXIST}, http.HTTPStatus.BAD_REQUEST

        user = UserModel(data['username'], UserModel.generate_hash(data['password']))
        user.save_to_db()

        return {"message": const.MSG_USER_CREATED_SUCCESSFULLY}, http.HTTPStatus.CREATED


class User(Resource):

    @classmethod
    @user_must_match
    def get(cls, user_id):
        user = UserModel.find_by_id(user_id)
        if not user:
            return {"message": const.MSG_USER_NOT_FOUND}, http.HTTPStatus.NOT_FOUND
        return user.json()

    @classmethod
    @jwt_required(optional=True)
    def delete(cls, user_id):
        current_user_id = get_jwt_identity()
        user = UserModel.find_by_id(user_id)
        if not user:
            return {"message": const.MSG_USER_NOT_FOUND}, http.HTTPStatus.NOT_FOUND

        if user.current_user(current_user_id) or user.is_admin():
            user.delete_from_db()
            return {"message": const.MSG_USER_DELETED}, http.HTTPStatus.OK

        return {'message': const.MSG_UNSUFFICIENT_CREDENTIALS}, http.HTTPStatus.NOT_FOUND


class ChangePassword(Resource):

    @classmethod
    @user_must_match
    def post(cls, user_id):
        password_parser = reqparse.RequestParser()
        password_parser.add_argument(
            'old_password',
            type=str,
            required=True,
            help=const.MSG_FIELD_CANNOT_BE_BLANK
        )
        password_parser.add_argument(
            'new_password',
            type=str,
            required=True,
            help=const.MSG_FIELD_CANNOT_BE_BLANK
        )
        data = password_parser.parse_args()
        user = UserModel.find_by_id(user_id)
        if user and UserModel.verify_hash(data["old_password"], user.password):
            user.update_password(user_id, UserModel.generate_hash(data["new_password"]))
            return {"message": const.MSG_PASSWORD_CHANGED_SUCCESSFULLY}, http.HTTPStatus.OK
        return {"message": const.MSG_USER_NOT_FOUND_OR_INCORRECT_PASSWORD}, http.HTTPStatus.NOT_FOUND


class UserLogin(Resource):

    @classmethod
    def post(cls):
        data = user_parser.parse_args()
        user = UserModel.find_by_username(data["username"])
        user_agent = data["User-Agent"]
        if user and UserModel.verify_hash(data["password"], user.password):
            access_token = create_access_token(
                identity=user.id,
                fresh=True,
                additional_claims={"access_level": user.access.value}
            )
            refresh_token = create_refresh_token(user.id)

            auth_service.delete_user_refresh_token(user.id, user_agent)
            auth_service.save_refresh_token_in_redis(user.id, user_agent, refresh_token)

            return {"access_token": access_token,
                    "refresh_token": refresh_token,
                    "user_id": str(user.id)}, http.HTTPStatus.OK
        return {"message": const.MSG_INVALID_CREDENTIALS}, http.HTTPStatus.UNAUTHORIZED


class UserLogout(Resource):
    @jwt_required()
    def post(self):
        token = get_jwt()
        jti = token["jti"]
        ttype = token["type"]

        if jwt_redis.get(jti):
            return {"message": const.MSG_TOKEN_ALREADY_REVOKED}, http.HTTPStatus.UNAUTHORIZED

        jwt_redis.set(jti, "revoked", ex=settings.ACCESS_EXPIRES)
        return jsonify(msg=f"{ttype.capitalize()} token successfully revoked")


refresh_post_parser = reqparse.RequestParser()
refresh_post_parser.add_argument("User-Agent", location="headers")
refresh_post_parser.add_argument("Authorization", location="headers")


class TokenRefresh(Resource):
    @jwt_required(refresh=True)
    def post(self):
        data = refresh_post_parser.parse_args()
        user_agent = data["User-Agent"]
        token_from_header = data.get("Authorization")
        if not token_from_header:
            return {"message": "No token"}, http.HTTPStatus.UNAUTHORIZED
        token_from_header = token_from_header.removeprefix(const.JWT_PREFIX)

        current_user_id = get_jwt_identity()

        token_from_redis = auth_service.get_refresh_token_from_redis(current_user_id, user_agent)
        if not token_from_redis or not token_from_header or token_from_header != token_from_redis:
            return {"message": const.MSG_INVALID_TOKEN}, http.HTTPStatus.UNAUTHORIZED

        new_token = create_access_token(identity=current_user_id, fresh=False)

        refresh_token = create_refresh_token(current_user_id)

        auth_service.delete_user_refresh_token(current_user_id, user_agent)
        auth_service.save_refresh_token_in_redis(current_user_id, user_agent, refresh_token)

        return {"access_token": new_token,
                "refresh_token": refresh_token}, http.HTTPStatus.OK
