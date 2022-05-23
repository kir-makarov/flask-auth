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
    help="This field cannot be blank."
)
user_parser.add_argument(
    'password',
    type=str,
    required=True,
    help="This field cannot be blank."
)
user_parser.add_argument("User-Agent", location="headers")


class UserRegister(Resource):

    def post(self):
        data = user_parser.parse_args()

        if UserModel.find_by_username(data['username']):
            return {"message": "A user with that username already exists"}, http.HTTPStatus.BAD_REQUEST

        user = UserModel(data['username'], UserModel.generate_hash(data['password']))
        user.save_to_db()

        return {"message": "User created successfully."}, http.HTTPStatus.CREATED


class User(Resource):

    @classmethod
    @user_must_match
    def get(cls, user_id):
        user = UserModel.find_by_id(user_id)
        if not user:
            return {'message': 'user not found'}, http.HTTPStatus.NOT_FOUND
        return user.json()

    @classmethod
    @jwt_required(optional=True)
    def delete(cls, user_id):
        current_user_id = get_jwt_identity()
        user = UserModel.find_by_id(user_id)
        if not user:
            return {'message': 'user not found'}, http.HTTPStatus.NOT_FOUND

        if user.current_user(current_user_id) or user.is_admin():
            user.delete_from_db()
            return {'message': 'user deleted'}, http.HTTPStatus.OK

        return {'message': 'insufficient credentials'}, http.HTTPStatus.NOT_FOUND


class ChangePassword(Resource):
    pass



class UserLogin(Resource):

    @classmethod
    def post(cls):
        data = user_parser.parse_args()
        user = UserModel.find_by_username(data['username'])
        user_agent = data["User-Agent"]
        if user and UserModel.verify_hash(data['password'], user.password):
            access_token = create_access_token(
                identity=user.id,
                fresh=True,
                additional_claims={"access_level": user.access.value}
            )
            refresh_token = create_refresh_token(user.id)

            auth_service.delete_user_refresh_token(user.id, user_agent)
            auth_service.save_refresh_token_in_redis(user.id, user_agent, refresh_token)

            return {'access_token': access_token,
                    'refresh_token': refresh_token}, http.HTTPStatus.OK
        return {'message': 'Invalid credentials'}, http.HTTPStatus.UNAUTHORIZED


class UserLogout(Resource):
    @jwt_required()
    def post(self):
        token = get_jwt()
        jti = token["jti"]
        ttype = token["type"]
        jwt_redis.set(jti, "", ex=settings.ACCESS_EXPIRES)
        return jsonify(msg=f"{ttype.capitalize()} token successfully revoked")


refresh_post_parser = reqparse.RequestParser()
refresh_post_parser.add_argument("User-Agent", location="headers")


class TokenRefresh(Resource):
    @jwt_required(refresh=True)
    def post(self):
        data = refresh_post_parser.parse_args()
        user_agent = data["User-Agent"]
        current_user_id = get_jwt_identity()

        if not auth_service.get_refresh_token_from_redis(current_user_id, user_agent):
            return {'message': 'Invalid token'}, http.HTTPStatus.UNAUTHORIZED

        new_token = create_access_token(identity=current_user_id, fresh=False)

        refresh_token = create_refresh_token(current_user_id)

        auth_service.delete_user_refresh_token(current_user_id, user_agent)
        auth_service.save_refresh_token_in_redis(current_user_id, user_agent, refresh_token)

        return {"access_token": new_token,
                "refresh_token": refresh_token}, http.HTTPStatus.OK
