import http

from flask_restful import Resource, reqparse
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity,
    get_jwt,
)
from flask import jsonify
from models.user import UserModel
from datetime import timedelta
from db import jwt_redis_blocklist

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

ACCESS_EXPIRES = timedelta(hours=1)


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
    def get(cls, user_id):
        user = UserModel.find_by_id(user_id)
        if not user:
            return {'message': 'user not found'}, http.HTTPStatus.NOT_FOUND
        return user.json()

    @classmethod
    def delete(cls, user_id):
        user = UserModel.find_by_id(user_id)
        if not user:
            return {'message': 'user not found'}, http.HTTPStatus.NOT_FOUND
        user.delete_from_db()
        return {'message': 'user deleted'}, http.HTTPStatus.OK


class UserLogin(Resource):

    @classmethod
    def post(cls):
        data = user_parser.parse_args()
        user = UserModel.find_by_username(data['username'])
        if user and UserModel.verify_hash(data['password'], user.password):
            access_token = create_access_token(identity=user.id, fresh=True)
            refresh_token = create_refresh_token(user.id)
            return {
                       'access_token': access_token,
                       'refresh_token': refresh_token
                   }, http.HTTPStatus.OK
        return {'message': 'Invalid credentials'}, http.HTTPStatus.UNAUTHORIZED


class UserLogout(Resource):
    @jwt_required()
    def post(self):
        token = get_jwt()
        jti = token["jti"]
        ttype = token["type"]
        jwt_redis_blocklist.set(jti, "", ex=ACCESS_EXPIRES)
        return jsonify(msg=f"{ttype.capitalize()} token successfully revoked")


class TokenRefresh(Resource):
    @jwt_required()
    def post(self):
        current_user_id = get_jwt_identity()
        new_token = create_access_token(identity=current_user_id, fresh=False)
        return {"access_token": new_token}, http.HTTPStatus.OK
