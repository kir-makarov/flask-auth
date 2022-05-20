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
from werkzeug.security import safe_join
from datetime import timedelta
from database.redis_db import jwt_redis_blocklist


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


ACCESS_EXPIRES = timedelta(hours=1)

class UserRegister(Resource):

    def post(self):
        data = user_parser.parse_args()

        if UserModel.find_by_username(data['username']):
            return {"message": "A user with that username already exists"}, 400

        user = UserModel(data['username'], data['password'])
        user.save_to_db()

        return {"message": "User created successfully."}, 201


class User(Resource):

    @classmethod
    def get(cls, user_id):
        user = UserModel.find_by_id(user_id)
        if not user:
            return {'message': 'user not found'}, 404
        return user.json()

    @classmethod
    def delete(cls, user_id):
        user = UserModel.find_by_id(user_id)
        if not user:
            return {'message': 'user not found'}, 404
        user.delete_from_db()
        return {'message': 'user deleted'}, 200


class UserLogin(Resource):

    @classmethod
    def post(cls):
        data = user_parser.parse_args()
        user = UserModel.find_by_username(data['username'])
        if user and safe_join(user.password, data['password']):
            access_token = create_access_token(identity=user.id, fresh=True)
            refresh_token = create_refresh_token(user.id)
            return {
                'access_token': access_token,
                'refresh_token': refresh_token
            }, 200
        return {'message': 'Invalid credentials'}, 401


class UserLogout(Resource):
    @jwt_required()
    def post(self):
        token = get_jwt()
        jti = token["jti"]
        ttype = token["type"]
        jwt_redis_blocklist.set(jti, "", ex=ACCESS_EXPIRES)
        return jsonify(msg=f"{ttype.capitalize()} token successfully revoked")

class TokenRefresh(Resource):
    @jwt_required(refresh=True)
    def post(self):
        current_user = get_jwt_identity()
        new_token = create_access_token(identity=current_user, fresh=False)
        return {"access_token": new_token}, 200
