import http
from flask import jsonify
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


from resources.user import UserRequestModel
from flask_pydantic import validate
from pydantic import BaseModel
from http import HTTPStatus
from flask_restful import request, Resource


class ResponseToken(BaseModel):
    access_token: str
    refresh_token: str


class Login(Resource):
    @validate()
    def post(self, body: UserRequestModel):
        user = UserModel.find_by_username(body.username)
        if user and UserModel.verify_hash(body.password, user.password):
            access_token = create_access_token(
                identity=user.id,
                fresh=True,
                additional_claims={"access_level": user.roles}
            )
            refresh_token = create_refresh_token(user.id)
            auth_service.delete_user_refresh_token(user.id, request.user_agent)
            auth_service.save_refresh_token_in_redis(user.id, request.user_agent, refresh_token)
            return ResponseToken(
                access_token=access_token,
                refresh_token=refresh_token,
            ), HTTPStatus.OK
        return {"message": const.MSG_INVALID_CREDENTIALS}, http.HTTPStatus.UNAUTHORIZED


class Logout(Resource):
    @jwt_required()
    def post(self):
        token = get_jwt()
        jti = token["jti"]
        ttype = token["type"]

        if jwt_redis.get(jti):
            return {"message": const.MSG_TOKEN_ALREADY_REVOKED}, http.HTTPStatus.UNAUTHORIZED

        jwt_redis.set(jti, "revoked", ex=settings.ACCESS_EXPIRES)
        return jsonify(msg=f"{ttype.capitalize()} token successfully revoked")


class TokenRefresh(Resource):
    @jwt_required(refresh=True)
    def post(self):
        token_from_header = request.headers.get("Authorization")
        if not token_from_header:
            return {"message": "No token"}, http.HTTPStatus.UNAUTHORIZED

        current_user_id = get_jwt_identity()
        new_token = create_access_token(identity=current_user_id, fresh=False)
        refresh_token = create_refresh_token(current_user_id)

        token_from_redis = auth_service.get_refresh_token_from_redis(current_user_id, request.user_agent)

        token_from_header = token_from_header.removeprefix(const.JWT_PREFIX)
        if not token_from_redis or not token_from_header or token_from_header != token_from_redis:
            print('BAD')
        else:
            print(token_from_redis)
            print(token_from_header)
        # return {"access_token": new_token,
        #         "refresh_token": refresh_token}, http.HTTPStatus.OK

        # data = refresh_post_parser.parse_args()
        # user_agent = data["User-Agent"]
        # token_from_header = data.get("Authorization")
        # print(token_from_header)
        # if not token_from_header:
        #     return {"message": "No token"}, http.HTTPStatus.UNAUTHORIZED
        #
        # #token_from_header = token_from_header.removeprefix(const.JWT_PREFIX)
        # current_user_id = get_jwt_identity()
        # print(current_user_id)
        # # token_from_redis = auth_service.get_refresh_token_from_redis(current_user_id, user_agent)
        # # if not token_from_redis or not token_from_header or token_from_header != token_from_redis:
        # #     return {"message": const.MSG_INVALID_TOKEN}, http.HTTPStatus.UNAUTHORIZED
        #
        # new_token = create_access_token(identity=current_user_id, fresh=False)
        #
        # refresh_token = create_refresh_token(current_user_id)
        #
        # # auth_service.delete_user_refresh_token(current_user_id, user_agent)
        # # auth_service.save_refresh_token_in_redis(current_user_id, user_agent, refresh_token)
        #
        # return {"access_token": new_token,
        #         "refresh_token": refresh_token}, http.HTTPStatus.OK


class Validate(Resource):
    @jwt_required(optional=True)
    def post(self):
        current_user_id = get_jwt_identity()
        if not current_user_id:
            return {"verified": "false"}

        token = get_jwt()
        jti = token["jti"]

        if jwt_redis.get(jti):
            return {"verified": "false"}

        user = UserModel.find_by_id(current_user_id)
        if user:
            return {"verified": "true",
                    "role": str(user.access)}

        return {"verified": "false"}