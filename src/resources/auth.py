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
    user_id: str


class Login(Resource):
    @validate()
    def post(self, body: UserRequestModel):
        """
            Login method for users
            ---
            tags:
              - user
            parameters:
              - in: body
                name: body
                schema:
                  id: UserLogin
                  required:
                    - username
                    - password
                  properties:
                    email:
                      type: string
                      description: The user's username.
                    password:
                      type: string
                      description: The user's password.
            responses:
              200:
                description: Success user's login
                schema:
                  properties:
                    access_token:
                      type: string
                      description: User's access token
                    refresh_token:
                      type: string
                      description: User's refresh token
                    user_id:
                      type: string
                      description: User's id
              400:
                description: Bad request response
                schema:
                  properties:
                    message:
                      type: string
                      description: Response message
        """
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
                user_id=str(user.id)
            ), HTTPStatus.OK
        return {"message": const.MSG_INVALID_CREDENTIALS}, http.HTTPStatus.UNAUTHORIZED


class Logout(Resource):
    @jwt_required()
    def post(self):
        """
            Logout method for users
            ---
            tags:
              - user
            responses:
              200:
                description: Success user's logout
                schema:
                  properties:
                    message:
                      type: string
                      description: Response message
              401:
                description: Authorization error response
                schema:
                  properties:
                    description:
                      type: string
                      description: Response status
                    error:
                      type: string
                      description: Response data
        """
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
        """
            Refresh token method for users
            ---
            tags:
             - user
            responses:
             200:
               description: Success user's token refresh
               schema:
                 properties:
                   access_token:
                     type: string
                     description: Response data
                   refresh_token:
                     type: string
                     description: Response data
             401:
               description: Authorization error response
               schema:
                 properties:
                   message:
                     type: string
                     description: Response message
        """
        # token_from_header = request.headers.get("Authorization")
        # if not token_from_header:
        #     return {"message": "No token"}, http.HTTPStatus.UNAUTHORIZED
        #
        # current_user_id = get_jwt_identity()
        # new_token = create_access_token(identity=current_user_id, fresh=False)
        # refresh_token = create_refresh_token(current_user_id)
        #
        # token_from_redis = auth_service.get_refresh_token_from_redis(current_user_id, request.user_agent)
        #
        # token_from_header = token_from_header.removeprefix(const.JWT_PREFIX)
        # if not token_from_redis or not token_from_header or token_from_header != token_from_redis:
        #     print('BAD')
        # else:
        #     print(token_from_redis)
        #     print(token_from_header)
        # return {"access_token": new_token,
        #         "refresh_token": refresh_token}, http.HTTPStatus.OK

        # data = refresh_post_parser.parse_args()
        user_agent = request.headers.get("User-Agent")
        token_from_header = request.headers.get("Authorization")
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


class Validate(Resource):
    @jwt_required(optional=True)
    def post(self):
        """
            Refresh token method for users
            ---
            tags:
              - user
            responses:
              200:
                description: Validate user's roles
                schema:
                  properties:
                    verified:
                      type: boolean
                      description: Response status
                    role:
                      type: string
                      description: Response data
              401:
                description: Authorization error response
                schema:
                  properties:
                    description:
                      type: string
                      description: Response status
                    error:
                      type: string
                      description: Response data
        """
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