from resources.role import RoleRequestModel
from sqlalchemy.exc import IntegrityError
from http import HTTPStatus
from flask_restful import Resource
from models.user import UserModel, RoleModel
from core import const
from flask_pydantic import validate
from pydantic import BaseModel
from db import db


class ResponseModel(BaseModel):
    message: str


class RoleUser(Resource):

    @validate()
    def post(self, user_id, body: RoleRequestModel):
        """
        СRUD Role method for users
        ---
        tags:
            - user
        responses:
            200:
            description: Validate user's roles
            schema:
                properties:
                message:
                    type: string
                    description: Response data
               """
        user = UserModel.find_by_id(user_id)
        if not user:
            return ResponseModel(
                message=const.MSG_USER_ALREADY_EXIST), HTTPStatus.BAD_REQUEST
        role = RoleModel.find_by_name(body.role)
        if not role:
            return ResponseModel(
                message=const.MSG_ROLE_ALREADY_EXIST
            ), HTTPStatus.BAD_REQUEST
        try:
            user.roles.append(role)
            db.session.commit()
            return ResponseModel(
                message=const.MSG_ROLE_SET_USER
            ), HTTPStatus.BAD_REQUEST
        except IntegrityError:
            return ResponseModel(
                message=const.MSG_ROLE_ALREADY_EXIST
            ), HTTPStatus.BAD_REQUEST

    @validate()
    def delete(self, user_id, body: RoleRequestModel):
        """
        CRUD Role method for users
        ---
        tags:
            - user
        responses:
            200:
            description: Validate user's roles
            schema:
                properties:
                message:
                    type: string
                    description: Response data
               """
        user = UserModel.find_by_id(user_id)
        if not user:
            return ResponseModel(
                message=const.MSG_USER_ALREADY_EXIST
            ), HTTPStatus.BAD_REQUEST
        role = RoleModel.find_by_name(body.role)
        if not role:
            return ResponseModel(
                message=const.MSG_ROLE_ALREADY_EXIST
            ), HTTPStatus.BAD_REQUEST
        try:
            user.roles.remove(role)
            db.session.commit()
            return ResponseModel(
                message=const.MSG_ROLE_UNSET_USER
            ), HTTPStatus.BAD_REQUEST
        except ValueError:
            return ResponseModel(
                message=const.MSG_ROLE_ALREADY_USER
            ), HTTPStatus.BAD_REQUEST
